#include "blocklist.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "esp_log.h"
#include "esp_http_client.h"
#include "esp_crt_bundle.h"
#include "cJSON.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

static const char *TAG = "blocklist";

/* Small built-in seed list of well-known ad/tracking domains. Used until
 * the first successful cloud sync below replaces it with the real list,
 * and as a fallback if that sync ever fails with nothing cached yet. */
static const char *s_blocklist[] = {
    "doubleclick.net",
    "googlesyndication.com",
    "googleadservices.com",
    "google-analytics.com",
    "googletagmanager.com",
    "scorecardresearch.com",
    "adsystem.amazon.com",
    "ads.yahoo.com",
    "adnxs.com",
    "criteo.com",
};
#define BLOCKLIST_COUNT (sizeof(s_blocklist) / sizeof(s_blocklist[0]))

/* User-managed whitelist: domains here are never blocked, even if the
 * cloud blocklist contains them. Persisted to LittleFS as a JSON array
 * and editable at runtime via the dashboard's REST API. A small
 * fixed-capacity table keeps this allocation-free and easy to reason
 * about - 64 manual exceptions is plenty for a personal device. */
#define WHITELIST_MAX         64
#define WHITELIST_MAX_DOMAIN  128
#define WHITELIST_PATH        "/littlefs/whitelist.json"

static char s_whitelist[WHITELIST_MAX][WHITELIST_MAX_DOMAIN];
static size_t s_whitelist_count = 0;

/* User-managed manual blocklist: domains the user explicitly blocks via
 * the dashboard, on top of the cloud list. Same fixed-table design as the
 * whitelist above; persisted separately. */
#define MANUALBLOCK_MAX         64
#define MANUALBLOCK_MAX_DOMAIN  128
#define MANUALBLOCK_PATH        "/littlefs/manualblock.json"

static char s_manualblock[MANUALBLOCK_MAX][MANUALBLOCK_MAX_DOMAIN];
static size_t s_manualblock_count = 0;

/* User-uploaded custom blocklist: a bulk list the user pastes/imports via
 * the dashboard (one domain per line). Stored as raw text on flash and
 * loaded into a buffer + line-pointer array - bigger than the manual list
 * but still small enough to keep in RAM. */
#define CUSTOMBLOCK_PATH       "/littlefs/customblock.txt"
#define CUSTOMBLOCK_MAX_BYTES  (48 * 1024)   /* ~2000 domains */

static char  *s_custom_buf = NULL;
static char **s_custom_entries = NULL;
static size_t s_custom_count = 0;

/* --------------------------------------------------------------------------
 * Cloud blocklist: a large domain list (tens of thousands of entries),
 * stored as 32-bit FNV-1a hashes in NUM_BUCKETS sorted buckets ON FLASH.
 *
 * Why hashes on flash instead of strings in RAM: a modern blocklist is
 * 50-150k domains (1-3 MB of text) and the ESP32 has only tens of KB of
 * free heap - the strings can't live in RAM. We stream-hash the list as
 * it downloads (the multi-MB text is never stored, only ~4 bytes/domain),
 * bucket the hashes, sort each bucket, and binary-search them on flash per
 * lookup. The whole list never sits in RAM at once.
 *
 * Lookups hash each parent suffix of the queried name ("a.b.tracker.com"
 * -> "a.b.tracker.com", "b.tracker.com", "tracker.com") and check each in
 * its bucket, so blocking "tracker.com" also blocks every subdomain.
 * ------------------------------------------------------------------------ */
#define BLOCKLIST_URL    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/light.txt"
#define IDX_PATH         "/littlefs/blockidx.bin"
#define IDX_TMP_PATH     "/littlefs/blockidx.tmp"
#define RAW_TMP_PATH     "/littlefs/blockraw.tmp"
#define NUM_BUCKETS      64u    /* power of two: bucket = hash & (NUM_BUCKETS-1) */
#define IDX_HEADER_BYTES (NUM_BUCKETS * (uint32_t)sizeof(uint32_t))
#define MAX_DOMAINS      80000u /* cap so raw+index files fit the 832KB partition */
#define SYNC_INTERVAL_MS (24UL * 60 * 60 * 1000)  /* once a day */

/* In-RAM index header: per-bucket entry count + byte offset of each
 * bucket's sorted hashes within IDX_PATH. The hashes themselves stay on
 * flash. Guarded by s_idx_lock because the background sync task swaps the
 * index file while the DNS task is searching it. */
static uint32_t s_bucket_count[NUM_BUCKETS];
static uint32_t s_bucket_off[NUM_BUCKETS];
static bool     s_idx_ready = false;
static FILE    *s_idx_fp = NULL;             /* persistent read handle into IDX_PATH */
static SemaphoreHandle_t s_idx_lock = NULL;

static uint32_t domain_hash(const char *s)
{
    uint32_t h = 2166136261u;            /* FNV-1a, case-insensitive */
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c >= 'A' && c <= 'Z') c += 32;
        h ^= c;
        h *= 16777619u;
    }
    return h;
}

static int cmp_u32(const void *a, const void *b)
{
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
    return (x > y) - (x < y);
}

/* True if `domain` is exactly `entry`, or a subdomain of it (e.g.
 * "ads.doubleclick.net" matches entry "doubleclick.net", but
 * "notdoubleclick.net" does not). */
static bool domain_matches(const char *domain, const char *entry)
{
    size_t domain_len = strlen(domain);
    size_t entry_len = strlen(entry);

    if (domain_len < entry_len) {
        return false;
    }
    if (strcasecmp(domain + (domain_len - entry_len), entry) != 0) {
        return false;
    }
    if (domain_len == entry_len) {
        return true;
    }
    return domain[domain_len - entry_len - 1] == '.';
}

/* Read the committed index file's header into RAM (per-bucket counts +
 * offsets) and keep a persistent read handle open. Call with s_idx_lock
 * held. Returns true if a usable index was loaded. */
static bool index_load_locked(void)
{
    if (s_idx_fp) { fclose(s_idx_fp); s_idx_fp = NULL; }
    s_idx_ready = false;

    FILE *f = fopen(IDX_PATH, "rb");
    if (f == NULL) {
        return false;
    }
    if (fread(s_bucket_count, sizeof(uint32_t), NUM_BUCKETS, f) != NUM_BUCKETS) {
        fclose(f);
        return false;
    }
    uint32_t off = IDX_HEADER_BYTES, total = 0;
    for (unsigned b = 0; b < NUM_BUCKETS; b++) {
        s_bucket_off[b] = off;
        off += s_bucket_count[b] * (uint32_t)sizeof(uint32_t);
        total += s_bucket_count[b];
    }
    s_idx_fp = f;
    s_idx_ready = true;
    ESP_LOGI(TAG, "Cloud blocklist active: %u domains (hash index on flash)", (unsigned)total);
    return true;
}

/* Binary-search one hash in its bucket on flash. Call with s_idx_lock held. */
static bool index_contains_hash_locked(uint32_t target)
{
    unsigned b = target & (NUM_BUCKETS - 1);
    uint32_t n = s_bucket_count[b];
    if (n == 0 || s_idx_fp == NULL) {
        return false;
    }
    uint32_t lo = 0, hi = n;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        uint32_t val;
        if (fseek(s_idx_fp, s_bucket_off[b] + mid * (uint32_t)sizeof(uint32_t), SEEK_SET) != 0) {
            return false;
        }
        if (fread(&val, sizeof(uint32_t), 1, s_idx_fp) != 1) {
            return false;
        }
        if (val == target) return true;
        if (val < target) lo = mid + 1; else hi = mid;
    }
    return false;
}

/* True if `domain` or any parent suffix (down to, but not including, the
 * bare TLD) is in the cloud index. */
static bool index_blocks_domain(const char *domain)
{
    bool blocked = false;
    xSemaphoreTake(s_idx_lock, portMAX_DELAY);
    if (s_idx_ready) {
        const char *p = domain;
        int labels = 1;
        for (const char *q = domain; *q; q++) {
            if (*q == '.') labels++;
        }
        while (labels >= 2) {
            if (index_contains_hash_locked(domain_hash(p))) {
                blocked = true;
                break;
            }
            const char *dot = strchr(p, '.');
            if (dot == NULL) break;
            p = dot + 1;
            labels--;
        }
    }
    xSemaphoreGive(s_idx_lock);
    return blocked;
}

/* ---- download: stream-hash the source list (text never stored whole) ---- */
static FILE   *s_raw_fp = NULL;
static char    s_dl_line[256];
static size_t  s_dl_len = 0;
static uint32_t s_dl_domains = 0;

static void dl_flush_line(void)
{
    s_dl_line[s_dl_len] = '\0';
    char *line = s_dl_line;
    if (s_dl_len && line[s_dl_len - 1] == '\r') {
        line[--s_dl_len] = '\0';
    }
    if (s_dl_len == 0 || line[0] == '#' || line[0] == '!') {
        s_dl_len = 0;
        return;
    }
    /* hosts-format lines ("0.0.0.0 domain") -> take the token after the
     * last space/tab; plain domain lines pass through unchanged. */
    char *sp = strrchr(line, ' ');
    char *tab = strrchr(line, '\t');
    if (tab && (!sp || tab > sp)) sp = tab;
    char *dom = sp ? sp + 1 : line;

    if (dom[0] != '\0' && strchr(dom, '/') == NULL && s_dl_domains < MAX_DOMAINS) {
        uint32_t h = domain_hash(dom);
        fwrite(&h, sizeof(uint32_t), 1, s_raw_fp);
        s_dl_domains++;
    }
    s_dl_len = 0;
}

static esp_err_t http_event_handler(esp_http_client_event_t *evt)
{
    if (evt->event_id == HTTP_EVENT_ON_DATA && s_raw_fp != NULL) {
        const char *d = (const char *)evt->data;
        for (int i = 0; i < evt->data_len; i++) {
            char c = d[i];
            if (c == '\n') {
                dl_flush_line();
            } else if (s_dl_len < sizeof(s_dl_line) - 1) {
                s_dl_line[s_dl_len++] = c;
            }
            /* overlong lines (shouldn't happen for domains) just stop
             * accumulating; the tail is dropped at the next newline. */
        }
    }
    return ESP_OK;
}

static bool download_to_raw(void)
{
    s_raw_fp = fopen(RAW_TMP_PATH, "wb");
    if (s_raw_fp == NULL) {
        return false;
    }
    s_dl_len = 0;
    s_dl_domains = 0;

    esp_http_client_config_t config = {
        .url = BLOCKLIST_URL,
        .event_handler = http_event_handler,
        .timeout_ms = 60000,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .buffer_size = 2048,
        .user_agent = "PocketDNS",
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_err_t err = esp_http_client_perform(client);
    int status = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);

    if (s_dl_len > 0) {
        dl_flush_line();  /* final line if it had no trailing newline */
    }
    fclose(s_raw_fp);
    s_raw_fp = NULL;

    if (err != ESP_OK || status != 200) {
        ESP_LOGW(TAG, "Blocklist download failed: %s (HTTP %d)", esp_err_to_name(err), status);
        remove(RAW_TMP_PATH);
        return false;
    }
    ESP_LOGI(TAG, "Downloaded and hashed %u domains", (unsigned)s_dl_domains);
    return true;
}

/* Turn the unsorted raw hash file into the bucketed, per-bucket-sorted
 * index file. One bucket is held in RAM at a time, so peak memory is just
 * the largest bucket (~a few KB) rather than the whole list. */
static bool build_index(void)
{
    FILE *raw = fopen(RAW_TMP_PATH, "rb");
    if (raw == NULL) {
        return false;
    }

    uint32_t counts[NUM_BUCKETS] = {0};
    uint32_t h;
    while (fread(&h, sizeof(uint32_t), 1, raw) == 1) {
        counts[h & (NUM_BUCKETS - 1)]++;
    }

    FILE *out = fopen(IDX_TMP_PATH, "wb");
    if (out == NULL) {
        fclose(raw);
        return false;
    }
    fwrite(counts, sizeof(uint32_t), NUM_BUCKETS, out);  /* header */

    for (unsigned b = 0; b < NUM_BUCKETS; b++) {
        if (counts[b] == 0) {
            continue;
        }
        uint32_t *arr = malloc(counts[b] * sizeof(uint32_t));
        if (arr == NULL) {
            fclose(raw);
            fclose(out);
            remove(IDX_TMP_PATH);
            return false;
        }
        uint32_t k = 0;
        fseek(raw, 0, SEEK_SET);
        while (fread(&h, sizeof(uint32_t), 1, raw) == 1) {
            if ((h & (NUM_BUCKETS - 1)) == b) arr[k++] = h;
        }
        qsort(arr, k, sizeof(uint32_t), cmp_u32);
        fwrite(arr, sizeof(uint32_t), k, out);
        free(arr);
    }
    fclose(raw);
    fclose(out);
    return true;
}

static void do_sync(void)
{
    ESP_LOGI(TAG, "Syncing cloud blocklist (downloading + indexing, ~1 min)...");
    if (!download_to_raw()) {
        return;  /* keep current index */
    }

    /* Drop the old index before building the new one: the raw file and the
     * new index together are ~640KB, and keeping the old index too would
     * overflow the 832KB partition. Lookups fall back to the small seed
     * list during the brief rebuild. */
    xSemaphoreTake(s_idx_lock, portMAX_DELAY);
    if (s_idx_fp) { fclose(s_idx_fp); s_idx_fp = NULL; }
    s_idx_ready = false;
    remove(IDX_PATH);
    xSemaphoreGive(s_idx_lock);

    if (!build_index()) {
        ESP_LOGW(TAG, "Blocklist index build failed");
        remove(RAW_TMP_PATH);
        return;
    }
    remove(RAW_TMP_PATH);

    xSemaphoreTake(s_idx_lock, portMAX_DELAY);
    rename(IDX_TMP_PATH, IDX_PATH);
    index_load_locked();
    xSemaphoreGive(s_idx_lock);
}

static void blocklist_sync_task(void *pvParameters)
{
    /* Only sync immediately if there's no usable index yet (fresh device);
     * otherwise wait for the daily interval so we don't rebuild a list we
     * just loaded at boot. */
    if (!s_idx_ready) {
        do_sync();
    }
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(SYNC_INTERVAL_MS));
        do_sync();
    }
}

void blocklist_start_cloud_sync(void)
{
    xTaskCreate(blocklist_sync_task, "blocklist_sync", 8192, NULL, 3, NULL);
}

/* --------------------------------------------------------------------------
 * User whitelist persistence + management.
 * ------------------------------------------------------------------------ */
static void whitelist_save(void)
{
    cJSON *arr = cJSON_CreateArray();
    if (arr == NULL) {
        return;
    }
    for (size_t i = 0; i < s_whitelist_count; i++) {
        cJSON_AddItemToArray(arr, cJSON_CreateString(s_whitelist[i]));
    }
    char *json = cJSON_PrintUnformatted(arr);
    if (json != NULL) {
        FILE *f = fopen(WHITELIST_PATH, "w");
        if (f != NULL) {
            fputs(json, f);
            fclose(f);
        }
        cJSON_free(json);
    }
    cJSON_Delete(arr);
}

static void whitelist_load(void)
{
    s_whitelist_count = 0;

    FILE *f = fopen(WHITELIST_PATH, "r");
    if (f == NULL) {
        return;
    }
    /* Heap, not stack: this buffer can be several KB, and whitelist_load()
     * runs on the main task (via blocklist_init -> dns_server_start), whose
     * stack is only ~8KB - a stack array this size overflows it. */
    const size_t buf_sz = WHITELIST_MAX * WHITELIST_MAX_DOMAIN;
    char *buf = malloc(buf_sz);
    if (buf == NULL) {
        fclose(f);
        return;
    }
    size_t n = fread(buf, 1, buf_sz - 1, f);
    fclose(f);
    buf[n] = '\0';

    cJSON *arr = cJSON_Parse(buf);
    free(buf);
    if (arr == NULL || !cJSON_IsArray(arr)) {
        cJSON_Delete(arr);
        return;
    }
    int count = cJSON_GetArraySize(arr);
    for (int i = 0; i < count && s_whitelist_count < WHITELIST_MAX; i++) {
        cJSON *item = cJSON_GetArrayItem(arr, i);
        if (cJSON_IsString(item) && strlen(item->valuestring) < WHITELIST_MAX_DOMAIN) {
            strcpy(s_whitelist[s_whitelist_count++], item->valuestring);
        }
    }
    cJSON_Delete(arr);
}

bool blocklist_whitelist_add(const char *domain)
{
    if (domain == NULL || domain[0] == '\0' || strlen(domain) >= WHITELIST_MAX_DOMAIN) {
        return false;
    }
    for (size_t i = 0; i < s_whitelist_count; i++) {
        if (strcasecmp(s_whitelist[i], domain) == 0) {
            return true;  /* already present - idempotent */
        }
    }
    if (s_whitelist_count >= WHITELIST_MAX) {
        return false;
    }
    strcpy(s_whitelist[s_whitelist_count++], domain);
    whitelist_save();
    ESP_LOGI(TAG, "Whitelisted %s (%u total)", domain, (unsigned)s_whitelist_count);
    return true;
}

bool blocklist_whitelist_remove(const char *domain)
{
    for (size_t i = 0; i < s_whitelist_count; i++) {
        if (strcasecmp(s_whitelist[i], domain) == 0) {
            /* Compact the gap by moving the last entry into this slot. */
            if (i != s_whitelist_count - 1) {
                strcpy(s_whitelist[i], s_whitelist[s_whitelist_count - 1]);
            }
            s_whitelist_count--;
            whitelist_save();
            ESP_LOGI(TAG, "Un-whitelisted %s (%u total)", domain, (unsigned)s_whitelist_count);
            return true;
        }
    }
    return false;
}

char *blocklist_whitelist_to_json(void)
{
    cJSON *arr = cJSON_CreateArray();
    if (arr == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < s_whitelist_count; i++) {
        cJSON_AddItemToArray(arr, cJSON_CreateString(s_whitelist[i]));
    }
    char *json = cJSON_PrintUnformatted(arr);
    cJSON_Delete(arr);
    return json;
}

/* --------------------------------------------------------------------------
 * User manual blocklist (domains the user blocks via the dashboard).
 * ------------------------------------------------------------------------ */
static void manualblock_save(void)
{
    cJSON *arr = cJSON_CreateArray();
    if (arr == NULL) {
        return;
    }
    for (size_t i = 0; i < s_manualblock_count; i++) {
        cJSON_AddItemToArray(arr, cJSON_CreateString(s_manualblock[i]));
    }
    char *json = cJSON_PrintUnformatted(arr);
    if (json != NULL) {
        FILE *f = fopen(MANUALBLOCK_PATH, "w");
        if (f != NULL) {
            fputs(json, f);
            fclose(f);
        }
        cJSON_free(json);
    }
    cJSON_Delete(arr);
}

static void manualblock_load(void)
{
    s_manualblock_count = 0;

    FILE *f = fopen(MANUALBLOCK_PATH, "r");
    if (f == NULL) {
        return;
    }
    const size_t buf_sz = MANUALBLOCK_MAX * MANUALBLOCK_MAX_DOMAIN;
    char *buf = malloc(buf_sz);   /* heap, not stack - see whitelist_load() */
    if (buf == NULL) {
        fclose(f);
        return;
    }
    size_t n = fread(buf, 1, buf_sz - 1, f);
    fclose(f);
    buf[n] = '\0';

    cJSON *arr = cJSON_Parse(buf);
    free(buf);
    if (arr == NULL || !cJSON_IsArray(arr)) {
        cJSON_Delete(arr);
        return;
    }
    int count = cJSON_GetArraySize(arr);
    for (int i = 0; i < count && s_manualblock_count < MANUALBLOCK_MAX; i++) {
        cJSON *item = cJSON_GetArrayItem(arr, i);
        if (cJSON_IsString(item) && strlen(item->valuestring) < MANUALBLOCK_MAX_DOMAIN) {
            strcpy(s_manualblock[s_manualblock_count++], item->valuestring);
        }
    }
    cJSON_Delete(arr);
}

bool blocklist_manual_add(const char *domain)
{
    if (domain == NULL || domain[0] == '\0' || strlen(domain) >= MANUALBLOCK_MAX_DOMAIN) {
        return false;
    }
    for (size_t i = 0; i < s_manualblock_count; i++) {
        if (strcasecmp(s_manualblock[i], domain) == 0) {
            return true;  /* already present - idempotent */
        }
    }
    if (s_manualblock_count >= MANUALBLOCK_MAX) {
        return false;
    }
    strcpy(s_manualblock[s_manualblock_count++], domain);
    manualblock_save();
    ESP_LOGI(TAG, "Manually blocked %s (%u total)", domain, (unsigned)s_manualblock_count);
    return true;
}

bool blocklist_manual_remove(const char *domain)
{
    for (size_t i = 0; i < s_manualblock_count; i++) {
        if (strcasecmp(s_manualblock[i], domain) == 0) {
            if (i != s_manualblock_count - 1) {
                strcpy(s_manualblock[i], s_manualblock[s_manualblock_count - 1]);
            }
            s_manualblock_count--;
            manualblock_save();
            ESP_LOGI(TAG, "Un-blocked %s (%u total)", domain, (unsigned)s_manualblock_count);
            return true;
        }
    }
    return false;
}

char *blocklist_manual_to_json(void)
{
    cJSON *arr = cJSON_CreateArray();
    if (arr == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < s_manualblock_count; i++) {
        cJSON_AddItemToArray(arr, cJSON_CreateString(s_manualblock[i]));
    }
    char *json = cJSON_PrintUnformatted(arr);
    cJSON_Delete(arr);
    return json;
}

/* --------------------------------------------------------------------------
 * User-uploaded custom blocklist (bulk paste/import).
 * ------------------------------------------------------------------------ */

/* Split the loaded buffer into line pointers, skipping blanks/comments and
 * trimming CR. Mutates s_custom_buf in place. */
static void custom_rebuild_index(void)
{
    free(s_custom_entries);
    s_custom_entries = NULL;
    s_custom_count = 0;
    if (s_custom_buf == NULL) {
        return;
    }

    size_t cap = 0;
    for (char *p = s_custom_buf; *p; p++) {
        if (*p == '\n') cap++;
    }
    cap += 1;
    s_custom_entries = malloc(cap * sizeof(char *));
    if (s_custom_entries == NULL) {
        return;
    }

    char *p = s_custom_buf;
    while (*p) {
        char *eol = strchr(p, '\n');
        if (eol) *eol = '\0';
        size_t len = strlen(p);
        if (len && p[len - 1] == '\r') p[len - 1] = '\0';
        if (p[0] != '\0' && p[0] != '#' && s_custom_count < cap) {
            s_custom_entries[s_custom_count++] = p;
        }
        if (!eol) break;
        p = eol + 1;
    }
}

static void custom_load(void)
{
    free(s_custom_buf);
    s_custom_buf = NULL;
    free(s_custom_entries);
    s_custom_entries = NULL;
    s_custom_count = 0;

    FILE *f = fopen(CUSTOMBLOCK_PATH, "r");
    if (f == NULL) {
        return;
    }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (size <= 0 || size > CUSTOMBLOCK_MAX_BYTES) {
        if (size > CUSTOMBLOCK_MAX_BYTES) ESP_LOGW(TAG, "Custom blocklist too big, ignoring");
        fclose(f);
        return;
    }
    s_custom_buf = malloc((size_t)size + 1);
    if (s_custom_buf == NULL) {
        fclose(f);
        return;
    }
    size_t n = fread(s_custom_buf, 1, (size_t)size, f);
    fclose(f);
    s_custom_buf[n] = '\0';
    custom_rebuild_index();
    ESP_LOGI(TAG, "Custom blocklist: %u domains", (unsigned)s_custom_count);
}

bool blocklist_custom_set(const char *text)
{
    if (text == NULL) {
        return false;
    }
    if (strlen(text) > CUSTOMBLOCK_MAX_BYTES) {
        return false;
    }
    FILE *f = fopen(CUSTOMBLOCK_PATH, "w");
    if (f == NULL) {
        return false;
    }
    fputs(text, f);
    fclose(f);
    custom_load();
    return true;
}

char *blocklist_custom_get_text(void)
{
    FILE *f = fopen(CUSTOMBLOCK_PATH, "r");
    if (f == NULL) {
        char *empty = malloc(1);
        if (empty) empty[0] = '\0';
        return empty;
    }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (size < 0 || size > CUSTOMBLOCK_MAX_BYTES) size = 0;
    char *buf = malloc((size_t)size + 1);
    if (buf == NULL) { fclose(f); return NULL; }
    size_t n = fread(buf, 1, (size_t)size, f);
    fclose(f);
    buf[n] = '\0';
    return buf;
}

size_t blocklist_custom_count(void)
{
    return s_custom_count;
}

esp_err_t blocklist_init(void)
{
    if (s_idx_lock == NULL) {
        s_idx_lock = xSemaphoreCreateMutex();
    }

    /* Remove the old string-list file from the previous design, if present,
     * so it doesn't waste the tight flash budget the index build needs. */
    remove("/littlefs/blocklist.txt");
    remove("/littlefs/blocklist.txt.tmp");

    whitelist_load();
    manualblock_load();
    custom_load();

    xSemaphoreTake(s_idx_lock, portMAX_DELAY);
    bool have_idx = index_load_locked();
    xSemaphoreGive(s_idx_lock);
    if (!have_idx) {
        ESP_LOGI(TAG, "No cloud blocklist yet - using %u built-in seed entries until first sync",
                 (unsigned)BLOCKLIST_COUNT);
    }
    ESP_LOGI(TAG, "%u whitelist, %u manual-block, %u custom-block entries loaded",
             (unsigned)s_whitelist_count, (unsigned)s_manualblock_count, (unsigned)s_custom_count);
    return ESP_OK;
}

bool blocklist_is_blocked(const char *domain)
{
    /* Whitelist wins over everything. */
    for (size_t i = 0; i < s_whitelist_count; i++) {
        if (domain_matches(domain, s_whitelist[i])) {
            return false;
        }
    }

    /* User's manual blocks, checked before the cloud/seed list. */
    for (size_t i = 0; i < s_manualblock_count; i++) {
        if (domain_matches(domain, s_manualblock[i])) {
            return true;
        }
    }

    /* User's uploaded custom blocklist. */
    for (size_t i = 0; i < s_custom_count; i++) {
        if (domain_matches(domain, s_custom_entries[i])) {
            return true;
        }
    }

    /* Cloud blocklist (flash hash index) once it's loaded; until then,
     * fall back to the small built-in seed list. */
    if (s_idx_ready) {
        return index_blocks_domain(domain);
    }
    for (size_t i = 0; i < BLOCKLIST_COUNT; i++) {
        if (domain_matches(domain, s_blocklist[i])) {
            return true;
        }
    }
    return false;
}
