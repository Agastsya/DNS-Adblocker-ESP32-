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

/* --------------------------------------------------------------------------
 * Cloud blocklist sync: periodically fetch a plain domain-per-line list
 * and use it instead of the small built-in seed list above. Firebog's
 * Prigent-Ads list is ~70KB / ~4300 domains - comfortably under our
 * 832KB LittleFS partition, unlike the larger unified lists (Easylist is
 * ~900KB, AdguardDNS is ~3MB on their own).
 * ------------------------------------------------------------------------ */
#define BLOCKLIST_URL       "https://v.firebog.net/hosts/Prigent-Ads.txt"
#define BLOCKLIST_PATH      "/littlefs/blocklist.txt"
#define BLOCKLIST_TMP_PATH  "/littlefs/blocklist.txt.tmp"
#define SYNC_INTERVAL_MS    (24UL * 60 * 60 * 1000)  /* once a day */

static char *s_dynamic_buf = NULL;       /* whole downloaded file, lines NUL-split in place */
static char **s_dynamic_entries = NULL;  /* pointers into s_dynamic_buf, one per domain */
static size_t s_dynamic_count = 0;

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

/* Pure (no I/O) line splitter: walks a NUL-terminated, mutable buffer,
 * NUL-terminating each line in place and collecting pointers to the
 * usable ones (skipping blank lines, "#" comments, and a trailing "\r"
 * for CRLF-served lists). Kept separate from the download/file-loading
 * code below so it can be unit tested without a mounted filesystem or a
 * network connection. Returns the entry count; *out_entries is a
 * caller-owned array (malloc'd) on success, untouched (NULL) if there's
 * nothing usable in buf.
 */
static size_t parse_domain_lines(char *buf, char ***out_entries)
{
    size_t count = 0;
    for (char *p = buf; *p != '\0'; ) {
        char *line_end = strchr(p, '\n');
        size_t line_len = line_end ? (size_t)(line_end - p) : strlen(p);
        if (line_len > 0 && p[0] != '#' && p[0] != '\r') {
            count++;
        }
        if (!line_end) {
            break;
        }
        p = line_end + 1;
    }

    if (count == 0) {
        *out_entries = NULL;
        return 0;
    }

    char **entries = malloc(count * sizeof(char *));
    if (entries == NULL) {
        *out_entries = NULL;
        return 0;
    }

    size_t idx = 0;
    char *p = buf;
    while (*p != '\0' && idx < count) {
        char *line_end = strchr(p, '\n');
        if (line_end != NULL) {
            *line_end = '\0';
        }
        size_t len = strlen(p);
        if (len > 0 && p[len - 1] == '\r') {
            p[len - 1] = '\0';
        }
        if (p[0] != '\0' && p[0] != '#') {
            entries[idx++] = p;
        }
        if (line_end == NULL) {
            break;
        }
        p = line_end + 1;
    }

    *out_entries = entries;
    return idx;
}

static bool load_dynamic_list(void)
{
    FILE *f = fopen(BLOCKLIST_PATH, "r");
    if (f == NULL) {
        return false;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (size <= 0) {
        fclose(f);
        return false;
    }

    /* Free the previous list (if any) before allocating the new one,
     * rather than holding both at once - on this device's heap budget,
     * needing 2x the buffer plus 2x the ~34KB entry-pointer array at the
     * same time is enough to fail the allocation outright. Matching
     * falls back to the small built-in seed list for the brief gap,
     * which is safe - just temporarily less comprehensive. */
    free(s_dynamic_buf);
    free(s_dynamic_entries);
    s_dynamic_buf = NULL;
    s_dynamic_entries = NULL;
    s_dynamic_count = 0;

    char *buf = malloc((size_t)size + 1);
    if (buf == NULL) {
        fclose(f);
        ESP_LOGE(TAG, "Out of memory loading blocklist (%ld bytes)", size);
        return false;
    }
    size_t n = fread(buf, 1, (size_t)size, f);
    fclose(f);
    buf[n] = '\0';

    char **entries = NULL;
    size_t count = parse_domain_lines(buf, &entries);
    if (count == 0) {
        free(buf);
        free(entries);
        ESP_LOGW(TAG, "Downloaded blocklist had no usable entries");
        return false;
    }

    s_dynamic_buf = buf;
    s_dynamic_entries = entries;
    s_dynamic_count = count;

    ESP_LOGI(TAG, "Loaded %u domains from cloud blocklist", (unsigned)s_dynamic_count);
    return true;
}

static FILE *s_download_fp = NULL;

static esp_err_t http_event_handler(esp_http_client_event_t *evt)
{
    if (evt->event_id == HTTP_EVENT_ON_DATA && s_download_fp != NULL) {
        fwrite(evt->data, 1, evt->data_len, s_download_fp);
    }
    return ESP_OK;
}

static bool download_blocklist(void)
{
    s_download_fp = fopen(BLOCKLIST_TMP_PATH, "w");
    if (s_download_fp == NULL) {
        ESP_LOGE(TAG, "Could not open %s for writing", BLOCKLIST_TMP_PATH);
        return false;
    }

    esp_http_client_config_t config = {
        .url = BLOCKLIST_URL,
        .event_handler = http_event_handler,
        .timeout_ms = 20000,
        .crt_bundle_attach = esp_crt_bundle_attach,
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_err_t err = esp_http_client_perform(client);
    int status = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);

    fclose(s_download_fp);
    s_download_fp = NULL;

    if (err != ESP_OK || status != 200) {
        ESP_LOGW(TAG, "Blocklist download failed: %s (HTTP %d)", esp_err_to_name(err), status);
        remove(BLOCKLIST_TMP_PATH);
        return false;
    }
    return true;
}

static void do_sync(void)
{
    ESP_LOGI(TAG, "Syncing blocklist from %s", BLOCKLIST_URL);
    if (download_blocklist()) {
        remove(BLOCKLIST_PATH);
        rename(BLOCKLIST_TMP_PATH, BLOCKLIST_PATH);
        load_dynamic_list();
    } else {
        ESP_LOGW(TAG, "Blocklist sync failed - keeping the existing list");
    }
}

static void blocklist_sync_task(void *pvParameters)
{
    /* blocklist_init() already loaded a cached copy from a previous run,
     * if there was one - only sync immediately on a genuinely fresh
     * device, so we're not redundantly re-fetching (and momentarily
     * double-allocating) a list we just finished loading seconds ago. */
    if (s_dynamic_count == 0) {
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

esp_err_t blocklist_init(void)
{
    whitelist_load();
    manualblock_load();

    if (load_dynamic_list()) {
        ESP_LOGI(TAG, "Using previously synced cloud blocklist (%u domains)",
                 (unsigned)s_dynamic_count);
    } else {
        ESP_LOGI(TAG, "No cloud blocklist yet - using %u built-in seed entries",
                 (unsigned)BLOCKLIST_COUNT);
    }
    ESP_LOGI(TAG, "%u whitelist, %u manual-block entries loaded",
             (unsigned)s_whitelist_count, (unsigned)s_manualblock_count);
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

    if (s_dynamic_count > 0) {
        for (size_t i = 0; i < s_dynamic_count; i++) {
            if (domain_matches(domain, s_dynamic_entries[i])) {
                return true;
            }
        }
        return false;
    }

    for (size_t i = 0; i < BLOCKLIST_COUNT; i++) {
        if (domain_matches(domain, s_blocklist[i])) {
            return true;
        }
    }
    return false;
}
