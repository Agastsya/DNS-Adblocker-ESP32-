#include "dns_stats.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "esp_log.h"
#include "cJSON.h"

static const char *TAG = "dns_stats";

#define STATS_PATH               "/littlefs/statistics.json"
#define STATS_TMP_PATH           "/littlefs/statistics.json.tmp"
#define PERSIST_EVERY_N_QUERIES  10

static dns_stats_t s_stats;
static uint32_t s_since_last_checkpoint = 0;

/* Rolling 24h query history for the dashboard graph: 48 buckets of 30 min.
 * Each bucket records totals for one 30-min wall-clock slot; the `slot`
 * field marks which slot it currently holds so stale buckets (from >24h
 * ago) are recycled. RAM-only - the graph resets on reboot, which is fine. */
#define HIST_BUCKETS  48
#define HIST_SECONDS  1800   /* 30 min per bucket */

typedef struct {
    uint32_t slot;      /* epoch / HIST_SECONDS this bucket represents */
    uint16_t total;
    uint16_t blocked;
} hist_bucket_t;

static hist_bucket_t s_hist[HIST_BUCKETS];

/* Return the current bucket, recycling it if it now belongs to a new slot. */
static hist_bucket_t *hist_current(void)
{
    uint32_t slot = (uint32_t)(time(NULL) / HIST_SECONDS);
    hist_bucket_t *b = &s_hist[slot % HIST_BUCKETS];
    if (b->slot != slot) {
        b->slot = slot;
        b->total = 0;
        b->blocked = 0;
    }
    return b;
}

/* Pure (no file I/O) serialize/deserialize, kept separate from persist()/
 * dns_stats_init() below so the actual encoding logic can be unit tested
 * without needing a mounted filesystem. */
char *dns_stats_to_json(const dns_stats_t *stats)
{
    cJSON *root = cJSON_CreateObject();
    if (root == NULL) {
        return NULL;
    }
    cJSON_AddNumberToObject(root, "total_queries", stats->total_queries);
    cJSON_AddNumberToObject(root, "blocked", stats->blocked);
    cJSON_AddNumberToObject(root, "cache_hits", stats->cache_hits);
    cJSON_AddNumberToObject(root, "forwarded", stats->forwarded);
    cJSON_AddNumberToObject(root, "forward_failures", stats->forward_failures);

    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return json;  /* caller must cJSON_free() this */
}

bool dns_stats_from_json(const char *json, dns_stats_t *out)
{
    cJSON *root = cJSON_Parse(json);
    if (root == NULL) {
        return false;
    }

    memset(out, 0, sizeof(*out));
    cJSON *item;
    if ((item = cJSON_GetObjectItem(root, "total_queries")) != NULL) {
        out->total_queries = (uint32_t)item->valuedouble;
    }
    if ((item = cJSON_GetObjectItem(root, "blocked")) != NULL) {
        out->blocked = (uint32_t)item->valuedouble;
    }
    if ((item = cJSON_GetObjectItem(root, "cache_hits")) != NULL) {
        out->cache_hits = (uint32_t)item->valuedouble;
    }
    if ((item = cJSON_GetObjectItem(root, "forwarded")) != NULL) {
        out->forwarded = (uint32_t)item->valuedouble;
    }
    if ((item = cJSON_GetObjectItem(root, "forward_failures")) != NULL) {
        out->forward_failures = (uint32_t)item->valuedouble;
    }
    cJSON_Delete(root);
    return true;
}

/* Write to a temp file and rename over the real one, rather than
 * truncating STATS_PATH in place. This device gets power-cycled/reflashed
 * a lot; truncate-then-write leaves a half-written, unparseable file if
 * that happens mid-write, silently resetting the lifetime counter to 0 on
 * every later boot. rename() is atomic on LittleFS, so the real file is
 * always either the old complete one or the new complete one. */
static void persist(void)
{
    char *json = dns_stats_to_json(&s_stats);
    if (json == NULL) {
        return;
    }
    FILE *f = fopen(STATS_TMP_PATH, "w");
    if (f != NULL) {
        fputs(json, f);
        fclose(f);
        if (rename(STATS_TMP_PATH, STATS_PATH) != 0) {
            ESP_LOGW(TAG, "Could not rename %s -> %s", STATS_TMP_PATH, STATS_PATH);
        }
    } else {
        ESP_LOGW(TAG, "Could not open %s for writing", STATS_TMP_PATH);
    }
    cJSON_free(json);
}

void dns_stats_checkpoint(void)
{
    s_since_last_checkpoint++;
    if (s_since_last_checkpoint >= PERSIST_EVERY_N_QUERIES) {
        s_since_last_checkpoint = 0;
        persist();
        dns_stats_log_summary();
    }
}

esp_err_t dns_stats_init(void)
{
    memset(&s_stats, 0, sizeof(s_stats));

    FILE *f = fopen(STATS_PATH, "r");
    if (f == NULL) {
        ESP_LOGI(TAG, "No previous statistics file - starting fresh");
        return ESP_OK;
    }

    char buf[256];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';

    if (!dns_stats_from_json(buf, &s_stats)) {
        ESP_LOGW(TAG, "Could not parse %s - starting fresh", STATS_PATH);
        memset(&s_stats, 0, sizeof(s_stats));
        return ESP_OK;
    }

    ESP_LOGI(TAG, "Loaded statistics: %lu lifetime queries so far",
             (unsigned long)s_stats.total_queries);
    return ESP_OK;
}

void dns_stats_record_query(void)
{
    s_stats.total_queries++;
    hist_current()->total++;
}

void dns_stats_record_blocked(void)        { s_stats.blocked++; hist_current()->blocked++; }
void dns_stats_record_cache_hit(void)      { s_stats.cache_hits++; }
void dns_stats_record_forwarded(void)      { s_stats.forwarded++; }
void dns_stats_record_forward_failure(void) { s_stats.forward_failures++; }

dns_stats_t dns_stats_get(void)
{
    return s_stats;
}

/* JSON array of the last 24h in chronological order:
 * [{"t":<minutes-ago-of-bucket-start>,"total":N,"blocked":M}, ...].
 * Only buckets with a real wall-clock slot are included (so before SNTP
 * sync the graph is simply empty rather than wrong). */
char *dns_stats_history_to_json(void)
{
    uint32_t now_slot = (uint32_t)(time(NULL) / HIST_SECONDS);
    cJSON *arr = cJSON_CreateArray();
    if (arr == NULL) {
        return NULL;
    }
    /* walk from oldest (now-47) to newest (now) slot */
    for (int i = HIST_BUCKETS - 1; i >= 0; i--) {
        uint32_t slot = now_slot - (uint32_t)i;
        hist_bucket_t *b = &s_hist[slot % HIST_BUCKETS];
        uint16_t total = (b->slot == slot) ? b->total : 0;
        uint16_t blocked = (b->slot == slot) ? b->blocked : 0;
        cJSON *o = cJSON_CreateObject();
        cJSON_AddNumberToObject(o, "m", i * (HIST_SECONDS / 60));  /* minutes ago */
        cJSON_AddNumberToObject(o, "total", total);
        cJSON_AddNumberToObject(o, "blocked", blocked);
        cJSON_AddItemToArray(arr, o);
    }
    char *json = cJSON_PrintUnformatted(arr);
    cJSON_Delete(arr);
    return json;
}

void dns_stats_log_summary(void)
{
    ESP_LOGI(TAG, "queries=%lu blocked=%lu cache_hits=%lu forwarded=%lu forward_failures=%lu",
             (unsigned long)s_stats.total_queries, (unsigned long)s_stats.blocked,
             (unsigned long)s_stats.cache_hits, (unsigned long)s_stats.forwarded,
             (unsigned long)s_stats.forward_failures);
}
