#include "dns_stats.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#include "cJSON.h"

static const char *TAG = "dns_stats";

#define STATS_PATH               "/littlefs/statistics.json"
#define PERSIST_EVERY_N_QUERIES  10

static dns_stats_t s_stats;
static uint32_t s_since_last_checkpoint = 0;

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

static void persist(void)
{
    char *json = dns_stats_to_json(&s_stats);
    if (json == NULL) {
        return;
    }
    FILE *f = fopen(STATS_PATH, "w");
    if (f != NULL) {
        fputs(json, f);
        fclose(f);
    } else {
        ESP_LOGW(TAG, "Could not open %s for writing", STATS_PATH);
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
}

void dns_stats_record_blocked(void)        { s_stats.blocked++; }
void dns_stats_record_cache_hit(void)      { s_stats.cache_hits++; }
void dns_stats_record_forwarded(void)      { s_stats.forwarded++; }
void dns_stats_record_forward_failure(void) { s_stats.forward_failures++; }

dns_stats_t dns_stats_get(void)
{
    return s_stats;
}

void dns_stats_log_summary(void)
{
    ESP_LOGI(TAG, "queries=%lu blocked=%lu cache_hits=%lu forwarded=%lu forward_failures=%lu",
             (unsigned long)s_stats.total_queries, (unsigned long)s_stats.blocked,
             (unsigned long)s_stats.cache_hits, (unsigned long)s_stats.forwarded,
             (unsigned long)s_stats.forward_failures);
}
