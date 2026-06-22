#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

typedef struct {
    uint32_t total_queries;
    uint32_t blocked;
    uint32_t cache_hits;
    uint32_t forwarded;
    uint32_t forward_failures;
} dns_stats_t;

/* Load any previously persisted lifetime stats from LittleFS, so counts
 * survive a reboot. Call after storage_init() has mounted the filesystem. */
esp_err_t dns_stats_init(void);

void dns_stats_record_query(void);
void dns_stats_record_blocked(void);
void dns_stats_record_cache_hit(void);
void dns_stats_record_forwarded(void);
void dns_stats_record_forward_failure(void);

/* Call once a query's outcome (blocked/cache hit/forwarded/failed) has
 * been fully recorded. Every Nth call persists the running totals to
 * flash and logs a summary - on a query count rather than a wall-clock
 * timer, so no extra periodic task is needed. */
void dns_stats_checkpoint(void);

dns_stats_t dns_stats_get(void);

/* Log a one-line summary at INFO level. */
void dns_stats_log_summary(void);

/* Pure (no file I/O) serialize/deserialize - exposed mainly so the
 * encoding logic can be unit tested without a mounted filesystem. */
char *dns_stats_to_json(const dns_stats_t *stats);   /* caller must cJSON_free() the result */
bool dns_stats_from_json(const char *json, dns_stats_t *out);
