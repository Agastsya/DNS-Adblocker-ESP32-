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
 * been fully recorded. Persists the running totals (and 24h history) to
 * flash once enough queries or enough time has passed since the last save. */
void dns_stats_checkpoint(void);

/* Starts a low-priority background task that persists stats on a fixed
 * cadence if anything changed since the last save - catches a reboot
 * during a quiet spell that dns_stats_checkpoint() alone wouldn't see
 * (it only runs when a query arrives). Call once after dns_stats_init(). */
void dns_stats_start_autosave(void);

dns_stats_t dns_stats_get(void);

/* Log a one-line summary at INFO level. */
void dns_stats_log_summary(void);

/* Pure (no file I/O) serialize/deserialize - exposed mainly so the
 * encoding logic can be unit tested without a mounted filesystem. */
char *dns_stats_to_json(const dns_stats_t *stats);   /* caller must cJSON_free() the result */
bool dns_stats_from_json(const char *json, dns_stats_t *out);

/* Rolling 24h query history for the dashboard graph (caller cJSON_free()s). */
char *dns_stats_history_to_json(void);
