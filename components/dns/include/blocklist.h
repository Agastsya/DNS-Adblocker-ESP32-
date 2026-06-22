#pragma once

#include <stdbool.h>
#include "esp_err.h"

/* Load the block/allow lists. For now this is a small built-in seed list;
 * Phase 10 (cloud blocklist sync) will extend this to load from LittleFS. */
esp_err_t blocklist_init(void);

/* True if `domain` (or one of its parent domains) is blocked and not
 * explicitly whitelisted. */
bool blocklist_is_blocked(const char *domain);

/* Start a background task that fetches the cloud blocklist immediately
 * and then once every 24h, replacing the in-memory list on success and
 * leaving the existing one in place on failure. Call once at startup. */
void blocklist_start_cloud_sync(void);

/* User whitelist management (persisted to LittleFS). add/remove return
 * true on success; add is idempotent. to_json returns a malloc'd JSON
 * array string the caller must cJSON_free(). */
bool blocklist_whitelist_add(const char *domain);
bool blocklist_whitelist_remove(const char *domain);
char *blocklist_whitelist_to_json(void);
