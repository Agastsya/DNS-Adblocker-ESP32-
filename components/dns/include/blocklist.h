#pragma once

#include <stdbool.h>
#include <stdint.h>
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

/* Number of domains in the active cloud blocklist index, or 0 if it
 * hasn't been built/loaded yet (the built-in list is still in force). */
uint32_t blocklist_active_count(void);

/* User whitelist management (persisted to LittleFS). add/remove return
 * true on success; add is idempotent. to_json returns a malloc'd JSON
 * array string the caller must cJSON_free(). */
bool blocklist_whitelist_add(const char *domain);
bool blocklist_whitelist_remove(const char *domain);
char *blocklist_whitelist_to_json(void);

/* User manual blocklist - domains the user blocks via the dashboard, on
 * top of the cloud list (whitelist still overrides). Same semantics as
 * the whitelist helpers above. */
bool blocklist_manual_add(const char *domain);
bool blocklist_manual_remove(const char *domain);
char *blocklist_manual_to_json(void);

/* User-uploaded custom blocklist (bulk paste/import, one domain per line).
 * set replaces the whole list from raw text and persists it; get_text
 * returns the stored text (caller free()s); count is the active entries. */
bool blocklist_custom_set(const char *text);
char *blocklist_custom_get_text(void);
size_t blocklist_custom_count(void);
