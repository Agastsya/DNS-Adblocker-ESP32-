#pragma once

#include <stdbool.h>
#include "esp_err.h"

/* Load the block/allow lists. For now this is a small built-in seed list;
 * Phase 10 (cloud blocklist sync) will extend this to load from LittleFS. */
esp_err_t blocklist_init(void);

/* True if `domain` (or one of its parent domains) is blocked and not
 * explicitly whitelisted. */
bool blocklist_is_blocked(const char *domain);
