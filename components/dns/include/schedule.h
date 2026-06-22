#pragma once

#include <stdbool.h>
#include "esp_err.h"

/* Parental-control schedules: block a domain during a daily time window.
 * Times are minutes since midnight, local time (0-1439). A window where
 * start <= end is a normal same-day window; start > end wraps past
 * midnight (e.g. 21:00-07:00). Persisted to LittleFS, editable via the
 * dashboard REST API. */

/* Load saved schedules from LittleFS. Call after storage is mounted. */
esp_err_t schedule_init(void);

/* Start SNTP so the device knows the wall-clock time the windows are
 * checked against. Without a synced clock, schedules don't block. */
void schedule_start_time_sync(void);

/* True if `domain` is inside an active blocking window right now. */
bool schedule_is_blocked_now(const char *domain);

/* Pure helper (no clock, no I/O): is `domain` blocked at now_min minutes
 * past local midnight, given the current schedule table? Exposed for
 * unit testing the window math. */
bool schedule_domain_blocked_at(const char *domain, int now_min);

/* Management (persisted). add returns false if the table is full or args
 * are invalid; remove returns false if no schedule for that domain. */
bool schedule_add(const char *domain, int start_min, int end_min);
bool schedule_remove(const char *domain);

/* Malloc'd JSON array of {"domain","start","end"} objects; caller
 * cJSON_free()s it. */
char *schedule_to_json(void);
