#pragma once

/* Start a background task that checks the project's GitHub Releases for
 * a firmware build newer than the one currently running, immediately and
 * then once a day. If found, downloads it via esp_https_ota and reboots
 * into it; if not, leaves the running firmware alone. */
void ota_start_periodic_check(void);
