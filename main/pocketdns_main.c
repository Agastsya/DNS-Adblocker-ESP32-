/* ==========================================================================
 * PocketDNS
 *
 * app_main() just orchestrates the components: mount storage, prove
 * persistence with a boot counter, join Wi-Fi (or run the captive portal
 * if there are no credentials), then start the DNS + web servers. The
 * actual logic for each step lives in components/{storage,wifi,dns,web,ota}.
 * ========================================================================== */

#include <stdint.h>
#include <stdio.h>

#include "esp_log.h"
#include "esp_system.h"
#include "storage.h"
#include "wifi_manager.h"
#include "dns_server.h"
#include "web_server.h"
#include "ota_check.h"
#include "blocklist.h"
#include "schedule.h"

static const char *TAG = "pocketdns";

/* One-time housekeeping: clear the test artifacts left on flash during
 * development (a doubleclick.net whitelist that was leaking ads, and a
 * scheduletest.com schedule), and prove the manual "Block a website" path
 * works end to end. Guarded by a marker so it runs exactly once. */
#define CLEANUP_MARKER "/littlefs/cleanup_v1_done"
static void one_time_cleanup_and_selfcheck(void)
{
    FILE *m = fopen(CLEANUP_MARKER, "r");
    if (m != NULL) {
        fclose(m);
        return;
    }

    blocklist_whitelist_remove("doubleclick.net");
    schedule_remove("scheduletest.com");

    /* Manual-block self-check: add, verify it (and a subdomain) is blocked,
     * then remove so nothing is left behind. */
    blocklist_manual_add("selfblockcheck.invalid");
    bool exact = blocklist_is_blocked("selfblockcheck.invalid");
    bool sub   = blocklist_is_blocked("ads.selfblockcheck.invalid");
    blocklist_manual_remove("selfblockcheck.invalid");
    ESP_LOGI(TAG, "Manual-block self-check: exact=%s subdomain=%s -> %s",
             exact ? "blocked" : "ALLOWED", sub ? "blocked" : "ALLOWED",
             (exact && sub) ? "PASS" : "FAIL");

    FILE *w = fopen(CLEANUP_MARKER, "w");
    if (w) { fputs("done", w); fclose(w); }
}

void app_main(void)
{
    ESP_LOGI(TAG, "=== PocketDNS booting ===");

    if (storage_init() != ESP_OK) {
        ESP_LOGE(TAG, "Storage init failed; halting.");
        return;
    }

    uint32_t boots = storage_bootcount_increment();
    ESP_LOGI(TAG, ">>> This device has booted %lu time(s) <<<", (unsigned long)boots);

    if (wifi_manager_connect() != ESP_OK) {
        /* No usable credentials, or the connection failed - hand off to the
         * captive portal so the user can set up Wi-Fi. This does not return;
         * the device reboots once they submit their details. */
        ESP_LOGW(TAG, "Wi-Fi unavailable - starting captive portal for setup");
        wifi_manager_start_portal();
    }

    dns_server_start();
    one_time_cleanup_and_selfcheck();
    web_server_start();
    ota_start_periodic_check();

    ESP_LOGI(TAG, "Free heap: %lu bytes", (unsigned long)esp_get_free_heap_size());
    ESP_LOGI(TAG, "Boot sequence complete.");
}
