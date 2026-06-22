/* ==========================================================================
 * PocketDNS
 *
 * app_main() just orchestrates the components: mount storage, prove
 * persistence with a boot counter, join Wi-Fi, then start the DNS server.
 * The actual logic for each step lives in components/{storage,wifi,dns}.
 * ========================================================================== */

#include <stdint.h>
#include <stdbool.h>

#include "esp_log.h"
#include "esp_system.h"
#include "storage.h"
#include "wifi_manager.h"
#include "dns_server.h"

static const char *TAG = "pocketdns";

void app_main(void)
{
    ESP_LOGI(TAG, "=== PocketDNS booting ===");

    if (storage_init() != ESP_OK) {
        ESP_LOGE(TAG, "Storage init failed; halting.");
        return;
    }

    uint32_t boots = storage_bootcount_increment();
    ESP_LOGI(TAG, ">>> This device has booted %lu time(s) <<<", (unsigned long)boots);

    bool wifi_ok = (wifi_manager_connect() == ESP_OK);
    if (!wifi_ok) {
        ESP_LOGW(TAG, "Continuing without Wi-Fi");
    }

    if (wifi_ok) {
        dns_server_start();
    }

    ESP_LOGI(TAG, "Free heap: %lu bytes", (unsigned long)esp_get_free_heap_size());
    ESP_LOGI(TAG, "Boot sequence complete.");
}
