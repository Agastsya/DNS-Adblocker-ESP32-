#pragma once

#include <stdbool.h>
#include "esp_err.h"

/* Initialise NVS and the Wi-Fi/netif stack, then join a network using
 * credentials from NVS (set previously via the captive portal) or, if
 * none are stored, the build-time `idf.py menuconfig` defaults. Blocks
 * until we get an IP or exhaust our retries. Returns ESP_OK on success,
 * ESP_FAIL if there are no usable credentials or the connection failed. */
esp_err_t wifi_manager_connect(void);

/* Persist home Wi-Fi credentials to NVS (used by the captive portal). */
esp_err_t wifi_manager_save_credentials(const char *ssid, const char *password);

/* Launch the captive-portal SoftAP so the user can enter their Wi-Fi
 * details. Does not return - the device reboots once they're saved. */
void wifi_manager_start_portal(void);
