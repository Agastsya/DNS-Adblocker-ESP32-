#pragma once

#include "esp_err.h"

/* Initialise NVS (if needed), join the network configured via
 * `idf.py menuconfig` -> "PocketDNS Configuration", and block until we
 * either get an IP or exhaust our retries. Returns ESP_OK on success. */
esp_err_t wifi_manager_connect(void);
