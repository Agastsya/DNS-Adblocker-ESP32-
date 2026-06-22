#pragma once

#include <stdint.h>
#include "esp_err.h"

/* Mount LittleFS, formatting the partition on first boot. */
esp_err_t storage_init(void);

/* Read the saved boot counter (0 if none), increment it, save it, and
 * return the new value. */
uint32_t storage_bootcount_increment(void);
