#include "storage.h"

#include <stdio.h>

#include "esp_log.h"
#include "esp_littlefs.h"   /* provided by the joltwallet/littlefs component */

static const char *TAG = "storage";

#define LFS_BASE_PATH   "/littlefs"
#define LFS_PARTITION   "littlefs"
#define BOOTCOUNT_PATH  LFS_BASE_PATH "/bootcount.txt"

esp_err_t storage_init(void)
{
    esp_vfs_littlefs_conf_t conf = {
        .base_path = LFS_BASE_PATH,
        .partition_label = LFS_PARTITION,
        .format_if_mount_failed = true,  /* first boot: blank flash -> format */
        .dont_mount = false,
    };

    esp_err_t err = esp_vfs_littlefs_register(&conf);
    if (err != ESP_OK) {
        if (err == ESP_FAIL) {
            ESP_LOGE(TAG, "Failed to mount or format LittleFS");
        } else if (err == ESP_ERR_NOT_FOUND) {
            ESP_LOGE(TAG, "Partition '%s' not found - check partitions.csv", LFS_PARTITION);
        } else {
            ESP_LOGE(TAG, "littlefs register failed: %s", esp_err_to_name(err));
        }
        return err;
    }

    size_t total = 0, used = 0;
    if (esp_littlefs_info(LFS_PARTITION, &total, &used) == ESP_OK) {
        /* Integer percent on purpose: floating-point in log format strings is
         * a classic ESP32 footgun (it can print garbage unless full newlib
         * formatting is linked). Avoid %f in logs until you actually need it. */
        unsigned pct = total ? (unsigned)(((uint64_t)used * 100) / total) : 0;
        ESP_LOGI(TAG, "LittleFS mounted at %s | used %u / %u bytes (%u%%)",
                 LFS_BASE_PATH, (unsigned)used, (unsigned)total, pct);
    } else {
        ESP_LOGW(TAG, "Mounted, but could not read filesystem usage info");
    }
    return ESP_OK;
}

uint32_t storage_bootcount_increment(void)
{
    uint32_t count = 0;

    FILE *f = fopen(BOOTCOUNT_PATH, "r");
    if (f != NULL) {
        unsigned long tmp = 0;
        if (fscanf(f, "%lu", &tmp) == 1) {
            count = (uint32_t)tmp;
        }
        fclose(f);
    } else {
        ESP_LOGI(TAG, "No boot counter file yet - first ever boot");
    }

    count++;

    f = fopen(BOOTCOUNT_PATH, "w");
    if (f == NULL) {
        ESP_LOGE(TAG, "Could not open %s for writing", BOOTCOUNT_PATH);
        return count;
    }
    fprintf(f, "%lu", (unsigned long)count);
    fclose(f);

    return count;
}
