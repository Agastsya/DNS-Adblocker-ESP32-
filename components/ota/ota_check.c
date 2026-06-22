#include "ota_check.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "esp_app_desc.h"
#include "esp_http_client.h"
#include "esp_https_ota.h"
#include "esp_crt_bundle.h"
#include "cJSON.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "ota_check";

#define GITHUB_RELEASES_API_URL \
    "https://api.github.com/repos/Agastsya/DNS-Adblocker-ESP32-/releases/latest"
#define FIRMWARE_ASSET_NAME "pocketdns.bin"
#define CHECK_INTERVAL_MS    (24UL * 60 * 60 * 1000)  /* once a day */

typedef struct {
    char version[32];
    char download_url[256];
} ota_release_info_t;

/* Pure (no I/O) JSON parsing, kept separate from the HTTP fetch below so
 * it can be unit tested against a saved sample response without a
 * network connection. Returns true if both a tag_name and a matching
 * firmware asset URL were found. */
static bool parse_release_json(const char *json, ota_release_info_t *out)
{
    memset(out, 0, sizeof(*out));

    cJSON *root = cJSON_Parse(json);
    if (root == NULL) {
        return false;
    }

    bool found = false;
    cJSON *tag = cJSON_GetObjectItem(root, "tag_name");
    cJSON *assets = cJSON_GetObjectItem(root, "assets");
    if (cJSON_IsString(tag) && cJSON_IsArray(assets)) {
        strncpy(out->version, tag->valuestring, sizeof(out->version) - 1);

        int n = cJSON_GetArraySize(assets);
        for (int i = 0; i < n; i++) {
            cJSON *asset = cJSON_GetArrayItem(assets, i);
            cJSON *name = cJSON_GetObjectItem(asset, "name");
            cJSON *url = cJSON_GetObjectItem(asset, "browser_download_url");
            if (cJSON_IsString(name) && cJSON_IsString(url) &&
                strcmp(name->valuestring, FIRMWARE_ASSET_NAME) == 0) {
                strncpy(out->download_url, url->valuestring, sizeof(out->download_url) - 1);
                found = true;
                break;
            }
        }
    }
    cJSON_Delete(root);
    return found;
}

static char *s_response_buf = NULL;
static size_t s_response_len = 0;
static size_t s_response_cap = 0;

static esp_err_t api_http_event_handler(esp_http_client_event_t *evt)
{
    if (evt->event_id != HTTP_EVENT_ON_DATA) {
        return ESP_OK;
    }
    size_t needed = s_response_len + (size_t)evt->data_len + 1;
    if (needed > s_response_cap) {
        size_t new_cap = needed + 1024;
        char *new_buf = realloc(s_response_buf, new_cap);
        if (new_buf == NULL) {
            return ESP_FAIL;
        }
        s_response_buf = new_buf;
        s_response_cap = new_cap;
    }
    memcpy(s_response_buf + s_response_len, evt->data, evt->data_len);
    s_response_len += evt->data_len;
    s_response_buf[s_response_len] = '\0';
    return ESP_OK;
}

static bool fetch_latest_release(ota_release_info_t *out)
{
    free(s_response_buf);
    s_response_buf = NULL;
    s_response_len = 0;
    s_response_cap = 0;

    esp_http_client_config_t config = {
        .url = GITHUB_RELEASES_API_URL,
        .event_handler = api_http_event_handler,
        .timeout_ms = 10000,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .user_agent = "PocketDNS-OTA",  /* GitHub's API rejects requests with no User-Agent */
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_err_t err = esp_http_client_perform(client);
    int status = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);

    if (err != ESP_OK || status != 200 || s_response_buf == NULL) {
        ESP_LOGW(TAG, "Could not fetch latest release info: %s (HTTP %d)", esp_err_to_name(err), status);
        return false;
    }

    bool ok = parse_release_json(s_response_buf, out);
    if (!ok) {
        ESP_LOGW(TAG, "Release JSON had no tag_name / no '%s' asset", FIRMWARE_ASSET_NAME);
    }
    return ok;
}

static void apply_ota_update(const char *url)
{
    ESP_LOGI(TAG, "Applying OTA update from %s", url);

    esp_http_client_config_t http_config = {
        .url = url,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .timeout_ms = 30000,
    };
    esp_https_ota_config_t ota_config = {
        .http_config = &http_config,
    };

    esp_err_t err = esp_https_ota(&ota_config);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "OTA failed: %s", esp_err_to_name(err));
        return;
    }

    ESP_LOGI(TAG, "OTA succeeded - rebooting into the new firmware");
    esp_restart();
}

static void do_check(void)
{
    const esp_app_desc_t *app_desc = esp_app_get_description();
    ESP_LOGI(TAG, "Checking for updates (current version: %s)", app_desc->version);

    ota_release_info_t release;
    if (!fetch_latest_release(&release)) {
        ESP_LOGW(TAG, "OTA check failed - could not get latest release info");
        return;
    }

    ESP_LOGI(TAG, "Latest GitHub release: %s", release.version);

    if (strcmp(release.version, app_desc->version) == 0) {
        ESP_LOGI(TAG, "Already running the latest version");
        return;
    }

    ESP_LOGI(TAG, "New version available (%s -> %s) - downloading update",
             app_desc->version, release.version);
    apply_ota_update(release.download_url);
}

static void ota_check_task(void *pvParameters)
{
    while (1) {
        do_check();
        vTaskDelay(pdMS_TO_TICKS(CHECK_INTERVAL_MS));
    }
}

void ota_start_periodic_check(void)
{
    xTaskCreate(ota_check_task, "ota_check", 8192, NULL, 3, NULL);
}
