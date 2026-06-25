#include "wifi_manager.h"
#include "captive_portal.h"

#include <string.h>

#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "mdns.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"

#define MDNS_HOSTNAME "pocketdns"

static const char *TAG = "wifi_manager";

/* Lets the dashboard be reached at http://pocketdns.local/ regardless of
 * what IP DHCP hands out - the device's IP changes across reboots/lease
 * renewals, which otherwise makes a bookmarked IP "go dead" and look like
 * the whole thing is broken when it's just at a new address. */
static void start_mdns(void)
{
    esp_err_t err = mdns_init();
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "mDNS init failed: %s (dashboard still reachable by IP)", esp_err_to_name(err));
        return;
    }
    mdns_hostname_set(MDNS_HOSTNAME);
    mdns_instance_name_set("PocketDNS");
    mdns_service_add(NULL, "_http", "_tcp", 80, NULL, 0);
    ESP_LOGI(TAG, "mDNS up - dashboard also reachable at http://%s.local/", MDNS_HOSTNAME);
}

/* Bits set on s_wifi_event_group to report the outcome of a connection
 * attempt back to wifi_manager_connect(), which blocks waiting for one. */
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1

#define NVS_WIFI_NAMESPACE "pdns_wifi"
#define NVS_KEY_SSID       "ssid"
#define NVS_KEY_PASS       "pass"

static EventGroupHandle_t s_wifi_event_group;
static int s_retry_num = 0;

static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                                int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
#if CONFIG_POCKETDNS_STATIC_IP_ENABLE
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_CONNECTED) {
        /* With a static IP, the DHCP client (which normally posts
         * IP_EVENT_STA_GOT_IP once a lease is granted) never runs - so
         * that event never fires. Association success is as good as it
         * gets here; the IP was already configured before esp_wifi_start(). */
        ESP_LOGI(TAG, "Associated (static IP %s)", CONFIG_POCKETDNS_STATIC_IP);
        s_retry_num = 0;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
#endif
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_retry_num < CONFIG_POCKETDNS_WIFI_MAXIMUM_RETRY) {
            s_retry_num++;
            ESP_LOGW(TAG, "Wi-Fi disconnected, retrying (%d/%d)",
                     s_retry_num, CONFIG_POCKETDNS_WIFI_MAXIMUM_RETRY);
            esp_wifi_connect();
        } else {
            xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
        }
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *) event_data;
        ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&event->ip_info.ip));
        s_retry_num = 0;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

static esp_err_t nvs_init(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "NVS unusable, erasing and re-initialising");
        ESP_ERROR_CHECK(nvs_flash_erase());
        return nvs_flash_init();
    }
    return err;
}

/* Fill ssid/pass from NVS; if nothing's stored there, fall back to the
 * build-time Kconfig defaults. Returns true if a non-empty SSID resulted
 * (i.e. we have something to try connecting with). */
static bool load_credentials(char *ssid, size_t ssid_len, char *pass, size_t pass_len)
{
    ssid[0] = '\0';
    pass[0] = '\0';

    nvs_handle_t h;
    if (nvs_open(NVS_WIFI_NAMESPACE, NVS_READONLY, &h) == ESP_OK) {
        size_t sl = ssid_len, pl = pass_len;
        nvs_get_str(h, NVS_KEY_SSID, ssid, &sl);
        nvs_get_str(h, NVS_KEY_PASS, pass, &pl);
        nvs_close(h);
    }

    if (ssid[0] == '\0') {
        /* Nothing provisioned yet - seed from the build-time defaults so a
         * freshly-flashed device with Kconfig creds still "just works". */
        strlcpy(ssid, CONFIG_POCKETDNS_WIFI_SSID, ssid_len);
        strlcpy(pass, CONFIG_POCKETDNS_WIFI_PASSWORD, pass_len);
    }

    return ssid[0] != '\0';
}

esp_err_t wifi_manager_save_credentials(const char *ssid, const char *password)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_WIFI_NAMESPACE, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        return err;
    }
    nvs_set_str(h, NVS_KEY_SSID, ssid);
    nvs_set_str(h, NVS_KEY_PASS, password);
    err = nvs_commit(h);
    nvs_close(h);
    ESP_LOGI(TAG, "Saved Wi-Fi credentials for SSID '%s' to NVS", ssid);
    return err;
}

esp_err_t wifi_manager_connect(void)
{
    ESP_ERROR_CHECK(nvs_init());

    /* Always bring up the netif + Wi-Fi stack first, so that if we end up
     * with no usable credentials the captive portal can rely on a
     * consistently-initialised state and just switch the radio to AP. */
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_t *sta_netif = esp_netif_create_default_wifi_sta();

#if CONFIG_POCKETDNS_STATIC_IP_ENABLE
    /* A static IP means a bookmark/DNS setting pointed at this device never
     * goes stale after a reboot or DHCP lease renewal - the recurring
     * "dashboard looks dead" issue whenever the router handed out a new
     * address. Must be set before esp_wifi_start(); DHCP client is stopped
     * first since it would otherwise overwrite this once connected. */
    esp_netif_dhcpc_stop(sta_netif);
    esp_netif_ip_info_t static_ip = { 0 };
    static_ip.ip.addr      = esp_ip4addr_aton(CONFIG_POCKETDNS_STATIC_IP);
    static_ip.gw.addr      = esp_ip4addr_aton(CONFIG_POCKETDNS_STATIC_GATEWAY);
    static_ip.netmask.addr = esp_ip4addr_aton(CONFIG_POCKETDNS_STATIC_NETMASK);
    ESP_ERROR_CHECK(esp_netif_set_ip_info(sta_netif, &static_ip));

    /* DHCP normally hands us upstream DNS servers too - with it stopped,
     * the netif has none, so this device's OWN lookups (blocklist download
     * host, OTA check host, NTP pool) all fail even though it serves DNS
     * to everyone else fine. Point its own resolver at public DNS so those
     * outbound requests work regardless of what clients are told to use. */
    esp_netif_dns_info_t dns_main = { 0 };
    dns_main.ip.type = ESP_IPADDR_TYPE_V4;
    dns_main.ip.u_addr.ip4.addr = esp_ip4addr_aton("1.1.1.1");
    esp_netif_set_dns_info(sta_netif, ESP_NETIF_DNS_MAIN, &dns_main);

    esp_netif_dns_info_t dns_backup = { 0 };
    dns_backup.ip.type = ESP_IPADDR_TYPE_V4;
    dns_backup.ip.u_addr.ip4.addr = esp_ip4addr_aton("8.8.8.8");
    esp_netif_set_dns_info(sta_netif, ESP_NETIF_DNS_BACKUP, &dns_backup);

    ESP_LOGI(TAG, "Static IP configured: %s", CONFIG_POCKETDNS_STATIC_IP);
#endif

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    char ssid[33];
    char pass[65];
    if (!load_credentials(ssid, sizeof(ssid), pass, sizeof(pass))) {
        ESP_LOGW(TAG, "No Wi-Fi credentials stored or configured");
        return ESP_FAIL;
    }

    s_wifi_event_group = xEventGroupCreate();

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, &instance_got_ip));

    wifi_config_t wifi_config = {
        .sta = {
            .threshold.authmode = WIFI_AUTH_WPA2_PSK,
        },
    };
    strlcpy((char *)wifi_config.sta.ssid, ssid, sizeof(wifi_config.sta.ssid));
    strlcpy((char *)wifi_config.sta.password, pass, sizeof(wifi_config.sta.password));

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "Connecting to SSID '%s' ...", ssid);

    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
                                            WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
                                            pdFALSE, pdFALSE, portMAX_DELAY);

    esp_err_t result = ESP_FAIL;
    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "Wi-Fi connected");
        start_mdns();
        result = ESP_OK;
    } else if (bits & WIFI_FAIL_BIT) {
        ESP_LOGE(TAG, "Failed to connect after %d attempts", CONFIG_POCKETDNS_WIFI_MAXIMUM_RETRY);
    }

    ESP_ERROR_CHECK(esp_event_handler_instance_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, instance_got_ip));
    ESP_ERROR_CHECK(esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, instance_any_id));
    vEventGroupDelete(s_wifi_event_group);

    return result;
}

void wifi_manager_start_portal(void)
{
    captive_portal_run();
}
