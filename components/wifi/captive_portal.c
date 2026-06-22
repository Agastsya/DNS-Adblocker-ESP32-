#include "captive_portal.h"
#include "wifi_manager.h"

#include <string.h>

#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_http_server.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"

static const char *TAG = "captive_portal";

#define PORTAL_AP_SSID  "PocketDNS-Setup"
#define PORTAL_DNS_PORT 53

static const char SETUP_PAGE[] =
    "<!DOCTYPE html><html><head><meta charset='UTF-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>PocketDNS Setup</title><style>"
    "body{background:#121212;color:#e0e0e0;font-family:sans-serif;margin:0;padding:2rem;}"
    "h1{font-weight:600;}form{max-width:360px;}label{display:block;margin:1rem 0 0.3rem;color:#888;}"
    "input{width:100%;box-sizing:border-box;background:#1e1e1e;border:1px solid #2a2a2a;"
    "border-radius:8px;color:#e0e0e0;padding:0.7rem;font-size:1rem;}"
    "button{margin-top:1.5rem;width:100%;background:#4dabf7;color:#06121f;border:none;"
    "border-radius:8px;padding:0.8rem;font-weight:600;font-size:1rem;cursor:pointer;}"
    "</style></head><body><h1>PocketDNS Setup</h1>"
    "<p>Enter your home Wi-Fi details. The device will restart and join it.</p>"
    "<form action='/save' method='POST'>"
    "<label>Wi-Fi Name (SSID)</label><input name='ssid' autocomplete='off' required>"
    "<label>Password</label><input name='password' type='password' autocomplete='off'>"
    "<button type='submit'>Save &amp; Restart</button></form></body></html>";

/* --- tiny URL-decode for the form POST body (application/x-www-form-urlencoded) --- */
static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static void url_decode(const char *src, char *dst, size_t dst_len)
{
    size_t di = 0;
    for (size_t i = 0; src[i] != '\0' && di + 1 < dst_len; i++) {
        if (src[i] == '+') {
            dst[di++] = ' ';
        } else if (src[i] == '%' && hexval(src[i + 1]) >= 0 && hexval(src[i + 2]) >= 0) {
            dst[di++] = (char)(hexval(src[i + 1]) * 16 + hexval(src[i + 2]));
            i += 2;
        } else {
            dst[di++] = src[i];
        }
    }
    dst[di] = '\0';
}

/* Pull a field value out of "ssid=..&password=.." form data. */
static void form_field(const char *body, const char *key, char *out, size_t out_len)
{
    out[0] = '\0';
    size_t key_len = strlen(key);
    const char *p = body;
    while (p && *p) {
        if (strncmp(p, key, key_len) == 0 && p[key_len] == '=') {
            const char *val = p + key_len + 1;
            const char *amp = strchr(val, '&');
            char raw[128];
            size_t n = amp ? (size_t)(amp - val) : strlen(val);
            if (n >= sizeof(raw)) n = sizeof(raw) - 1;
            memcpy(raw, val, n);
            raw[n] = '\0';
            url_decode(raw, out, out_len);
            return;
        }
        p = strchr(p, '&');
        if (p) p++;
    }
}

static esp_err_t setup_get_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req, SETUP_PAGE, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t save_post_handler(httpd_req_t *req)
{
    char body[256];
    int total = req->content_len;
    if (total <= 0 || total >= (int)sizeof(body)) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Bad form");
        return ESP_FAIL;
    }
    int received = httpd_req_recv(req, body, total);
    if (received <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Could not read form");
        return ESP_FAIL;
    }
    body[received] = '\0';

    char ssid[33], pass[65];
    form_field(body, "ssid", ssid, sizeof(ssid));
    form_field(body, "password", pass, sizeof(pass));

    if (ssid[0] == '\0') {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "SSID required");
        return ESP_FAIL;
    }

    wifi_manager_save_credentials(ssid, pass);

    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req,
        "<html><body style='background:#121212;color:#e0e0e0;font-family:sans-serif;padding:2rem'>"
        "<h1>Saved</h1><p>PocketDNS is restarting and will join your network.</p></body></html>",
        HTTPD_RESP_USE_STRLEN);

    ESP_LOGI(TAG, "Credentials saved via portal - rebooting in 1s");
    vTaskDelay(pdMS_TO_TICKS(1000));
    esp_restart();
    return ESP_OK;  /* not reached */
}

/* Any other path -> redirect to the setup page, which is what makes
 * phones/laptops pop the captive-portal window automatically. */
static esp_err_t redirect_handler(httpd_req_t *req)
{
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "/");
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

static void start_portal_http(void)
{
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.uri_match_fn = httpd_uri_match_wildcard;
    httpd_handle_t server = NULL;
    if (httpd_start(&server, &config) != ESP_OK) {
        ESP_LOGE(TAG, "Portal HTTP server failed to start");
        return;
    }
    httpd_uri_t root = { .uri = "/", .method = HTTP_GET, .handler = setup_get_handler };
    httpd_register_uri_handler(server, &root);
    httpd_uri_t save = { .uri = "/save", .method = HTTP_POST, .handler = save_post_handler };
    httpd_register_uri_handler(server, &save);
    httpd_uri_t any = { .uri = "/*", .method = HTTP_GET, .handler = redirect_handler };
    httpd_register_uri_handler(server, &any);
}

/* Catch-all DNS: answer every A query with the AP's own IP (192.168.4.1)
 * so the client's connectivity check fails closed and opens the portal. */
static void captive_dns_task(void *pv)
{
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0) {
        vTaskDelete(NULL);
        return;
    }
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port = htons(PORTAL_DNS_PORT),
    };
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        vTaskDelete(NULL);
        return;
    }

    uint8_t buf[512];
    while (1) {
        struct sockaddr_in src;
        socklen_t sl = sizeof(src);
        int len = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&src, &sl);
        if (len < 12) {
            continue;
        }
        /* Build a minimal response: echo the question, add one A answer
         * pointing at 192.168.4.1. */
        buf[2] |= 0x80;   /* QR = response */
        buf[3] = 0x80;    /* RA */
        buf[6] = 0; buf[7] = 1;   /* ANCOUNT = 1 */
        buf[8] = 0; buf[9] = 0;
        buf[10] = 0; buf[11] = 0;

        if (len + 16 > (int)sizeof(buf)) {
            continue;
        }
        uint8_t *a = buf + len;
        *a++ = 0xC0; *a++ = 0x0C;        /* name -> pointer to the question */
        *a++ = 0x00; *a++ = 0x01;        /* TYPE A */
        *a++ = 0x00; *a++ = 0x01;        /* CLASS IN */
        *a++ = 0x00; *a++ = 0x00; *a++ = 0x00; *a++ = 0x3C;  /* TTL 60 */
        *a++ = 0x00; *a++ = 0x04;        /* RDLENGTH 4 */
        *a++ = 192; *a++ = 168; *a++ = 4; *a++ = 1;          /* 192.168.4.1 */

        sendto(sock, buf, len + 16, 0, (struct sockaddr *)&src, sl);
    }
}

void captive_portal_run(void)
{
    ESP_LOGW(TAG, "Starting captive portal - connect to Wi-Fi '%s' and open any page",
             PORTAL_AP_SSID);

    /* The STA stack was already initialised by wifi_manager_connect(); stop
     * it and bring the radio up as an access point instead. */
    esp_wifi_stop();
    esp_netif_create_default_wifi_ap();

    wifi_config_t ap_config = {
        .ap = {
            .ssid = PORTAL_AP_SSID,
            .ssid_len = strlen(PORTAL_AP_SSID),
            .max_connection = 4,
            .authmode = WIFI_AUTH_OPEN,
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    xTaskCreate(captive_dns_task, "captive_dns", 4096, NULL, 5, NULL);
    start_portal_http();

    /* Nothing else to do here - the device lives in portal mode until the
     * user submits the form, which saves creds and reboots. */
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(10000));
    }
}
