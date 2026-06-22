#include "web_server.h"

#include <string.h>
#include <stdio.h>

#include "esp_log.h"
#include "esp_http_server.h"
#include "dns_stats.h"
#include "blocklist.h"
#include "schedule.h"
#include "cJSON.h"
#include "sdkconfig.h"

#if CONFIG_POCKETDNS_WEB_AUTH_ENABLE
#include "mbedtls/base64.h"
#endif

static const char *TAG = "web_server";

extern const uint8_t dashboard_html_start[] asm("_binary_dashboard_html_start");
extern const uint8_t dashboard_html_end[]   asm("_binary_dashboard_html_end");

#if CONFIG_POCKETDNS_WEB_AUTH_ENABLE
/* "Basic " + base64("user:pass"), precomputed once at startup so each
 * request is just a string compare against the client's Authorization
 * header. */
static char s_expected_auth[200];

static void build_expected_auth(void)
{
    char creds[96];
    int creds_len = snprintf(creds, sizeof(creds), "%s:%s",
                             CONFIG_POCKETDNS_WEB_AUTH_USER,
                             CONFIG_POCKETDNS_WEB_AUTH_PASSWORD);

    char b64[136];
    size_t b64_len = 0;
    mbedtls_base64_encode((unsigned char *)b64, sizeof(b64), &b64_len,
                          (const unsigned char *)creds, creds_len);
    b64[b64_len] = '\0';
    snprintf(s_expected_auth, sizeof(s_expected_auth), "Basic %s", b64);
}

/* Returns true if the request carries valid credentials. Otherwise sends
 * a 401 challenge and returns false - handlers should just return ESP_OK
 * in that case, the response is already complete. */
static bool check_auth(httpd_req_t *req)
{
    size_t hdr_len = httpd_req_get_hdr_value_len(req, "Authorization");
    if (hdr_len > 0 && hdr_len < 128) {
        char hdr[128];
        if (httpd_req_get_hdr_value_str(req, "Authorization", hdr, sizeof(hdr)) == ESP_OK &&
            strcmp(hdr, s_expected_auth) == 0) {
            return true;
        }
    }
    httpd_resp_set_status(req, "401 Unauthorized");
    httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"PocketDNS\"");
    httpd_resp_send(req, "Authentication required", HTTPD_RESP_USE_STRLEN);
    return false;
}
#else
static bool check_auth(httpd_req_t *req) { (void)req; return true; }
#endif

static esp_err_t root_get_handler(httpd_req_t *req)
{
    if (!check_auth(req)) {
        return ESP_OK;
    }
    size_t len = dashboard_html_end - dashboard_html_start;
    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req, (const char *)dashboard_html_start, len);
}

static esp_err_t api_stats_get_handler(httpd_req_t *req)
{
    if (!check_auth(req)) {
        return ESP_OK;
    }
    dns_stats_t stats = dns_stats_get();
    char *json = dns_stats_to_json(&stats);
    if (json == NULL) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    httpd_resp_set_type(req, "application/json");
    esp_err_t err = httpd_resp_send(req, json, HTTPD_RESP_USE_STRLEN);
    cJSON_free(json);
    return err;
}

static esp_err_t api_whitelist_get_handler(httpd_req_t *req)
{
    if (!check_auth(req)) {
        return ESP_OK;
    }
    char *json = blocklist_whitelist_to_json();
    if (json == NULL) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "application/json");
    esp_err_t err = httpd_resp_send(req, json, HTTPD_RESP_USE_STRLEN);
    cJSON_free(json);
    return err;
}

/* POST /api/whitelist with body {"domain":"x.com","action":"add"|"remove"} */
static esp_err_t api_whitelist_post_handler(httpd_req_t *req)
{
    if (!check_auth(req)) {
        return ESP_OK;
    }

    char body[160];
    int total = req->content_len;
    if (total <= 0 || total >= (int)sizeof(body)) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Bad request body");
        return ESP_FAIL;
    }
    int received = httpd_req_recv(req, body, total);
    if (received <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Could not read body");
        return ESP_FAIL;
    }
    body[received] = '\0';

    cJSON *root = cJSON_Parse(body);
    cJSON *domain = root ? cJSON_GetObjectItem(root, "domain") : NULL;
    cJSON *action = root ? cJSON_GetObjectItem(root, "action") : NULL;
    if (!cJSON_IsString(domain) || !cJSON_IsString(action)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Need string domain + action");
        return ESP_FAIL;
    }

    bool ok;
    if (strcmp(action->valuestring, "remove") == 0) {
        ok = blocklist_whitelist_remove(domain->valuestring);
    } else {
        ok = blocklist_whitelist_add(domain->valuestring);
    }
    cJSON_Delete(root);

    if (!ok) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Operation failed (full, or domain not found)");
        return ESP_FAIL;
    }

    char *json = blocklist_whitelist_to_json();
    httpd_resp_set_type(req, "application/json");
    esp_err_t err = httpd_resp_send(req, json ? json : "[]", HTTPD_RESP_USE_STRLEN);
    cJSON_free(json);
    return err;
}

static esp_err_t api_blocklist_get_handler(httpd_req_t *req)
{
    if (!check_auth(req)) {
        return ESP_OK;
    }
    char *json = blocklist_manual_to_json();
    if (json == NULL) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "application/json");
    esp_err_t err = httpd_resp_send(req, json, HTTPD_RESP_USE_STRLEN);
    cJSON_free(json);
    return err;
}

/* POST /api/blocklist with body {"domain":"x.com","action":"add"|"remove"} */
static esp_err_t api_blocklist_post_handler(httpd_req_t *req)
{
    if (!check_auth(req)) {
        return ESP_OK;
    }

    char body[160];
    int total = req->content_len;
    if (total <= 0 || total >= (int)sizeof(body)) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Bad request body");
        return ESP_FAIL;
    }
    int received = httpd_req_recv(req, body, total);
    if (received <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Could not read body");
        return ESP_FAIL;
    }
    body[received] = '\0';

    cJSON *root = cJSON_Parse(body);
    cJSON *domain = root ? cJSON_GetObjectItem(root, "domain") : NULL;
    cJSON *action = root ? cJSON_GetObjectItem(root, "action") : NULL;
    if (!cJSON_IsString(domain) || !cJSON_IsString(action)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Need string domain + action");
        return ESP_FAIL;
    }

    bool ok;
    if (strcmp(action->valuestring, "remove") == 0) {
        ok = blocklist_manual_remove(domain->valuestring);
    } else {
        ok = blocklist_manual_add(domain->valuestring);
    }
    cJSON_Delete(root);

    if (!ok) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Operation failed (full, or domain not found)");
        return ESP_FAIL;
    }

    char *json = blocklist_manual_to_json();
    httpd_resp_set_type(req, "application/json");
    esp_err_t err = httpd_resp_send(req, json ? json : "[]", HTTPD_RESP_USE_STRLEN);
    cJSON_free(json);
    return err;
}

static esp_err_t api_schedules_get_handler(httpd_req_t *req)
{
    if (!check_auth(req)) {
        return ESP_OK;
    }
    char *json = schedule_to_json();
    if (json == NULL) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "application/json");
    esp_err_t err = httpd_resp_send(req, json, HTTPD_RESP_USE_STRLEN);
    cJSON_free(json);
    return err;
}

/* POST /api/schedules:
 *   add:    {"domain":"x.com","start":1260,"end":420}
 *   remove: {"domain":"x.com","action":"remove"}
 * start/end are minutes since local midnight (0-1439). */
static esp_err_t api_schedules_post_handler(httpd_req_t *req)
{
    if (!check_auth(req)) {
        return ESP_OK;
    }

    char body[200];
    int total = req->content_len;
    if (total <= 0 || total >= (int)sizeof(body)) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Bad request body");
        return ESP_FAIL;
    }
    int received = httpd_req_recv(req, body, total);
    if (received <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Could not read body");
        return ESP_FAIL;
    }
    body[received] = '\0';

    cJSON *root = cJSON_Parse(body);
    cJSON *domain = root ? cJSON_GetObjectItem(root, "domain") : NULL;
    if (!cJSON_IsString(domain)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Need string domain");
        return ESP_FAIL;
    }

    cJSON *action = cJSON_GetObjectItem(root, "action");
    bool ok;
    if (cJSON_IsString(action) && strcmp(action->valuestring, "remove") == 0) {
        ok = schedule_remove(domain->valuestring);
    } else {
        cJSON *start = cJSON_GetObjectItem(root, "start");
        cJSON *end = cJSON_GetObjectItem(root, "end");
        if (!cJSON_IsNumber(start) || !cJSON_IsNumber(end)) {
            cJSON_Delete(root);
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Need numeric start + end");
            return ESP_FAIL;
        }
        ok = schedule_add(domain->valuestring, start->valueint, end->valueint);
    }
    cJSON_Delete(root);

    if (!ok) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Operation failed (full, bad time, or not found)");
        return ESP_FAIL;
    }

    char *json = schedule_to_json();
    httpd_resp_set_type(req, "application/json");
    esp_err_t err = httpd_resp_send(req, json ? json : "[]", HTTPD_RESP_USE_STRLEN);
    cJSON_free(json);
    return err;
}

void web_server_start(void)
{
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    httpd_handle_t server = NULL;

#if CONFIG_POCKETDNS_WEB_AUTH_ENABLE
    build_expected_auth();
#endif

    if (httpd_start(&server, &config) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start HTTP server");
        return;
    }

    httpd_uri_t root_uri = {
        .uri = "/",
        .method = HTTP_GET,
        .handler = root_get_handler,
    };
    httpd_register_uri_handler(server, &root_uri);

    httpd_uri_t stats_uri = {
        .uri = "/api/stats",
        .method = HTTP_GET,
        .handler = api_stats_get_handler,
    };
    httpd_register_uri_handler(server, &stats_uri);

    httpd_uri_t whitelist_get_uri = {
        .uri = "/api/whitelist",
        .method = HTTP_GET,
        .handler = api_whitelist_get_handler,
    };
    httpd_register_uri_handler(server, &whitelist_get_uri);

    httpd_uri_t whitelist_post_uri = {
        .uri = "/api/whitelist",
        .method = HTTP_POST,
        .handler = api_whitelist_post_handler,
    };
    httpd_register_uri_handler(server, &whitelist_post_uri);

    httpd_uri_t blocklist_get_uri = {
        .uri = "/api/blocklist",
        .method = HTTP_GET,
        .handler = api_blocklist_get_handler,
    };
    httpd_register_uri_handler(server, &blocklist_get_uri);

    httpd_uri_t blocklist_post_uri = {
        .uri = "/api/blocklist",
        .method = HTTP_POST,
        .handler = api_blocklist_post_handler,
    };
    httpd_register_uri_handler(server, &blocklist_post_uri);

    httpd_uri_t schedules_get_uri = {
        .uri = "/api/schedules",
        .method = HTTP_GET,
        .handler = api_schedules_get_handler,
    };
    httpd_register_uri_handler(server, &schedules_get_uri);

    httpd_uri_t schedules_post_uri = {
        .uri = "/api/schedules",
        .method = HTTP_POST,
        .handler = api_schedules_post_handler,
    };
    httpd_register_uri_handler(server, &schedules_post_uri);

    ESP_LOGI(TAG, "HTTP server started - dashboard at http://<device-ip>/");
}
