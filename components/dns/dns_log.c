#include "dns_log.h"

#include <stdio.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_timer.h"
#include "cJSON.h"

#define LOG_CAPACITY   60      /* recent queries kept for the dashboard */
#define LOG_NAME_LEN   80

typedef struct {
    int64_t  ts_us;            /* esp_timer_get_time() when recorded */
    uint32_t ip;               /* client address, network byte order */
    uint8_t  action;           /* dns_log_action_t */
    char     name[LOG_NAME_LEN];
} log_entry_t;

static log_entry_t       s_log[LOG_CAPACITY];
static int               s_head = 0;   /* next slot to write */
static int               s_count = 0;  /* number of valid entries (<= capacity) */
static SemaphoreHandle_t s_lock = NULL;

void dns_log_init(void)
{
    if (s_lock == NULL) {
        s_lock = xSemaphoreCreateMutex();
    }
}

void dns_log_record(const char *qname, uint32_t client_ip, dns_log_action_t action)
{
    if (s_lock == NULL) {
        return;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    log_entry_t *e = &s_log[s_head];
    e->ts_us  = esp_timer_get_time();
    e->ip     = client_ip;
    e->action = (uint8_t)action;
    strlcpy(e->name, qname ? qname : "", sizeof(e->name));
    s_head = (s_head + 1) % LOG_CAPACITY;
    if (s_count < LOG_CAPACITY) {
        s_count++;
    }
    xSemaphoreGive(s_lock);
}

char *dns_log_to_json(void)
{
    cJSON *arr = cJSON_CreateArray();
    if (arr == NULL) {
        return NULL;
    }

    if (s_lock) {
        xSemaphoreTake(s_lock, portMAX_DELAY);
    }
    int64_t now = esp_timer_get_time();
    for (int i = 0; i < s_count; i++) {
        /* walk newest -> oldest */
        int idx = (s_head - 1 - i + 2 * LOG_CAPACITY) % LOG_CAPACITY;
        log_entry_t *e = &s_log[idx];

        char ipbuf[16];
        const uint8_t *b = (const uint8_t *)&e->ip;
        snprintf(ipbuf, sizeof(ipbuf), "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);

        cJSON *o = cJSON_CreateObject();
        cJSON_AddStringToObject(o, "name", e->name);
        cJSON_AddStringToObject(o, "ip", ipbuf);
        cJSON_AddNumberToObject(o, "ago", (double)((now - e->ts_us) / 1000000));
        cJSON_AddNumberToObject(o, "act", e->action);
        cJSON_AddItemToArray(arr, o);
    }
    if (s_lock) {
        xSemaphoreGive(s_lock);
    }

    char *json = cJSON_PrintUnformatted(arr);
    cJSON_Delete(arr);
    return json;
}
