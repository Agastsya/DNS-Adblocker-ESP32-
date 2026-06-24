#include "schedule.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "esp_log.h"
#include "esp_netif_sntp.h"
#include "cJSON.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char *TAG = "schedule";

/* Guards s_schedules/s_schedule_count: every DNS worker reads this on
 * every query while the dashboard's REST API can add/remove a schedule
 * from a different task at any moment. */
static SemaphoreHandle_t s_sched_lock = NULL;

#define SCHEDULE_MAX         16
#define SCHEDULE_MAX_DOMAIN  128
#define SCHEDULE_PATH        "/littlefs/schedules.json"
#define TIMEZONE_PATH        "/littlefs/timezone.txt"
#define TZ_MAX               64

static char s_timezone[TZ_MAX] = CONFIG_POCKETDNS_TIMEZONE;

typedef struct {
    char domain[SCHEDULE_MAX_DOMAIN];
    int  start_min;   /* minutes since local midnight, inclusive */
    int  end_min;     /* minutes since local midnight, exclusive */
} schedule_entry_t;

static schedule_entry_t s_schedules[SCHEDULE_MAX];
static size_t s_schedule_count = 0;

/* True if `domain` is exactly `entry` or a subdomain of it - same rule as
 * the blocklist, so a schedule on "youtube.com" also covers
 * "www.youtube.com". */
static bool domain_matches(const char *domain, const char *entry)
{
    size_t dl = strlen(domain), el = strlen(entry);
    if (dl < el) {
        return false;
    }
    if (strcasecmp(domain + (dl - el), entry) != 0) {
        return false;
    }
    return dl == el || domain[dl - el - 1] == '.';
}

/* Is now_min inside [start, end)? A window with start > end wraps past
 * midnight (e.g. 21:00-07:00 blocks 21:00..23:59 and 00:00..06:59). */
static bool in_window(int now_min, int start_min, int end_min)
{
    if (start_min <= end_min) {
        return now_min >= start_min && now_min < end_min;
    }
    return now_min >= start_min || now_min < end_min;
}

bool schedule_domain_blocked_at(const char *domain, int now_min)
{
    for (size_t i = 0; i < s_schedule_count; i++) {
        if (domain_matches(domain, s_schedules[i].domain) &&
            in_window(now_min, s_schedules[i].start_min, s_schedules[i].end_min)) {
            return true;
        }
    }
    return false;
}

bool schedule_is_blocked_now(const char *domain)
{
    if (s_schedule_count == 0) {
        return false;
    }
    time_t now = time(NULL);
    struct tm tm_now;
    localtime_r(&now, &tm_now);

    /* time() before SNTP sync is near the epoch (year 1970); don't enforce
     * schedules until the clock is actually set, or every window would be
     * evaluated against a meaningless time. */
    if (tm_now.tm_year < (2020 - 1900)) {
        return false;
    }

    int now_min = tm_now.tm_hour * 60 + tm_now.tm_min;
    if (s_sched_lock) {
        xSemaphoreTake(s_sched_lock, portMAX_DELAY);
    }
    bool blocked = schedule_domain_blocked_at(domain, now_min);
    if (s_sched_lock) {
        xSemaphoreGive(s_sched_lock);
    }
    return blocked;
}

static void schedule_save(void)
{
    cJSON *arr = cJSON_CreateArray();
    if (arr == NULL) {
        return;
    }
    for (size_t i = 0; i < s_schedule_count; i++) {
        cJSON *o = cJSON_CreateObject();
        cJSON_AddStringToObject(o, "domain", s_schedules[i].domain);
        cJSON_AddNumberToObject(o, "start", s_schedules[i].start_min);
        cJSON_AddNumberToObject(o, "end", s_schedules[i].end_min);
        cJSON_AddItemToArray(arr, o);
    }
    char *json = cJSON_PrintUnformatted(arr);
    if (json != NULL) {
        FILE *f = fopen(SCHEDULE_PATH, "w");
        if (f != NULL) {
            fputs(json, f);
            fclose(f);
        }
        cJSON_free(json);
    }
    cJSON_Delete(arr);
}

esp_err_t schedule_init(void)
{
    if (s_sched_lock == NULL) {
        s_sched_lock = xSemaphoreCreateMutex();
    }
    s_schedule_count = 0;

    FILE *f = fopen(SCHEDULE_PATH, "r");
    if (f == NULL) {
        ESP_LOGI(TAG, "No saved schedules");
        return ESP_OK;
    }
    /* Heap, not stack - schedule_init() runs on the 8KB main task. */
    const size_t buf_sz = SCHEDULE_MAX * (SCHEDULE_MAX_DOMAIN + 64);
    char *buf = malloc(buf_sz);
    if (buf == NULL) {
        fclose(f);
        return ESP_OK;
    }
    size_t n = fread(buf, 1, buf_sz - 1, f);
    fclose(f);
    buf[n] = '\0';

    cJSON *arr = cJSON_Parse(buf);
    free(buf);
    if (arr == NULL || !cJSON_IsArray(arr)) {
        cJSON_Delete(arr);
        return ESP_OK;
    }
    int count = cJSON_GetArraySize(arr);
    for (int i = 0; i < count && s_schedule_count < SCHEDULE_MAX; i++) {
        cJSON *o = cJSON_GetArrayItem(arr, i);
        cJSON *domain = cJSON_GetObjectItem(o, "domain");
        cJSON *start = cJSON_GetObjectItem(o, "start");
        cJSON *end = cJSON_GetObjectItem(o, "end");
        if (cJSON_IsString(domain) && cJSON_IsNumber(start) && cJSON_IsNumber(end) &&
            strlen(domain->valuestring) < SCHEDULE_MAX_DOMAIN) {
            schedule_entry_t *e = &s_schedules[s_schedule_count++];
            strcpy(e->domain, domain->valuestring);
            e->start_min = start->valueint;
            e->end_min = end->valueint;
        }
    }
    cJSON_Delete(arr);
    ESP_LOGI(TAG, "Loaded %u schedule(s)", (unsigned)s_schedule_count);
    return ESP_OK;
}

void schedule_start_time_sync(void)
{
    /* Load a saved timezone from flash if present, else keep the build-time
     * default. The TZ is what makes schedule windows use *local* time - get
     * it wrong and a "9pm" rule fires at the wrong hour, which looks exactly
     * like "parental controls aren't working". */
    FILE *tf = fopen(TIMEZONE_PATH, "r");
    if (tf != NULL) {
        if (fgets(s_timezone, sizeof(s_timezone), tf) != NULL) {
            s_timezone[strcspn(s_timezone, "\r\n")] = '\0';
        }
        fclose(tf);
    }
    if (s_timezone[0] == '\0') {
        strlcpy(s_timezone, CONFIG_POCKETDNS_TIMEZONE, sizeof(s_timezone));
    }

    setenv("TZ", s_timezone, 1);
    tzset();

    esp_sntp_config_t config = ESP_NETIF_SNTP_DEFAULT_CONFIG("pool.ntp.org");
    esp_netif_sntp_init(&config);
    ESP_LOGI(TAG, "SNTP time sync started (pool.ntp.org), TZ=%s", s_timezone);
}

void schedule_get_timezone(char *out, size_t out_len)
{
    strlcpy(out, s_timezone, out_len);
}

bool schedule_set_timezone(const char *tz)
{
    if (tz == NULL || tz[0] == '\0' || strlen(tz) >= TZ_MAX) {
        return false;
    }
    strlcpy(s_timezone, tz, sizeof(s_timezone));
    setenv("TZ", s_timezone, 1);
    tzset();

    FILE *f = fopen(TIMEZONE_PATH, "w");
    if (f != NULL) {
        fputs(s_timezone, f);
        fclose(f);
    }
    ESP_LOGI(TAG, "Timezone set to %s", s_timezone);
    return true;
}

/* Current local time as "HH:MM" plus whether the clock is SNTP-synced, for
 * the dashboard to show (so users can confirm the timezone is right). */
void schedule_get_clock(char *out, size_t out_len, bool *synced)
{
    time_t now = time(NULL);
    struct tm tm_now;
    localtime_r(&now, &tm_now);
    bool ok = tm_now.tm_year >= (2020 - 1900);
    if (synced) *synced = ok;
    if (ok) {
        snprintf(out, out_len, "%02d:%02d", tm_now.tm_hour, tm_now.tm_min);
    } else {
        strlcpy(out, "--:--", out_len);
    }
}

bool schedule_add(const char *domain, int start_min, int end_min)
{
    if (domain == NULL || domain[0] == '\0' || strlen(domain) >= SCHEDULE_MAX_DOMAIN) {
        return false;
    }
    if (start_min < 0 || start_min > 1439 || end_min < 0 || end_min > 1439) {
        return false;
    }
    xSemaphoreTake(s_sched_lock, portMAX_DELAY);
    /* Replace an existing schedule for the same domain rather than
     * stacking duplicates. */
    for (size_t i = 0; i < s_schedule_count; i++) {
        if (strcasecmp(s_schedules[i].domain, domain) == 0) {
            s_schedules[i].start_min = start_min;
            s_schedules[i].end_min = end_min;
            schedule_save();
            xSemaphoreGive(s_sched_lock);
            return true;
        }
    }
    if (s_schedule_count >= SCHEDULE_MAX) {
        xSemaphoreGive(s_sched_lock);
        return false;
    }
    schedule_entry_t *e = &s_schedules[s_schedule_count++];
    strcpy(e->domain, domain);
    e->start_min = start_min;
    e->end_min = end_min;
    schedule_save();
    xSemaphoreGive(s_sched_lock);
    ESP_LOGI(TAG, "Scheduled %s blocked %02d:%02d-%02d:%02d",
             domain, start_min / 60, start_min % 60, end_min / 60, end_min % 60);
    return true;
}

bool schedule_remove(const char *domain)
{
    xSemaphoreTake(s_sched_lock, portMAX_DELAY);
    for (size_t i = 0; i < s_schedule_count; i++) {
        if (strcasecmp(s_schedules[i].domain, domain) == 0) {
            if (i != s_schedule_count - 1) {
                s_schedules[i] = s_schedules[s_schedule_count - 1];
            }
            s_schedule_count--;
            schedule_save();
            xSemaphoreGive(s_sched_lock);
            return true;
        }
    }
    xSemaphoreGive(s_sched_lock);
    return false;
}

char *schedule_to_json(void)
{
    cJSON *arr = cJSON_CreateArray();
    if (arr == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < s_schedule_count; i++) {
        cJSON *o = cJSON_CreateObject();
        cJSON_AddStringToObject(o, "domain", s_schedules[i].domain);
        cJSON_AddNumberToObject(o, "start", s_schedules[i].start_min);
        cJSON_AddNumberToObject(o, "end", s_schedules[i].end_min);
        cJSON_AddItemToArray(arr, o);
    }
    char *json = cJSON_PrintUnformatted(arr);
    cJSON_Delete(arr);
    return json;
}
