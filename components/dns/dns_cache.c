#include "dns_cache.h"

#include <stdbool.h>
#include <string.h>
#include <strings.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char *TAG = "dns_cache";

#define DNS_CACHE_SIZE          32
#define DNS_CACHE_MAX_RESPONSE  512
#define DNS_CACHE_MAX_NAME      255

/* Guards s_cache/s_next_evict: the DNS worker pool reads and writes the
 * cache from several tasks at once. */
static SemaphoreHandle_t s_cache_lock = NULL;

void dns_cache_init(void)
{
    if (s_cache_lock == NULL) {
        s_cache_lock = xSemaphoreCreateMutex();
    }
}

typedef struct {
    bool     in_use;
    char     qname[DNS_CACHE_MAX_NAME + 1];
    uint16_t qtype;
    uint8_t  response[DNS_CACHE_MAX_RESPONSE];
    int      response_len;
    int64_t  expires_at_us;
} dns_cache_entry_t;

static dns_cache_entry_t s_cache[DNS_CACHE_SIZE];
static int s_next_evict = 0;

/* Advance past a (possibly compressed) NAME field without decoding it -
 * we only need to know where it ends, not what it says. A pointer
 * (top two bits of the byte set) is always exactly 2 bytes and is the
 * last element of a name, so it ends the field immediately. */
static int skip_name(const uint8_t *buf, int len, int pos)
{
    while (pos < len) {
        uint8_t b = buf[pos];
        if (b == 0) {
            return pos + 1;
        }
        if ((b & 0xC0) == 0xC0) {
            return pos + 2;
        }
        if ((b & 0xC0) != 0) {
            return -1;  /* reserved label type we don't understand */
        }
        pos += 1 + b;
        if (pos > len) {
            return -1;
        }
    }
    return -1;
}

/* Scan the answer section of a raw DNS response and return the minimum
 * TTL across all answer records, or -1 if there are none / it's
 * malformed. We cache for the shortest-lived record, same as a real
 * resolver would. */
static int32_t extract_min_ttl(const uint8_t *buf, int len)
{
    if (len < 12) {
        return -1;
    }
    uint16_t ancount = (buf[6] << 8) | buf[7];
    if (ancount == 0) {
        return -1;
    }

    int pos = skip_name(buf, len, 12);
    if (pos < 0 || pos + 4 > len) {
        return -1;
    }
    pos += 4;  /* QTYPE + QCLASS */

    int32_t min_ttl = -1;
    for (int i = 0; i < ancount; i++) {
        pos = skip_name(buf, len, pos);
        if (pos < 0 || pos + 10 > len) {
            break;  /* malformed past this point - use whatever we already found */
        }
        pos += 4;  /* TYPE + CLASS */

        uint32_t ttl = ((uint32_t)buf[pos] << 24) | ((uint32_t)buf[pos + 1] << 16) |
                       ((uint32_t)buf[pos + 2] << 8) | buf[pos + 3];
        pos += 4;

        uint16_t rdlength = (buf[pos] << 8) | buf[pos + 1];
        pos += 2 + rdlength;
        if (pos > len) {
            break;
        }

        if (min_ttl < 0 || (int32_t)ttl < min_ttl) {
            min_ttl = (int32_t)ttl;
        }
    }
    return min_ttl;
}

int dns_cache_lookup(const char *qname, uint16_t qtype, uint16_t query_id,
                      uint8_t *out_response, int out_buf_len)
{
    int64_t now = esp_timer_get_time();
    int result = -1;

    if (s_cache_lock) xSemaphoreTake(s_cache_lock, portMAX_DELAY);
    for (int i = 0; i < DNS_CACHE_SIZE; i++) {
        dns_cache_entry_t *e = &s_cache[i];
        if (!e->in_use || e->qtype != qtype) {
            continue;
        }
        if (strcasecmp(e->qname, qname) != 0) {
            continue;
        }
        if (now >= e->expires_at_us) {
            e->in_use = false;  /* expired - free the slot while we're here */
            continue;
        }
        if (e->response_len > out_buf_len) {
            break;
        }
        memcpy(out_response, e->response, e->response_len);
        out_response[0] = query_id >> 8;
        out_response[1] = query_id & 0xFF;
        result = e->response_len;
        break;
    }
    if (s_cache_lock) xSemaphoreGive(s_cache_lock);
    return result;
}

void dns_cache_store(const char *qname, uint16_t qtype,
                      const uint8_t *response, int response_len)
{
    if (response_len <= 0 || response_len > DNS_CACHE_MAX_RESPONSE) {
        return;
    }
    if (strlen(qname) > DNS_CACHE_MAX_NAME) {
        return;
    }

    int32_t ttl = extract_min_ttl(response, response_len);
    if (ttl <= 0) {
        return;  /* nothing worth caching (no answers, or a 0-TTL record) */
    }

    if (s_cache_lock) xSemaphoreTake(s_cache_lock, portMAX_DELAY);
    dns_cache_entry_t *e = &s_cache[s_next_evict];
    s_next_evict = (s_next_evict + 1) % DNS_CACHE_SIZE;

    strncpy(e->qname, qname, DNS_CACHE_MAX_NAME);
    e->qname[DNS_CACHE_MAX_NAME] = '\0';
    e->qtype = qtype;
    memcpy(e->response, response, response_len);
    e->response_len = response_len;
    e->expires_at_us = esp_timer_get_time() + ((int64_t)ttl * 1000000);
    e->in_use = true;
    if (s_cache_lock) xSemaphoreGive(s_cache_lock);

    ESP_LOGI(TAG, "Cached %s (%u) for %ld s", qname, qtype, (long)ttl);
}
