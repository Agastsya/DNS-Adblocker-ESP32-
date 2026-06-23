#include "dns_server.h"
#include "dns_parser.h"
#include "dns_forwarder.h"
#include "blocklist.h"
#include "dns_cache.h"
#include "dns_stats.h"
#include "dns_log.h"
#include "schedule.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"

static const char *TAG = "dns_server";

#define DNS_PORT       53
#define DNS_RX_BUF_LEN 512  /* classic non-EDNS UDP DNS message ceiling */

/* --------------------------------------------------------------------------
 * Concurrency model
 *
 * A browser loading one modern web page fires dozens of DNS lookups almost
 * simultaneously (CDNs, trackers, fonts, APIs). Forwarding a single query
 * upstream blocks for up to a couple of seconds waiting on the reply, so a
 * server that handles queries one-at-a-time stalls the entire network behind
 * whichever lookup is currently in flight - the symptom is "Google loads but
 * everything else just spins".
 *
 * So we split the work: ONE listener task does nothing but drain the UDP
 * socket as fast as packets arrive and hand each one to a queue; a POOL of
 * worker tasks pull from that queue and do the slow part (blocklist check,
 * cache, upstream forward, reply). With N workers, up to N slow upstream
 * lookups can be in flight at once while the listener keeps the socket
 * empty, so bursts no longer overflow the kernel's small UDP mailbox.
 * ------------------------------------------------------------------------ */
#define DNS_WORKER_COUNT 4
#define DNS_QUEUE_DEPTH  16

typedef struct {
    int                len;
    struct sockaddr_in src;
    socklen_t          src_len;
    uint8_t            data[DNS_RX_BUF_LEN];
} dns_work_t;

static int              s_sock = -1;
static QueueHandle_t    s_work_queue = NULL;

/* Resolve one query and send the reply on the shared socket. Runs on a
 * worker task, so the slow upstream forward here never blocks the listener. */
static void handle_query(const dns_work_t *work)
{
    dns_query_t query;
    if (!dns_parse_query(work->data, work->len, &query) || query.qdcount == 0) {
        ESP_LOGW(TAG, "Received %d bytes from %s:%d - not a parseable DNS query",
                 work->len, inet_ntoa(work->src.sin_addr), ntohs(work->src.sin_port));
        return;
    }

    dns_stats_record_query();
    ESP_LOGI(TAG, "Query id=0x%04x from %s:%d -> %s (%s)%s",
             query.id, inet_ntoa(work->src.sin_addr), ntohs(work->src.sin_port),
             query.qname, dns_qtype_name(query.qtype), query.rd ? " rd" : "");

    const struct sockaddr *dst = (const struct sockaddr *)&work->src;
    socklen_t dst_len = work->src_len;

    uint32_t client_ip = work->src.sin_addr.s_addr;

    if (blocklist_is_blocked(query.qname) || schedule_is_blocked_now(query.qname)) {
        dns_stats_record_blocked();
        dns_log_record(query.qname, client_ip, DNS_LOG_BLOCKED);
        uint8_t resp[DNS_RX_BUF_LEN];
        memcpy(resp, work->data, work->len);
        dns_make_nxdomain_response(resp, work->len);
        sendto(s_sock, resp, work->len, 0, dst, dst_len);
        ESP_LOGI(TAG, "Blocked %s - sent NXDOMAIN to %s:%d",
                 query.qname, inet_ntoa(work->src.sin_addr), ntohs(work->src.sin_port));
        dns_stats_checkpoint();
        return;
    }

    uint8_t response_buffer[DNS_RX_BUF_LEN];
    int response_len = dns_cache_lookup(query.qname, query.qtype, query.id,
                                        response_buffer, sizeof(response_buffer));
    if (response_len > 0) {
        dns_stats_record_cache_hit();
        dns_log_record(query.qname, client_ip, DNS_LOG_CACHED);
        sendto(s_sock, response_buffer, response_len, 0, dst, dst_len);
        ESP_LOGI(TAG, "Cache hit for %s - served %d bytes to %s:%d",
                 query.qname, response_len,
                 inet_ntoa(work->src.sin_addr), ntohs(work->src.sin_port));
        dns_stats_checkpoint();
        return;
    }

    response_len = dns_forward_query(work->data, work->len,
                                     response_buffer, sizeof(response_buffer));
    if (response_len > 0) {
        dns_stats_record_forwarded();
        dns_log_record(query.qname, client_ip, DNS_LOG_ALLOWED);
        dns_cache_store(query.qname, query.qtype, response_buffer, response_len);
        sendto(s_sock, response_buffer, response_len, 0, dst, dst_len);
        ESP_LOGI(TAG, "Forwarded %d-byte reply for %s to %s:%d",
                 response_len, query.qname,
                 inet_ntoa(work->src.sin_addr), ntohs(work->src.sin_port));
    } else {
        dns_stats_record_forward_failure();
        ESP_LOGW(TAG, "Upstream forward for %s failed - no reply sent to client", query.qname);
    }
    dns_stats_checkpoint();
}

/* Worker: pull queued packets and resolve them. */
static void dns_worker_task(void *pvParameters)
{
    dns_work_t *work = malloc(sizeof(dns_work_t));
    if (work == NULL) {
        ESP_LOGE(TAG, "Worker out of memory");
        vTaskDelete(NULL);
        return;
    }
    while (1) {
        if (xQueueReceive(s_work_queue, work, portMAX_DELAY) == pdTRUE) {
            handle_query(work);
        }
    }
}

/* --------------------------------------------------------------------------
 * dns_listener_task(): bind a UDP socket on :53 and do nothing but receive
 * packets and hand them to the worker queue, so the socket is drained as
 * fast as datagrams arrive. The actual resolving happens on the workers.
 * ------------------------------------------------------------------------ */
static void dns_listener_task(void *pvParameters)
{
    s_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (s_sock < 0) {
        ESP_LOGE(TAG, "Could not create UDP socket: errno %d", errno);
        vTaskDelete(NULL);
        return;
    }

    struct sockaddr_in listen_addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port = htons(DNS_PORT),
    };

    if (bind(s_sock, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0) {
        ESP_LOGE(TAG, "Could not bind UDP socket to port %d: errno %d", DNS_PORT, errno);
        close(s_sock);
        s_sock = -1;
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "DNS listener up - bound to 0.0.0.0:%d (%d workers)", DNS_PORT, DNS_WORKER_COUNT);

    dns_work_t work;
    while (1) {
        work.src_len = sizeof(work.src);
        int len = recvfrom(s_sock, work.data, sizeof(work.data), 0,
                           (struct sockaddr *)&work.src, &work.src_len);
        if (len < 0) {
            ESP_LOGE(TAG, "recvfrom failed: errno %d", errno);
            continue;
        }
        work.len = len;
        /* Don't block the receive loop if every worker is busy - drop the
         * packet instead. DNS clients retry, and a dropped packet is far
         * cheaper than stalling the socket and overflowing the kernel buffer. */
        if (xQueueSend(s_work_queue, &work, 0) != pdTRUE) {
            ESP_LOGW(TAG, "Work queue full - dropped a query (workers saturated)");
        }
    }
}

void dns_server_start(void)
{
    blocklist_init();
    blocklist_start_cloud_sync();
    dns_forwarder_init();
    dns_cache_init();
    dns_log_init();
    dns_stats_init();
    schedule_init();
    schedule_start_time_sync();

    s_work_queue = xQueueCreate(DNS_QUEUE_DEPTH, sizeof(dns_work_t));
    if (s_work_queue == NULL) {
        ESP_LOGE(TAG, "Could not create DNS work queue");
        return;
    }
    for (int i = 0; i < DNS_WORKER_COUNT; i++) {
        xTaskCreate(dns_worker_task, "dns_worker", 4096, NULL, 5, NULL);
    }
    xTaskCreate(dns_listener_task, "dns_listener", 4096, NULL, 5, NULL);
}
