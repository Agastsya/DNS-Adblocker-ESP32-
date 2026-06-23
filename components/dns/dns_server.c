#include "dns_server.h"
#include "dns_parser.h"
#include "dns_forwarder.h"
#include "blocklist.h"
#include "dns_cache.h"
#include "dns_stats.h"
#include "dns_log.h"
#include "schedule.h"

#include <errno.h>
#include <stdbool.h>
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
 *
 * A separate task also serves DNS over TCP (port 53) for the clients and
 * resolvers that fall back to it (e.g. when a UDP answer is truncated).
 * ------------------------------------------------------------------------ */
#define DNS_WORKER_COUNT 4
#define DNS_QUEUE_DEPTH  16
#define DNS_TCP_TIMEOUT  5   /* seconds to wait on a stalled TCP client */

typedef struct {
    int                len;
    struct sockaddr_in src;
    socklen_t          src_len;
    uint8_t            data[DNS_RX_BUF_LEN];
} dns_work_t;

static int              s_sock = -1;      /* shared UDP socket */
static QueueHandle_t    s_work_queue = NULL;

/* --------------------------------------------------------------------------
 * resolve_query(): the heart of the server, transport-agnostic. Parses a raw
 * DNS query, decides blocked / cached / forwarded, and writes the bytes to
 * send back into resp[]. Returns the response length, or 0 if no reply
 * should be sent. client_ip is the client's address in network byte order,
 * used for the live log. Shared by both the UDP and TCP paths.
 * ------------------------------------------------------------------------ */
static int resolve_query(const uint8_t *req, int req_len, uint32_t client_ip,
                         uint8_t *resp, int resp_cap)
{
    dns_query_t query;
    if (!dns_parse_query(req, req_len, &query) || query.qdcount == 0) {
        struct in_addr a = { .s_addr = client_ip };
        ESP_LOGW(TAG, "Received %d bytes from %s - not a parseable DNS query",
                 req_len, inet_ntoa(a));
        return 0;
    }

    struct in_addr ca = { .s_addr = client_ip };
    dns_stats_record_query();
    ESP_LOGI(TAG, "Query id=0x%04x from %s -> %s (%s)%s",
             query.id, inet_ntoa(ca), query.qname,
             dns_qtype_name(query.qtype), query.rd ? " rd" : "");

    if (blocklist_is_blocked(query.qname) || schedule_is_blocked_now(query.qname)) {
        dns_stats_record_blocked();
        dns_log_record(query.qname, client_ip, DNS_LOG_BLOCKED);
        int out_len = 0;
        if (req_len <= resp_cap) {
            memcpy(resp, req, req_len);
            dns_make_nxdomain_response(resp, req_len);
            out_len = req_len;
        }
        ESP_LOGI(TAG, "Blocked %s", query.qname);
        dns_stats_checkpoint();
        return out_len;
    }

    int out_len = dns_cache_lookup(query.qname, query.qtype, query.id, resp, resp_cap);
    if (out_len > 0) {
        dns_stats_record_cache_hit();
        dns_log_record(query.qname, client_ip, DNS_LOG_CACHED);
        dns_stats_checkpoint();
        return out_len;
    }

    out_len = dns_forward_query(req, req_len, resp, resp_cap);
    if (out_len > 0) {
        dns_stats_record_forwarded();
        dns_log_record(query.qname, client_ip, DNS_LOG_ALLOWED);
        dns_cache_store(query.qname, query.qtype, resp, out_len);
    } else {
        dns_stats_record_forward_failure();
        ESP_LOGW(TAG, "Upstream forward for %s failed - no reply sent", query.qname);
        out_len = 0;
    }
    dns_stats_checkpoint();
    return out_len;
}

/* ---- UDP path ---------------------------------------------------------- */

/* Worker: resolve one queued UDP query and reply on the shared socket. The
 * slow upstream forward here never blocks the listener that fills the queue. */
static void handle_udp(const dns_work_t *work)
{
    uint8_t resp[DNS_RX_BUF_LEN];
    int n = resolve_query(work->data, work->len, work->src.sin_addr.s_addr,
                          resp, sizeof(resp));
    if (n > 0) {
        sendto(s_sock, resp, n, 0,
               (const struct sockaddr *)&work->src, work->src_len);
    }
}

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
            handle_udp(work);
        }
    }
}

/* Bind UDP :53 and do nothing but receive packets and hand them to the
 * worker queue, so the socket is drained as fast as datagrams arrive. */
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

    ESP_LOGI(TAG, "DNS listener up - bound to 0.0.0.0:%d UDP (%d workers)", DNS_PORT, DNS_WORKER_COUNT);

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

/* ---- TCP path ---------------------------------------------------------- */

/* Read exactly len bytes (TCP can deliver a frame in pieces). Returns the
 * number actually read; caller compares it to len. */
static int recv_all(int fd, uint8_t *buf, int len)
{
    int got = 0;
    while (got < len) {
        int r = recv(fd, buf + got, len - got, 0);
        if (r <= 0) {
            break;
        }
        got += r;
    }
    return got;
}

static bool send_all(int fd, const uint8_t *buf, int len)
{
    int sent = 0;
    while (sent < len) {
        int w = send(fd, buf + sent, len - sent, 0);
        if (w <= 0) {
            return false;
        }
        sent += w;
    }
    return true;
}

/* Serve one TCP DNS query: 2-byte big-endian length prefix, then the
 * message; reply framed the same way. */
static void dns_tcp_serve(int conn, uint32_t client_ip)
{
    struct timeval tv = { .tv_sec = DNS_TCP_TIMEOUT, .tv_usec = 0 };
    setsockopt(conn, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint8_t lenbuf[2];
    if (recv_all(conn, lenbuf, 2) != 2) {
        return;
    }
    int qlen = (lenbuf[0] << 8) | lenbuf[1];
    if (qlen <= 0 || qlen > DNS_RX_BUF_LEN) {
        return;
    }

    uint8_t req[DNS_RX_BUF_LEN];
    if (recv_all(conn, req, qlen) != qlen) {
        return;
    }

    uint8_t resp[DNS_RX_BUF_LEN];
    int n = resolve_query(req, qlen, client_ip, resp, sizeof(resp));
    if (n > 0) {
        uint8_t framed[2 + DNS_RX_BUF_LEN];
        framed[0] = (n >> 8) & 0xFF;
        framed[1] = n & 0xFF;
        memcpy(framed + 2, resp, n);
        send_all(conn, framed, n + 2);
    }
}

/* TCP DNS is a fallback transport with low volume, so one task handles
 * connections serially - it never bottlenecks the UDP fast path, which
 * runs on its own listener + worker pool. */
static void dns_tcp_listener_task(void *pvParameters)
{
    int lsock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (lsock < 0) {
        ESP_LOGE(TAG, "Could not create TCP socket: errno %d", errno);
        vTaskDelete(NULL);
        return;
    }
    int opt = 1;
    setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port = htons(DNS_PORT),
    };
    if (bind(lsock, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        listen(lsock, 4) < 0) {
        ESP_LOGE(TAG, "Could not bind/listen TCP port %d: errno %d", DNS_PORT, errno);
        close(lsock);
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "DNS TCP listener up - bound to 0.0.0.0:%d TCP", DNS_PORT);

    while (1) {
        struct sockaddr_in cli;
        socklen_t cl = sizeof(cli);
        int conn = accept(lsock, (struct sockaddr *)&cli, &cl);
        if (conn < 0) {
            continue;
        }
        dns_tcp_serve(conn, cli.sin_addr.s_addr);
        close(conn);
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
    xTaskCreate(dns_tcp_listener_task, "dns_tcp", 4096, NULL, 5, NULL);
}
