#include "dns_server.h"
#include "dns_parser.h"
#include "dns_forwarder.h"
#include "blocklist.h"

#include <errno.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"

static const char *TAG = "dns_server";

#define DNS_PORT       53
#define DNS_RX_BUF_LEN 512  /* classic non-EDNS UDP DNS message ceiling */

/* --------------------------------------------------------------------------
 * dns_listener_task(): bind a UDP socket on :53, parse each query, forward
 * it to the upstream resolver, and relay the reply back to the client.
 * No blocklist/cache yet - every query round-trips to upstream.
 * ------------------------------------------------------------------------ */
static void dns_listener_task(void *pvParameters)
{
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0) {
        ESP_LOGE(TAG, "Could not create UDP socket: errno %d", errno);
        vTaskDelete(NULL);
        return;
    }

    struct sockaddr_in listen_addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port = htons(DNS_PORT),
    };

    if (bind(sock, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0) {
        ESP_LOGE(TAG, "Could not bind UDP socket to port %d: errno %d", DNS_PORT, errno);
        close(sock);
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "DNS listener up - bound to 0.0.0.0:%d", DNS_PORT);

    char rx_buffer[DNS_RX_BUF_LEN];
    while (1) {
        struct sockaddr_in source_addr;
        socklen_t socklen = sizeof(source_addr);
        int len = recvfrom(sock, rx_buffer, sizeof(rx_buffer), 0,
                            (struct sockaddr *)&source_addr, &socklen);
        if (len < 0) {
            ESP_LOGE(TAG, "recvfrom failed: errno %d", errno);
            continue;
        }

        dns_query_t query;
        if (dns_parse_query((const uint8_t *)rx_buffer, len, &query) && query.qdcount > 0) {
            ESP_LOGI(TAG, "Query id=0x%04x from %s:%d -> %s (%s)%s",
                     query.id, inet_ntoa(source_addr.sin_addr), ntohs(source_addr.sin_port),
                     query.qname, dns_qtype_name(query.qtype), query.rd ? " rd" : "");

            if (blocklist_is_blocked(query.qname)) {
                dns_make_nxdomain_response((uint8_t *)rx_buffer, len);
                sendto(sock, rx_buffer, len, 0, (struct sockaddr *)&source_addr, socklen);
                ESP_LOGI(TAG, "Blocked %s - sent NXDOMAIN to %s:%d",
                         query.qname, inet_ntoa(source_addr.sin_addr), ntohs(source_addr.sin_port));
            } else {
                uint8_t response_buffer[DNS_RX_BUF_LEN];
                int response_len = dns_forward_query((const uint8_t *)rx_buffer, len,
                                                      response_buffer, sizeof(response_buffer));
                if (response_len > 0) {
                    sendto(sock, response_buffer, response_len, 0,
                           (struct sockaddr *)&source_addr, socklen);
                    ESP_LOGI(TAG, "Forwarded %d-byte reply for %s to %s:%d",
                             response_len, query.qname,
                             inet_ntoa(source_addr.sin_addr), ntohs(source_addr.sin_port));
                } else {
                    ESP_LOGW(TAG, "Upstream forward for %s failed - no reply sent to client", query.qname);
                }
            }
        } else {
            ESP_LOGW(TAG, "Received %d bytes from %s:%d - not a parseable DNS query",
                     len, inet_ntoa(source_addr.sin_addr), ntohs(source_addr.sin_port));
        }
    }
}

void dns_server_start(void)
{
    blocklist_init();
    xTaskCreate(dns_listener_task, "dns_listener", 4096, NULL, 5, NULL);
}
