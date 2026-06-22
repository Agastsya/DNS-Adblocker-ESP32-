#include "dns_forwarder.h"

#include <errno.h>

#include "esp_log.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"

static const char *TAG = "dns_forwarder";

int dns_forward_query(const uint8_t *query, int query_len,
                       uint8_t *response, int response_buf_len)
{
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0) {
        ESP_LOGE(TAG, "Could not create upstream socket: errno %d", errno);
        return -1;
    }

    /* Upstream may not answer at all (dropped packet, outage) - without a
     * receive timeout this task would block forever and the proxy would
     * wedge on the very first lost reply. */
    struct timeval timeout = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    struct sockaddr_in upstream_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(UPSTREAM_DNS_PORT),
        .sin_addr.s_addr = inet_addr(UPSTREAM_DNS_SERVER),
    };

    if (sendto(sock, query, query_len, 0,
               (struct sockaddr *)&upstream_addr, sizeof(upstream_addr)) < 0) {
        ESP_LOGW(TAG, "sendto upstream failed: errno %d", errno);
        close(sock);
        return -1;
    }

    int len = recvfrom(sock, response, response_buf_len, 0, NULL, NULL);
    if (len < 0) {
        ESP_LOGW(TAG, "No response from upstream %s (errno %d)", UPSTREAM_DNS_SERVER, errno);
    }

    close(sock);
    return len;
}
