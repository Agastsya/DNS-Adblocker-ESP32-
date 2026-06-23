#include "dns_forwarder.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"

static const char *TAG = "dns_forwarder";

#define UPSTREAM_PATH  "/littlefs/upstream.txt"
#define UPSTREAM_MAX   46   /* fits an IPv4 or IPv6 literal */

static char s_upstream[UPSTREAM_MAX] = UPSTREAM_DNS_DEFAULT;

void dns_forwarder_init(void)
{
    FILE *f = fopen(UPSTREAM_PATH, "r");
    if (f != NULL) {
        if (fgets(s_upstream, sizeof(s_upstream), f) != NULL) {
            s_upstream[strcspn(s_upstream, "\r\n")] = '\0';
        }
        fclose(f);
    }
    if (s_upstream[0] == '\0') {
        strlcpy(s_upstream, UPSTREAM_DNS_DEFAULT, sizeof(s_upstream));
    }
    ESP_LOGI(TAG, "Upstream resolver: %s", s_upstream);
}

void dns_forwarder_get_upstream(char *out, size_t out_len)
{
    strlcpy(out, s_upstream, out_len);
}

int dns_forwarder_set_upstream(const char *ip)
{
    /* Validate it's a usable IPv4 dotted-quad before accepting it, so a
     * typo can't silently break all forwarding. */
    if (ip == NULL || ip[0] == '\0' || strlen(ip) >= UPSTREAM_MAX ||
        inet_addr(ip) == INADDR_NONE) {
        return -1;
    }
    strlcpy(s_upstream, ip, sizeof(s_upstream));
    FILE *f = fopen(UPSTREAM_PATH, "w");
    if (f != NULL) {
        fputs(s_upstream, f);
        fclose(f);
    }
    ESP_LOGI(TAG, "Upstream resolver set to %s", s_upstream);
    return 0;
}

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
        .sin_addr.s_addr = inet_addr(s_upstream),
    };

    if (sendto(sock, query, query_len, 0,
               (struct sockaddr *)&upstream_addr, sizeof(upstream_addr)) < 0) {
        ESP_LOGW(TAG, "sendto upstream failed: errno %d", errno);
        close(sock);
        return -1;
    }

    int len = recvfrom(sock, response, response_buf_len, 0, NULL, NULL);
    if (len < 0) {
        ESP_LOGW(TAG, "No response from upstream %s (errno %d)", s_upstream, errno);
    }

    close(sock);
    return len;
}
