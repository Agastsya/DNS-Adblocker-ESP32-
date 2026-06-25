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

/* Send the query to one resolver and wait up to timeout_ms for a reply.
 * One blocking socket with SO_RCVTIMEO - simple and reliable. Returns the
 * response length, or -1 on timeout/error. */
static int forward_to(const char *ip, const uint8_t *query, int query_len,
                      uint8_t *response, int response_buf_len, int timeout_ms)
{
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0) {
        ESP_LOGW(TAG, "Could not create upstream socket: errno %d", errno);
        return -1;
    }
    struct timeval tv = { .tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(UPSTREAM_DNS_PORT),
        .sin_addr.s_addr = inet_addr(ip),
    };
    int len = -1;
    if (sendto(sock, query, query_len, 0, (struct sockaddr *)&addr, sizeof(addr)) >= 0) {
        len = recvfrom(sock, response, response_buf_len, 0, NULL, NULL);
    }
    close(sock);
    return len;
}

int dns_forward_query(const uint8_t *query, int query_len,
                       uint8_t *response, int response_buf_len)
{
    /* Try the configured resolver first with a short timeout. The DNS worker
     * pool means one slow lookup never blocks the others, so this stays snappy
     * even under a burst. If the primary doesn't answer quickly, fall back to a
     * public resolver so a slow/misconfigured upstream can't kill resolution. */
    int len = forward_to(s_upstream, query, query_len, response, response_buf_len, 1500);
    if (len > 0) {
        return len;
    }

    const char *fb = (strcmp(s_upstream, "1.1.1.1") == 0) ? "8.8.8.8" : "1.1.1.1";
    len = forward_to(fb, query, query_len, response, response_buf_len, 2000);
    if (len <= 0) {
        ESP_LOGW(TAG, "No upstream answered (primary %s, fallback %s)", s_upstream, fb);
    }
    return len;
}
