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

#define FORWARD_TIMEOUT_S 2   /* give up if neither resolver answers in time */

int dns_forward_query(const uint8_t *query, int query_len,
                       uint8_t *response, int response_buf_len)
{
    /* Race the configured resolver against a public fallback IN PARALLEL and
     * take whichever answers first. Doing them at once (instead of waiting
     * for the primary to time out before trying the fallback) means a slow
     * or dead upstream can never add seconds of latency to every lookup -
     * the page-load tax that makes a DNS filter feel "broken". */
    const char *resolvers[2];
    resolvers[0] = s_upstream;
    resolvers[1] = (strcmp(s_upstream, "1.1.1.1") == 0) ? "8.8.8.8" : "1.1.1.1";

    int socks[2];
    int nsock = 0;
    int maxfd = -1;
    for (int i = 0; i < 2; i++) {
        int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
        if (s < 0) {
            continue;
        }
        struct sockaddr_in addr = {
            .sin_family = AF_INET,
            .sin_port = htons(UPSTREAM_DNS_PORT),
            .sin_addr.s_addr = inet_addr(resolvers[i]),
        };
        if (sendto(s, query, query_len, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            close(s);
            continue;
        }
        socks[nsock++] = s;
        if (s > maxfd) {
            maxfd = s;
        }
    }
    if (nsock == 0) {
        return -1;
    }

    fd_set rfds;
    FD_ZERO(&rfds);
    for (int i = 0; i < nsock; i++) {
        FD_SET(socks[i], &rfds);
    }
    struct timeval tv = { .tv_sec = FORWARD_TIMEOUT_S, .tv_usec = 0 };

    int result = -1;
    if (select(maxfd + 1, &rfds, NULL, NULL, &tv) > 0) {
        for (int i = 0; i < nsock; i++) {
            if (FD_ISSET(socks[i], &rfds)) {
                int len = recvfrom(socks[i], response, response_buf_len, 0, NULL, NULL);
                if (len > 0) {
                    result = len;
                    break;
                }
            }
        }
    }
    if (result < 0) {
        ESP_LOGW(TAG, "No upstream answered within %ds", FORWARD_TIMEOUT_S);
    }
    for (int i = 0; i < nsock; i++) {
        close(socks[i]);
    }
    return result;
}
