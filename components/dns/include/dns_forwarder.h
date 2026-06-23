#pragma once

#include <stdint.h>
#include <stddef.h>

#define UPSTREAM_DNS_DEFAULT "1.1.1.1"
#define UPSTREAM_DNS_PORT    53

/* Forward a raw DNS query to the upstream resolver and return its raw
 * response in `response`. Returns the response length, or -1 on
 * failure/timeout. */
int dns_forward_query(const uint8_t *query, int query_len,
                       uint8_t *response, int response_buf_len);

/* The upstream resolver PocketDNS forwards non-blocked queries to. Set it
 * to a filtering resolver (e.g. AdGuard DNS 94.140.14.14) for a second
 * layer of ad/tracker blocking. Persisted to flash; load at startup.
 * (Note: no resolver, including these, can block YouTube video ads.) */
void dns_forwarder_init(void);
void dns_forwarder_get_upstream(char *out, size_t out_len);
int  dns_forwarder_set_upstream(const char *ip);   /* 0 on success */
