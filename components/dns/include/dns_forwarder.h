#pragma once

#include <stdint.h>

#define UPSTREAM_DNS_SERVER "1.1.1.1"
#define UPSTREAM_DNS_PORT   53

/* Forward a raw DNS query to the upstream resolver and return its raw
 * response in `response`. Returns the response length, or -1 on
 * failure/timeout. */
int dns_forward_query(const uint8_t *query, int query_len,
                       uint8_t *response, int response_buf_len);
