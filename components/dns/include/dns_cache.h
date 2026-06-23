#pragma once

#include <stdint.h>

/* Create the lock that guards the cache. Must be called once, before the
 * DNS worker tasks start, since several of them read/write the cache
 * concurrently. */
void dns_cache_init(void);

/* Look up a cached response for (qname, qtype). On a hit, copies it into
 * out_response with the ID field rewritten to match query_id (so it
 * matches whichever client just asked), and returns its length. Returns
 * -1 on a miss or an expired entry. */
int dns_cache_lookup(const char *qname, uint16_t qtype, uint16_t query_id,
                      uint8_t *out_response, int out_buf_len);

/* Store a raw upstream response for (qname, qtype). The TTL is read
 * straight out of the response's answer records (the minimum across all
 * of them), so callers don't need to track it separately. A response
 * with no answers, or one too large to fit, is silently not cached. */
void dns_cache_store(const char *qname, uint16_t qtype,
                      const uint8_t *response, int response_len);
