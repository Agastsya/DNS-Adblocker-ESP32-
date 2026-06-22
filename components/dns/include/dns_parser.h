#pragma once

#include <stdint.h>
#include <stdbool.h>

#define DNS_MAX_NAME_LEN 255

typedef struct {
    uint16_t id;
    bool     rd;        /* recursion desired */
    uint16_t qdcount;
    char     qname[DNS_MAX_NAME_LEN + 1];
    uint16_t qtype;
    uint16_t qclass;
} dns_query_t;

/* Parse the header and first question of a raw DNS message. Returns true
 * on success (qdcount may still be 0, in which case qname is empty). */
bool dns_parse_query(const uint8_t *buf, int len, dns_query_t *out);

/* Human-readable name for a QTYPE (e.g. 1 -> "A"), for logging. */
const char *dns_qtype_name(uint16_t qtype);

/* Turn a raw query buffer into an NXDOMAIN response in place: flips the
 * QR bit, sets RCODE=NXDOMAIN, and zeroes the answer/authority/additional
 * counts. The question section and overall length are unchanged, so the
 * client sees its own question echoed back with "no such domain". */
void dns_make_nxdomain_response(uint8_t *buf, int len);
