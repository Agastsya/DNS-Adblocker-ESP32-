#include "dns_parser.h"

#include <string.h>

#define DNS_HEADER_LEN 12

bool dns_parse_query(const uint8_t *buf, int len, dns_query_t *out)
{
    if (buf == NULL || out == NULL || len < DNS_HEADER_LEN) {
        return false;
    }

    memset(out, 0, sizeof(*out));

    out->id      = (buf[0] << 8) | buf[1];
    out->rd      = (buf[2] & 0x01) != 0;
    out->qdcount = (buf[4] << 8) | buf[5];

    if (out->qdcount == 0) {
        return true;  /* valid header, just no question to decode */
    }

    /* Decode QNAME: a sequence of length-prefixed labels terminated by a
     * zero-length label. We deliberately reject compression pointers
     * (top two bits of the length byte set) - those show up in responses,
     * not in well-formed client queries, so treat one as a parse failure
     * rather than chasing a pointer into possibly-attacker-controlled
     * offsets. */
    int pos = DNS_HEADER_LEN;
    size_t name_len = 0;

    while (pos < len) {
        uint8_t label_len = buf[pos];
        if (label_len == 0) {
            pos++;
            break;
        }
        if ((label_len & 0xC0) != 0) {
            return false;
        }
        pos++;
        if (pos + label_len > len) {
            return false;  /* truncated label */
        }
        if (name_len + label_len + 1 > DNS_MAX_NAME_LEN) {
            return false;  /* name too long */
        }
        if (name_len > 0) {
            out->qname[name_len++] = '.';
        }
        memcpy(&out->qname[name_len], &buf[pos], label_len);
        name_len += label_len;
        pos += label_len;
    }
    out->qname[name_len] = '\0';

    if (pos + 4 > len) {
        return false;  /* missing QTYPE/QCLASS */
    }
    out->qtype  = (buf[pos] << 8) | buf[pos + 1];
    out->qclass = (buf[pos + 2] << 8) | buf[pos + 3];

    return true;
}

void dns_make_nxdomain_response(uint8_t *buf, int len)
{
    if (len < DNS_HEADER_LEN) {
        return;
    }
    buf[2] |= 0x80;            /* QR = 1 (this is a response) */
    buf[3] = 0x80 | 0x03;      /* RA = 1, RCODE = 3 (NXDOMAIN) */
    buf[6] = 0; buf[7] = 0;    /* ANCOUNT */
    buf[8] = 0; buf[9] = 0;    /* NSCOUNT */
    buf[10] = 0; buf[11] = 0;  /* ARCOUNT */
}

const char *dns_qtype_name(uint16_t qtype)
{
    switch (qtype) {
        case 1:  return "A";
        case 2:  return "NS";
        case 5:  return "CNAME";
        case 6:  return "SOA";
        case 12: return "PTR";
        case 15: return "MX";
        case 16: return "TXT";
        case 28: return "AAAA";
        case 33: return "SRV";
        case 65: return "HTTPS";
        default: return "?";
    }
}
