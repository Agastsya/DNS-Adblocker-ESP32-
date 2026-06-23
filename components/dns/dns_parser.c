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

/* Decode a (possibly compressed) DNS name starting at `pos` into `out` as a
 * dotted string. Returns the offset just past the name in the sequential
 * stream (for a compressed name that's the position after the 2-byte
 * pointer), or -1 on malformed input. */
static int read_name(const uint8_t *buf, int len, int pos, char *out, size_t out_sz)
{
    size_t oi = 0;
    int jumped = 0;
    int next = -1;       /* where the sequential parse resumes after a pointer */
    int hops = 0;

    while (pos >= 0 && pos < len) {
        uint8_t b = buf[pos];
        if ((b & 0xC0) == 0xC0) {                 /* compression pointer */
            if (pos + 1 >= len) return -1;
            if (!jumped) next = pos + 2;
            jumped = 1;
            if (++hops > 20) return -1;           /* guard against pointer loops */
            pos = ((b & 0x3F) << 8) | buf[pos + 1];
            continue;
        }
        if ((b & 0xC0) != 0) return -1;           /* reserved label type */
        if (b == 0) { pos += 1; break; }          /* end of name */
        if (pos + 1 + b > len) return -1;
        if (oi + (size_t)b + 1 >= out_sz) return -1;
        if (oi > 0) out[oi++] = '.';
        memcpy(out + oi, buf + pos + 1, b);
        oi += b;
        pos += 1 + b;
    }
    out[oi] = '\0';
    return jumped ? next : pos;
}

int dns_extract_cname_targets(const uint8_t *buf, int len,
                              char out[][DNS_MAX_NAME_LEN + 1], int max)
{
    if (buf == NULL || len < DNS_HEADER_LEN || max <= 0) {
        return 0;
    }
    int qdcount = (buf[4] << 8) | buf[5];
    int ancount = (buf[6] << 8) | buf[7];

    int pos = DNS_HEADER_LEN;
    char tmp[DNS_MAX_NAME_LEN + 1];

    /* Skip the question section (QNAME + QTYPE + QCLASS each). */
    for (int i = 0; i < qdcount; i++) {
        pos = read_name(buf, len, pos, tmp, sizeof(tmp));
        if (pos < 0 || pos + 4 > len) return 0;
        pos += 4;
    }

    int count = 0;
    for (int i = 0; i < ancount && count < max; i++) {
        pos = read_name(buf, len, pos, tmp, sizeof(tmp));   /* record owner */
        if (pos < 0 || pos + 10 > len) break;
        int type   = (buf[pos] << 8) | buf[pos + 1];
        int rdlen  = (buf[pos + 8] << 8) | buf[pos + 9];
        int rdpos  = pos + 10;
        if (rdpos + rdlen > len) break;

        if (type == 5) {   /* CNAME: RDATA is the target name */
            char target[DNS_MAX_NAME_LEN + 1];
            if (read_name(buf, len, rdpos, target, sizeof(target)) >= 0 && target[0] != '\0') {
                strlcpy(out[count], target, DNS_MAX_NAME_LEN + 1);
                count++;
            }
        }
        pos = rdpos + rdlen;
    }
    return count;
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
