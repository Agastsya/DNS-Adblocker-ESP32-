#pragma once

#include <stdint.h>

/* A small in-RAM ring buffer of the most recent DNS queries, so the
 * dashboard can show live activity: what was asked, by which device, and
 * whether it was blocked. This is what lets a user confirm at a glance that
 * their devices are actually routing DNS through PocketDNS and that ads are
 * being blocked. RAM-only - it resets on reboot, which is fine. */

typedef enum {
    DNS_LOG_ALLOWED = 0,   /* forwarded upstream */
    DNS_LOG_BLOCKED = 1,   /* matched a blocklist / schedule -> NXDOMAIN */
    DNS_LOG_CACHED  = 2,   /* served from cache */
} dns_log_action_t;

/* Create the lock guarding the ring buffer. Call once before the DNS
 * worker tasks start. */
void dns_log_init(void);

/* Record one finished query. client_ip is the source address in network
 * byte order (struct sockaddr_in.sin_addr.s_addr). Safe to call from
 * multiple worker tasks at once. */
void dns_log_record(const char *qname, uint32_t client_ip, dns_log_action_t action);

/* Newest-first JSON array of recent queries:
 * [{"name":"x.com","ip":"192.168.1.5","ago":3,"act":1}, ...].
 * Caller must cJSON_free() the result. */
char *dns_log_to_json(void);
