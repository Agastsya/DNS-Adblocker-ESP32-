#pragma once

/* Start the DNS listener task: binds a UDP socket on :53 and begins
 * processing queries. Must be called after Wi-Fi is up. */
void dns_server_start(void);
