idf_component_register(
    SRCS "dns_stats.c" "dns_cache.c" "dns_server.c" "dns_parser.c" "dns_forwarder.c" "blocklist.c" "schedule.c"
    INCLUDE_DIRS "include"
    REQUIRES lwip esp_timer json esp_http_client mbedtls esp_netif
)
