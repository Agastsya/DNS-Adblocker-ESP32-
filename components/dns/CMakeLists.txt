idf_component_register(
    SRCS "dns_server.c" "dns_parser.c" "dns_forwarder.c" "blocklist.c"
    INCLUDE_DIRS "include"
    REQUIRES lwip
)
