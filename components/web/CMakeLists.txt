idf_component_register(
    SRCS "web_server.c"
    INCLUDE_DIRS "include"
    REQUIRES esp_http_server dns json mbedtls esp_netif
    EMBED_TXTFILES "dashboard.html"
)
