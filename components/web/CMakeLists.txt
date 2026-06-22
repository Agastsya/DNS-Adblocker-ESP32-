idf_component_register(
    SRCS "web_server.c"
    INCLUDE_DIRS "include"
    REQUIRES esp_http_server dns json mbedtls
    EMBED_TXTFILES "dashboard.html"
)
