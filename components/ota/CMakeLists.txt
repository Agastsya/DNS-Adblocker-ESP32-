idf_component_register(
    SRCS "ota_check.c"
    INCLUDE_DIRS "include"
    REQUIRES esp_http_client esp_https_ota mbedtls json esp_app_format
)
