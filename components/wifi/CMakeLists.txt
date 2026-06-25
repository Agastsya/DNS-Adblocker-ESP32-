idf_component_register(
    SRCS "wifi_manager.c" "captive_portal.c"
    INCLUDE_DIRS "include"
    REQUIRES esp_wifi esp_event esp_netif nvs_flash esp_http_server lwip mdns
)
