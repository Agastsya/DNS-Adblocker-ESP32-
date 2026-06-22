#include "blocklist.h"

#include <string.h>
#include <strings.h>

#include "esp_log.h"

static const char *TAG = "blocklist";

/* Small built-in seed list of well-known ad/tracking domains. Phase 10
 * (cloud blocklist sync) replaces/extends this with a list fetched
 * periodically and stored on LittleFS - this is deliberately minimal
 * until that exists. */
static const char *s_blocklist[] = {
    "doubleclick.net",
    "googlesyndication.com",
    "googleadservices.com",
    "google-analytics.com",
    "googletagmanager.com",
    "scorecardresearch.com",
    "adsystem.amazon.com",
    "ads.yahoo.com",
    "adnxs.com",
    "criteo.com",
};
#define BLOCKLIST_COUNT (sizeof(s_blocklist) / sizeof(s_blocklist[0]))

/* Empty for now - entries here override the blocklist above. Exists so
 * the matching logic and call sites don't need to change once a real
 * whitelist (e.g. user-managed via the Phase 9 dashboard) shows up. */
static const char *s_whitelist[] = {
    NULL,
};
#define WHITELIST_COUNT (sizeof(s_whitelist) / sizeof(s_whitelist[0]) - 1)

/* True if `domain` is exactly `entry`, or a subdomain of it (e.g.
 * "ads.doubleclick.net" matches entry "doubleclick.net", but
 * "notdoubleclick.net" does not). */
static bool domain_matches(const char *domain, const char *entry)
{
    size_t domain_len = strlen(domain);
    size_t entry_len = strlen(entry);

    if (domain_len < entry_len) {
        return false;
    }
    if (strcasecmp(domain + (domain_len - entry_len), entry) != 0) {
        return false;
    }
    if (domain_len == entry_len) {
        return true;
    }
    return domain[domain_len - entry_len - 1] == '.';
}

esp_err_t blocklist_init(void)
{
    ESP_LOGI(TAG, "Loaded %u blocklist entries, %u whitelist entries",
             (unsigned)BLOCKLIST_COUNT, (unsigned)WHITELIST_COUNT);
    return ESP_OK;
}

bool blocklist_is_blocked(const char *domain)
{
    for (size_t i = 0; i < WHITELIST_COUNT; i++) {
        if (domain_matches(domain, s_whitelist[i])) {
            return false;
        }
    }
    for (size_t i = 0; i < BLOCKLIST_COUNT; i++) {
        if (domain_matches(domain, s_blocklist[i])) {
            return true;
        }
    }
    return false;
}
