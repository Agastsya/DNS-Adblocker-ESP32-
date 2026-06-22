# PocketDNS

**A network-wide ad & tracker blocker that runs on a $5 ESP32.**

PocketDNS is a tiny, Pi-hole-style DNS filter built from scratch for the
ESP32. Plug it into power, point your phone, laptop, or whole router at it, and
it quietly blocks tens of thousands of ad and tracker domains across every app
and browser on your network — no software to install on your devices, no
subscription, no cloud account.

It comes with a clean web dashboard (live stats, a 24-hour activity graph, and
controls for blocking, allowing, scheduling, and uploading your own lists), a
captive-portal Wi-Fi setup so non-technical people can get it online from their
phone, and over-the-air updates.

---

## ⚠️ Read this first: what DNS blocking can and can't do

PocketDNS is a **DNS** blocker, exactly like Pi-hole, AdGuard-DNS, and NextDNS.
It's important to be honest about the limits, because they're the same for
*every* DNS-based blocker:

| It blocks ✅ | It can't block ❌ |
|---|---|
| Third-party ad networks (DoubleClick, Criteo, OpenX…) | **YouTube video ads** |
| Trackers & analytics (Google Analytics, Segment…) | Ads served from the **same domain** as the page (some news sites) |
| Telemetry & "phone-home" domains in apps | Anything inside an app that uses its **own** DNS |
| Malware / phishing domains (depending on list) | |

**Why not YouTube ads?** YouTube serves its ads from `googlevideo.com` — the
*exact same domain* as the actual videos — over an encrypted connection. A DNS
blocker only sees domain names, never the content, so it physically cannot tell
an ad apart from a video. Blocking the domain kills YouTube entirely. This is
why **no** DNS blocker (Pi-hole included) stops YouTube ads — only in-browser
blockers like uBlock Origin or Brave can, because they run *inside* the browser
with the page already decrypted. PocketDNS can't be that, and neither can any
network-level box.

If network-wide blocking of ad/tracker domains is what you want, PocketDNS does
it very well. If you specifically want YouTube ads gone, you need a browser
extension or a patched app — not any DNS tool.

---

## Features

- 🛡️ **~80,000-domain blocklist** (Hagezi's list), refreshed daily, stored as a
  hash index **on flash** so it isn't limited by the ESP32's tiny RAM.
- ➕ **Block any site yourself** from the dashboard, or **paste/upload your own
  list** of domains.
- ✅ **Allowlist** to un-block anything caught by mistake.
- ⏰ **Parental-control schedules** — block a domain during a daily time window
  (e.g. social media 9 PM–7 AM), in your local timezone.
- 📊 **Web dashboard** — live query/blocked/cache stats, a 24-hour activity
  graph, and all the controls above. Mobile-friendly.
- 📶 **Captive-portal Wi-Fi setup** — no credentials baked in? The device makes
  its own hotspot so you can enter your Wi-Fi from a phone.
- 🔄 **Over-the-air updates** from GitHub Releases.
- 🔒 **Password-protected** dashboard, **TTL-aware cache**, persistent stats.

---

## Hardware you need

- An **ESP32 development board** (e.g. ESP32 DevKit V1) with **4 MB of flash**
  (almost all of them). ~$5.
- A **USB cable** that supports data (not charge-only).
- That's it. It sips power and can run off any USB charger once set up.

---

## Software prerequisites

You build and flash the firmware once using Espressif's official toolchain,
**ESP-IDF v5.5.x**. Install it from the official guide for your OS:

👉 https://docs.espressif.com/projects/esp-idf/en/v5.5/esp32/get-started/

After installing, open a terminal and "activate" ESP-IDF so the `idf.py`
command works:

```bash
# macOS / Linux
. $HOME/esp/esp-idf/export.sh      # path may differ depending on where you installed it

# Windows: use the "ESP-IDF PowerShell" or "ESP-IDF CMD" shortcut it created
```

You'll do this once per terminal session.

---

## Install & flash (step by step)

### 1. Get the code

```bash
git clone https://github.com/Agastsya/DNS-Adblocker-ESP32-.git
cd DNS-Adblocker-ESP32-
```

### 2. Set your Wi-Fi (two ways — pick one)

**Option A — edit one file (simplest if you're building it yourself).**
Open [`sdkconfig.defaults`](sdkconfig.defaults) and fill in your home Wi-Fi:

```ini
CONFIG_POCKETDNS_WIFI_SSID="YourWiFiName"
CONFIG_POCKETDNS_WIFI_PASSWORD="YourWiFiPassword"
```

While you're there, set your timezone (used for parental schedules):

```ini
CONFIG_POCKETDNS_TIMEZONE="IST-5:30"     # India; see the file for more examples
```

**Option B — set it up from your phone later (no editing, great for sharing).**
Leave the Wi-Fi lines blank. On first boot the device creates a Wi-Fi hotspot
called **`PocketDNS-Setup`**. Connect your phone to it, a setup page pops up,
and you type in your home Wi-Fi. The device saves it and reboots. You can change
networks anytime by clearing its saved Wi-Fi.

### 3. Tell ESP-IDF this is an ESP32 (first time only)

```bash
idf.py set-target esp32
```

### 4. Build

```bash
idf.py build
```

### 5. Plug in the board and flash

Find your board's serial port:

- **macOS:** `ls /dev/cu.usbserial-*` (or `cu.SLAB_USBtoUART`)
- **Linux:** `ls /dev/ttyUSB*`
- **Windows:** it's a `COMx` port (check Device Manager)

Then flash and watch the logs:

```bash
idf.py -p <YOUR_PORT> flash monitor      # e.g. -p /dev/cu.usbserial-0001
```

You'll see it connect to Wi-Fi and print a line like:

```
I (2440) wifi_manager: Got IP: 192.168.0.42
```

**That IP address is your PocketDNS.** Note it down. Press `Ctrl-]` to leave the
monitor.

---

## Using it

### Point your devices at PocketDNS

Set the **DNS server** on whatever you want filtered to the IP from above:

- **One phone/laptop:** change its Wi-Fi's DNS to the PocketDNS IP.
  - *Android (Samsung etc.):* Settings → Connections → Wi-Fi → ⚙ on your network
    → IP settings → **Static** → set **DNS 1** to the PocketDNS IP.
    **Also turn off "Private DNS"** (Settings → Connections → More connection
    settings → Private DNS → Off) — otherwise your phone bypasses PocketDNS.
  - *Chrome:* also turn off **Settings → Privacy → Use secure DNS**, for the same
    reason.
  - *iPhone/Mac/Windows:* set DNS in the Wi-Fi/network settings.
- **Your whole home:** set the DNS server in your **router's** DHCP settings to
  the PocketDNS IP. Now every device is filtered automatically. (Give the ESP32
  a static IP / DHCP reservation in your router so it doesn't change.)

> **Tip:** a quick way to confirm it's working, from any computer:
> `nslookup doubleclick.net <PocketDNS-IP>` should come back empty/refused,
> while `nslookup example.com <PocketDNS-IP>` resolves normally.

### Open the dashboard

Visit **`http://<PocketDNS-IP>/`** in a browser. Default login:

- **Username:** `admin`
- **Password:** `pocketdns`

(Change these before sharing — see Configuration below.)

From the dashboard you can:

- See **live stats** and a **24-hour activity graph** (allowed vs blocked).
- **Block a website** — type a domain, it's blocked everywhere.
- **Upload a blocklist** — paste your own domains (one per line).
- **Allow** a domain the blocklist got wrong.
- Set **parental-control schedules** with a daily time window.
- Set your **timezone** so schedules use the right local time.

---

## Configuration

Most things are editable live from the dashboard. A few are build-time, in
[`sdkconfig.defaults`](sdkconfig.defaults) (or run `idf.py menuconfig` →
*PocketDNS …*):

| Setting | Where | Notes |
|---|---|---|
| Wi-Fi SSID / password | `sdkconfig.defaults` or captive portal | |
| Dashboard username / password | `menuconfig` → *PocketDNS Web Dashboard* | change from the default! |
| Timezone | dashboard **Settings**, or `sdkconfig.defaults` | for schedules |
| Blocklist source URL | `components/dns/blocklist.c` (`BLOCKLIST_URL`) | any plain domain-per-line list |

---

## How it works (architecture)

PocketDNS is a from-scratch implementation, organized as ESP-IDF components:

```
main/            – startup orchestration
components/
  storage/       – LittleFS filesystem + persistence
  wifi/          – Wi-Fi station + captive-portal setup AP
  dns/           – the DNS engine:
                     dns_server   UDP :53 listener
                     dns_parser   DNS packet parsing
                     dns_forwarder upstream resolver (1.1.1.1)
                     dns_cache    TTL-aware response cache
                     blocklist    cloud hash index + manual/custom/allow lists
                     schedule     parental-control time windows + SNTP clock
                     dns_stats    counters + 24h history
  web/           – HTTP dashboard + REST API (single embedded HTML page)
  ota/           – over-the-air update check
```

A DNS query comes in on UDP port 53 → it's parsed → checked against your
allowlist, then your block/custom lists, then the ~80k-domain cloud index
(binary-searched on flash), then any active schedule. If blocked, it returns
`NXDOMAIN`; otherwise it's served from cache or forwarded upstream to
`1.1.1.1`, cached, and returned.

The big blocklist is the interesting part: the multi-megabyte source list is
**hashed as it streams in during download** (never stored whole), and the
resulting 32-bit hashes are kept in sorted buckets **on flash**, so the list
size is bounded by the 4 MB flash chip rather than the ESP32's ~tens of KB of
free RAM.

---

## Troubleshooting

- **Dashboard won't load / device unreachable from your computer, but your
  phone reached it** → your router has **AP/client isolation** turned on (common
  on guest networks and some mesh routers). Turn off "AP Isolation" / "Client
  Isolation" / "Wireless Isolation" in the router.
- **Blocking doesn't seem to work** → almost always **Chrome's "Secure DNS"** or
  Android's **"Private DNS"** is on, sending lookups straight to Google and
  bypassing PocketDNS. Turn both off. Also, sites you *just* visited are cached
  by your browser/OS for a few minutes.
- **Parental schedules fire at the wrong time** → set your **timezone** in the
  dashboard Settings; schedules use local time.
- **Flash fails / port busy / disappears** → unplug and replug the USB cable
  (cheap USB-serial chips drop off sometimes), try a different cable/port, and
  make sure no serial monitor is already open on the port.
- **`idf.py: command not found`** → you didn't activate ESP-IDF in this terminal;
  run the `export.sh` step again.

---

## Limitations & honesty

- Cannot block YouTube ads or first-party ads (see the section at the top — this
  is true of all DNS blockers).
- Best for a personal/home network. The ESP32 isn't a high-throughput resolver;
  it's perfect for a household, not an office of hundreds.
- The daily blocklist rebuild takes ~1 minute in the background (the device keeps
  serving from a small built-in list during that window).

---

## Contributing

Issues and pull requests are welcome. Good first contributions: alternate
blocklist sources, dashboard improvements, IPv6/AAAA handling, or a "top blocked
domains" view.

## License

MIT — see [LICENSE](LICENSE). Built with [ESP-IDF](https://github.com/espressif/esp-idf)
and [LittleFS](https://github.com/joltwallet/esp_littlefs); blocklist by
[Hagezi](https://github.com/hagezi/dns-blocklists).
