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

## Contents

- [What DNS blocking can and can't do](#-read-this-first-what-dns-blocking-can-and-cant-do)
- [Features](#features)
- [Compatibility — which ESP32 boards work](#compatibility--which-esp32-boards-work)
- [What you need](#what-you-need)
- **Installation guide**
  - [1. Install the ESP-IDF toolchain](#1-install-the-esp-idf-toolchain)
  - [2. Install the USB driver (if needed)](#2-install-the-usb-driver-if-needed)
  - [3. Download PocketDNS](#3-download-pocketdns)
  - [4. Configure Wi-Fi and timezone](#4-configure-wi-fi-and-timezone)
  - [5. Build the firmware](#5-build-the-firmware)
  - [6. Connect the board and find its port](#6-connect-the-board-and-find-its-port)
  - [7. Flash the board](#7-flash-the-board)
  - [8. First boot — find your PocketDNS IP](#8-first-boot--find-your-pocketdns-ip)
- [Using it](#using-it)
- [Configuration reference](#configuration-reference)
- [How it works (architecture)](#how-it-works-architecture)
- [Troubleshooting](#troubleshooting)
- [Updating and resetting](#updating-and-resetting)
- [Limitations & honesty](#limitations--honesty)
- [Contributing & License](#contributing)

---

## ⚠️ Read this first: what DNS blocking can and can't do

PocketDNS is a **DNS** blocker, exactly like Pi-hole, AdGuard-DNS, and NextDNS.
It's important to be honest about the limits, because they're the same for
*every* DNS-based blocker:

| It blocks ✅ | It can't block ❌ |
|---|---|
| Third-party ad networks (DoubleClick, Criteo, OpenX…) |  |
| Trackers & analytics (Google Analytics, Segment…) | Ads served from the **same domain** as the page ( some rare sites) |
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

## Compatibility — which ESP32 boards work

PocketDNS needs three things from a board: **Wi-Fi**, **at least 4 MB of
flash**, and support for **ESP-IDF v5.5**.

### ✅ Fully supported and tested

| Chip | Typical boards | Notes |
|---|---|---|
| **ESP32** (classic, "ESP32-WROOM-32") | ESP32 **DevKit V1** / DOIT, NodeMCU-32S, WeMos/LOLIN D32, ESP32-WROVER | What PocketDNS is built and tested on. **Recommended.** Use a **4 MB** flash version (almost all are). |

If you're buying a board specifically for this, get a **classic ESP32 DevKit V1
with 4 MB flash** — it's ~$5, ubiquitous, and exactly what's tested.

### 🟡 Should work, but untested (you change one setting)

These chips have Wi-Fi and run ESP-IDF v5.5, and PocketDNS uses **no
chip-specific code**, so it should build and run. You just tell the build which
chip you have (`idf.py set-target esp32s3`, etc.):

| Chip | Notes |
|---|---|
| **ESP32-S3** | Dual-core, lots of RAM. Should work great. Needs 4 MB+ flash. |
| **ESP32-S2** | Single-core, Wi-Fi only. Should work. |
| **ESP32-C3** | RISC-V, single-core, Wi-Fi + BLE. Should work. |
| **ESP32-C6** | Wi-Fi 6 + BLE. Should work on recent ESP-IDF. |
| **ESP32-C2 (ESP8684)** | Low-cost; needs a 4 MB variant. |

### ❌ Not supported

| Chip / board | Why |
|---|---|
| **ESP32-H2** | No Wi-Fi (Thread/Zigbee/BLE only). |
| **ESP8266** | Older chip, different SDK (not ESP-IDF v5). Would need a port. |
| **Any board with < 4 MB flash** (2 MB modules) | Firmware + dual OTA slots + filesystem need 4 MB. |

**Check your flash size:** with the board plugged in, run
`idf.py -p <PORT> flash_id` — the `Detected flash size` line must say **4MB** or
more.

**USB-to-serial chip** (matters for flashing only): boards use either a
**CP2102/CP2104** (Silicon Labs) or **CH340/CH9102** (WCH) chip; some OSes need
a driver — see [step 2](#2-install-the-usb-driver-if-needed).

---

## What you need

- A **compatible ESP32 board** (see above) — 4 MB flash, with Wi-Fi.
- A **USB data cable** (must carry data — many cheap cables are charge-only).
- A computer running **macOS, Linux, or Windows**.
- Your **home Wi-Fi name and password** (2.4 GHz — ESP32 doesn't do 5 GHz).
- ~1 GB free disk space for the toolchain.

> **First time?** The steps below take ~30–45 minutes, most of it the one-time
> ESP-IDF install. Follow them top to bottom.

---

## 1. Install the ESP-IDF toolchain

ESP-IDF is Espressif's official development framework. PocketDNS uses
**v5.5.x**. Install it with the official installer for your OS:

👉 **https://docs.espressif.com/projects/esp-idf/en/v5.5/esp32/get-started/**

Quick summary per OS:

**Windows (easiest):** download the **ESP-IDF Windows Installer** from the link
above, pick **v5.5**, and let it install everything (Python, toolchain, Git). It
creates an **"ESP-IDF CMD"** (and PowerShell) shortcut — use that for all
commands below.

**macOS / Linux:**

```bash
mkdir -p ~/esp && cd ~/esp
git clone -b v5.5.4 --recursive https://github.com/espressif/esp-idf.git
cd esp-idf
./install.sh esp32
```

After installing, you **activate** ESP-IDF in your terminal so the `idf.py`
command works. Do this **once per terminal session**:

```bash
# macOS / Linux
. ~/esp/esp-idf/export.sh
# Windows: just open the "ESP-IDF CMD" shortcut — it's already activated
```

You'll know it worked when `idf.py --version` prints something like
`ESP-IDF v5.5.4`.

---

## 2. Install the USB driver (if needed)

When you plug in the board, your computer needs to recognize its USB-serial
chip. Plug it in first — if a new serial port shows up (see
[step 6](#6-connect-the-board-and-find-its-port)), skip this step.

If it **doesn't** show up, install the driver for your board's chip:

- **CP2102 / CP2104:** Silicon Labs "CP210x VCP" driver —
  https://www.silabs.com/developers/usb-to-uart-bridge-vcp-drivers
- **CH340 / CH9102:** WCH driver — http://www.wch-ic.com/downloads/CH341SER_ZIP.html
  (macOS: search "CH340 macOS driver").

> Recent macOS and Linux usually have the CP2102 driver built in. CH340 often
> needs a manual install.

---

## 3. Download PocketDNS

In your activated ESP-IDF terminal:

```bash
git clone https://github.com/Agastsya/DNS-Adblocker-ESP32-.git
cd DNS-Adblocker-ESP32-
```

---

## 4. Configure Wi-Fi and timezone

You have **two ways** to set the Wi-Fi. Pick one.

### Option A — edit one file (simplest)

Open **`sdkconfig.defaults`** in any text editor and fill in your network:

```ini
CONFIG_POCKETDNS_WIFI_SSID="YourWiFiName"
CONFIG_POCKETDNS_WIFI_PASSWORD="YourWiFiPassword"
```

While you're there, set your timezone (used for parental-control schedules) —
more examples are in the file:

```ini
CONFIG_POCKETDNS_TIMEZONE="IST-5:30"     # India. UK: "GMT0BST,M3.5.0/1,M10.5.0"
```

> Use a **2.4 GHz** network name. The ESP32 cannot connect to 5 GHz Wi-Fi.

### Option B — set it up from your phone after flashing (no editing)

Leave the two Wi-Fi lines blank. After flashing, the device creates its own
Wi-Fi hotspot named **`PocketDNS-Setup`**. Connect your phone to it and a setup
page appears where you type your home Wi-Fi. Great for giving a flashed board to
someone non-technical.

---

## 5. Build the firmware

Tell ESP-IDF which chip you have (only needed once):

```bash
idf.py set-target esp32       # classic ESP32. Use esp32s3 / esp32c3 / etc. for those chips
```

Then build:

```bash
idf.py build
```

The first build downloads a couple of small dependencies and takes a few
minutes. It's done when you see **"Project build complete."**

---

## 6. Connect the board and find its port

Plug the board into your computer with the USB cable. Now find its serial port:

- **macOS:** `ls /dev/cu.usbserial-* /dev/cu.SLAB_USBtoUART* 2>/dev/null`
  → e.g. `/dev/cu.usbserial-0001`
- **Linux:** `ls /dev/ttyUSB* /dev/ttyACM*`
  → e.g. `/dev/ttyUSB0`
  (you may need: `sudo usermod -a -G dialout $USER`, then log out/in)
- **Windows:** **Device Manager → Ports (COM & LPT)** → look for "Silicon Labs
  CP210x" or "USB-SERIAL CH340" → note the **COMx** number.

If nothing appears, revisit [step 2](#2-install-the-usb-driver-if-needed) or try
a different cable/USB port.

---

## 7. Flash the board

Replace `<PORT>` with what you found above:

```bash
idf.py -p <PORT> flash monitor
```

Examples:
`idf.py -p /dev/cu.usbserial-0001 flash monitor` (macOS),
`idf.py -p /dev/ttyUSB0 flash monitor` (Linux),
`idf.py -p COM5 flash monitor` (Windows).

This writes the firmware and opens a live log. Some boards need you to **hold the
BOOT button** while flashing starts — if it sits at "Connecting…", press and
hold BOOT for a second. Press **`Ctrl-]`** to exit the log viewer.

---

## 8. First boot — find your PocketDNS IP

In the log right after flashing, watch for:

```
I (xxxx) wifi_manager: Got IP: 192.168.0.42
...
I (xxxx) blocklist: Cloud blocklist active: 80000 domains (hash index on flash)
I (xxxx) web_server: HTTP server started - dashboard at http://<device-ip>/
```

**That `Got IP` address is your PocketDNS — write it down.** On the very first
boot it spends ~1 minute downloading and indexing the blocklist in the
background; it's usable immediately and full blocking kicks in once you see
"Cloud blocklist active".

> **Tip:** give the ESP32 a **fixed IP** in your router (a "DHCP reservation" for
> its MAC address) so the address never changes.

If you left Wi-Fi blank (Option B), the log says it's starting the captive
portal — connect your phone to the **`PocketDNS-Setup`** Wi-Fi and follow the
setup page.

---

## Using it

### Point your devices at PocketDNS

Set the **DNS server** on whatever you want filtered to the IP from above:

- **One phone/laptop:** change its Wi-Fi's DNS to the PocketDNS IP.
  - *Android (Samsung etc.):* Settings → Connections → Wi-Fi → ⚙ on your network
    → IP settings → **Static** → set **DNS 1** to the PocketDNS IP.
    **Also turn off "Private DNS"** (Settings → Connections → More connection
    settings → Private DNS → Off) — otherwise your phone bypasses PocketDNS.
  - *Chrome:* also turn off **Settings → Privacy → Use secure DNS**, same reason.
  - *iPhone / Mac / Windows:* set DNS in the Wi-Fi/network settings.
- **Your whole home:** set the DNS server in your **router's** DHCP settings to
  the PocketDNS IP. Now every device is filtered automatically. (Give the ESP32 a
  static IP / DHCP reservation so it doesn't change.)

> **Quick test it's working**, from any computer:
> ```
> nslookup doubleclick.net <PocketDNS-IP>     # should fail / return nothing
> nslookup example.com    <PocketDNS-IP>     # should resolve normally
> ```

### Open the dashboard

Visit **`http://<PocketDNS-IP>/`** in a browser. Default login:

- **Username:** `admin`
- **Password:** `pocketdns`

(Change these before sharing — see [Configuration](#configuration-reference).)

From the dashboard you can see **live stats** and a **24-hour activity graph**,
**block a website**, **upload your own blocklist**, **allow** a domain the
blocklist got wrong, set **parental-control schedules**, and set your
**timezone**.

---

## Configuration reference

Most things are editable live from the dashboard. A few are build-time, in
`sdkconfig.defaults` (or run `idf.py menuconfig` → *PocketDNS …*):

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
                     dns_server    UDP :53 listener
                     dns_parser    DNS packet parsing
                     dns_forwarder upstream resolver (1.1.1.1)
                     dns_cache     TTL-aware response cache
                     blocklist     cloud hash index + manual/custom/allow lists
                     schedule      parental-control time windows + SNTP clock
                     dns_stats     counters + 24h history
  web/           – HTTP dashboard + REST API (single embedded HTML page)
  ota/           – over-the-air update check
```

A DNS query comes in on UDP port 53 → it's parsed → checked against your
allowlist, then your block/custom lists, then the ~80k-domain cloud index
(binary-searched on flash), then any active schedule. If blocked, it returns
`NXDOMAIN`; otherwise it's served from cache or forwarded upstream to `1.1.1.1`,
cached, and returned.

The big blocklist is the interesting part: the multi-megabyte source list is
**hashed as it streams in during download** (never stored whole), and the
resulting 32-bit hashes are kept in sorted buckets **on flash**, so the list
size is bounded by the 4 MB flash chip rather than the ESP32's ~tens of KB of
free RAM.

---

## Troubleshooting

- **`idf.py: command not found`** → you didn't activate ESP-IDF in this terminal.
  Run `. ~/esp/esp-idf/export.sh` again (macOS/Linux), or use the "ESP-IDF CMD"
  shortcut (Windows).
- **Flashing stuck at "Connecting……"** → hold the **BOOT** button as flashing
  begins; release after it starts. Try a different data cable / port, and make
  sure no other program has the port open.
- **"Could not open port" / "port is busy" / port disappears** → close any open
  serial monitor, unplug and replug the board (cheap USB-serial chips drop off
  sometimes), and retry.
- **Board connects but no IP** → use a **2.4 GHz** network (not 5 GHz);
  double-check SSID/password.
- **Dashboard won't load from your computer, but your phone can reach it** →
  your router has **AP/Client Isolation** on (common on guest/mesh networks).
  Turn off "AP Isolation" / "Client Isolation" / "Wireless Isolation".
- **Blocking doesn't seem to work** → almost always **Chrome's "Secure DNS"** or
  Android's **"Private DNS"** is on, bypassing PocketDNS. Turn both off. Also,
  recently-visited sites are cached by your browser/OS for a few minutes.
- **Parental schedules fire at the wrong time** → set your **timezone** in the
  dashboard's Settings; schedules use local time.

---

## Updating and resetting

**Update the firmware** — pull the latest code and re-flash:
```bash
git pull
idf.py build
idf.py -p <PORT> flash
```
(If the project publishes GitHub Releases, the device also updates itself
over-the-air once a day.)

**Wipe everything** (clears saved Wi-Fi, lists, stats — full factory reset):
```bash
idf.py -p <PORT> erase-flash
idf.py -p <PORT> flash
```

**Change the Wi-Fi network later:** the simplest way is the erase-and-reflash
above (which then triggers the captive portal if you didn't bake credentials
in), or edit `sdkconfig.defaults` and re-flash.

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

Issues and pull requests welcome. Good first contributions: confirming an
ESP32-S3/C3 board works, alternate blocklist sources, dashboard improvements,
IPv6/AAAA handling, or a "top blocked domains" view.

## License

MIT — see [LICENSE](LICENSE). Built with [ESP-IDF](https://github.com/espressif/esp-idf)
and [LittleFS](https://github.com/joltwallet/esp_littlefs); blocklist by
[Hagezi](https://github.com/hagezi/dns-blocklists).
