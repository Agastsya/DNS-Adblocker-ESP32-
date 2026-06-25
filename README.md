# PocketDNS

**A network-wide ad and tracker blocker that runs on a $5 ESP32.**

PocketDNS is a tiny, Pi-hole-style DNS filter built from scratch for the
ESP32. Plug it into power, point your phone, laptop, or whole router at it,
and it quietly blocks tens of thousands of ad and tracker domains across
every app and browser on your network. Nothing to install on your devices,
no subscription, no cloud account.

It comes with a clean web dashboard (live stats, a 24-hour activity graph,
and controls for blocking, allowing, scheduling, and uploading your own
lists), a captive-portal Wi-Fi setup so non-technical people can get it
online from their phone, and over-the-air updates.

---

## Contents

- [Read this first: what DNS blocking can and can't do](#read-this-first-what-dns-blocking-can-and-cant-do)
- [Features](#features)
- [Quick install: flash from your browser](#quick-install-flash-from-your-browser)
- [Compatibility: which ESP32 boards work](#compatibility-which-esp32-boards-work)
- [What you need](#what-you-need)
- **Build from source (developers)**
  - [1. Install the ESP-IDF toolchain](#1-install-the-esp-idf-toolchain)
  - [2. Install the USB driver (if needed)](#2-install-the-usb-driver-if-needed)
  - [3. Download PocketDNS](#3-download-pocketdns)
  - [4. Configure Wi-Fi and timezone](#4-configure-wi-fi-and-timezone)
  - [5. Build the firmware](#5-build-the-firmware)
  - [6. Connect the board and find its port](#6-connect-the-board-and-find-its-port)
  - [7. Flash the board](#7-flash-the-board)
  - [8. First boot: find your PocketDNS IP](#8-first-boot-find-your-pocketdns-ip)
- [Using it](#using-it)
- [Configuration reference](#configuration-reference)
- [How it works (architecture)](#how-it-works-architecture)
- [Troubleshooting](#troubleshooting)
- [Updating and resetting](#updating-and-resetting)
- [Limitations and honesty](#limitations-and-honesty)
- [Why I built this](#why-i-built-this)
- [Contributing](#contributing)

---

## Read this first: what DNS blocking can and can't do

PocketDNS is a DNS blocker, exactly like Pi-hole, AdGuard DNS, and NextDNS.
It's worth being upfront about the limits, because they're the same for
every DNS-based blocker, not just this one.

| What it blocks | What it can't block |
|---|---|
| Third-party ad networks (DoubleClick, Criteo, OpenX, and similar) | Ads served from the same domain as the page itself (rare, but it happens) |
| Trackers and analytics (Google Analytics, Segment, and similar) | Anything inside an app that uses its own DNS instead of your network's |
| Telemetry and "phone home" domains baked into apps | |
| Malware and phishing domains, depending on the list | |

**Why not YouTube ads?** YouTube serves its ads from `googlevideo.com`, the
exact same domain as the actual videos, over an encrypted connection. A DNS
blocker only ever sees domain names, never the content behind them, so it
has no way to tell an ad apart from a video. Blocking that domain would just
kill YouTube entirely. This is why no DNS blocker, Pi-hole included, stops
YouTube ads. Only in-browser blockers like uBlock Origin or Brave manage it,
because they run inside the browser where the page is already decrypted.
PocketDNS can't be that, and neither can any other network-level box.

If what you want is network-wide blocking of ad and tracker domains,
PocketDNS does that well. If you specifically want YouTube ads gone, you'll
need a browser extension or a patched app, not a DNS tool.

---

## Features

- **Roughly 80,000-domain blocklist** (Hagezi's list), refreshed daily,
  stored as a hash index on flash so it isn't limited by the ESP32's tiny
  amount of RAM.
- **Block any site yourself** from the dashboard, or paste/upload your own
  list of domains.
- **Allowlist** to un-block anything the blocklist caught by mistake.
- **Parental-control schedules**, block a domain during a daily time window
  (social media from 9 PM to 7 AM, for example), evaluated in your local
  timezone.
- **Web dashboard** with live query/blocked/cache stats, a 24-hour activity
  graph, and every control listed above. Works fine from a phone.
- **Captive-portal Wi-Fi setup**, so if you don't bake your credentials in
  ahead of time, the device makes its own hotspot and lets you enter your
  Wi-Fi from a phone instead.
- **Over-the-air updates** from GitHub Releases.
- **Password-protected dashboard**, a TTL-aware cache, and stats that
  persist across reboots.

---

## Quick install: flash from your browser

The easy way, no software and no command line. Open the flasher page in a
desktop browser, plug in your ESP32, and click install.

### [Open the PocketDNS Web Flasher](https://agastsya.github.io/DNS-Adblocker-ESP32-/)

Here's the whole process:

1. Plug your ESP32 into your computer with a USB data cable.
2. Open the flasher (link above) in Chrome, Edge, or Opera on a desktop or
   laptop. These are the browsers that support flashing over USB through Web
   Serial. Safari, Firefox, and phones can't flash a board, so use one of
   the three above.
3. Click Install, pick your board's port, and wait about a minute. If it
   sits on "Connecting..." for more than a few seconds, hold the BOOT button
   on the board for a second or two. That's usually enough to nudge it into
   flashing mode.
4. Once it's done, the board starts its own Wi-Fi hotspot called
   `PocketDNS-Setup`. Connect your phone to that network. A setup page
   should pop up automatically; if it doesn't, open a browser and go to
   `192.168.4.1` yourself. Enter your home Wi-Fi name and password there.
5. The board joins your home network. Find its IP from your router's device
   list, point your devices' DNS at it, and open `http://<that-ip>/` for the
   dashboard. See [Using it](#using-it) below.

If something acts up partway through, a hard refresh of the flasher page
(Ctrl+Shift+R) or clearing the browser cache and trying again fixes it more
often than you'd expect, before you go assuming the board itself is broken.

No ESP-IDF, no terminal. Prefer building it yourself? See
[Build from source](#1-install-the-esp-idf-toolchain) below.

<details>
<summary><b>Repo owner: one-time setup to make the web flasher live</b></summary>

The flasher is built and published automatically by GitHub Actions
([`.github/workflows/deploy-flasher.yml`](.github/workflows/deploy-flasher.yml)).
To turn it on once:

1. Push this repo to GitHub.
2. Go to **Settings → Pages** and set **Source** to **GitHub Actions**.
3. Push to `main` (or run the workflow manually under the **Actions** tab).

GitHub then compiles the firmware in the cloud and serves the flasher at
`https://<your-username>.github.io/<your-repo>/`. It rebuilds on every push,
so the downloadable firmware always matches your latest code. The published
binary ships with blank Wi-Fi, so every user who flashes it gets the
captive-portal setup; no secrets are baked into the public build.
</details>

---

## Compatibility: which ESP32 boards work

PocketDNS needs three things from a board: Wi-Fi, at least 4 MB of flash,
and support for ESP-IDF v5.5.

### Fully supported and tested

| Chip | Typical boards | Notes |
|---|---|---|
| **ESP32** (classic, "ESP32-WROOM-32") | ESP32 DevKit V1 / DOIT, NodeMCU-32S, WeMos/LOLIN D32, ESP32-WROVER | What PocketDNS is built and tested on. Recommended. Use a 4 MB flash version (almost all are). |

If you're buying a board specifically for this, get a classic ESP32 DevKit
V1 with 4 MB flash. It's about $5, it's everywhere, and it's exactly what's
been tested.

### Should work, but untested (you change one setting)

These chips have Wi-Fi and run ESP-IDF v5.5, and PocketDNS uses no
chip-specific code, so it should build and run fine. You just tell the build
which chip you have (`idf.py set-target esp32s3`, and so on):

| Chip | Notes |
|---|---|
| **ESP32-S3** | Dual-core, lots of RAM. Should work great. Needs 4 MB+ flash. |
| **ESP32-S2** | Single-core, Wi-Fi only. Should work. |
| **ESP32-C3** | RISC-V, single-core, Wi-Fi + BLE. Should work. |
| **ESP32-C6** | Wi-Fi 6 + BLE. Should work on recent ESP-IDF. |
| **ESP32-C2 (ESP8684)** | Low-cost; needs a 4 MB variant. |

### Not supported

| Chip / board | Why |
|---|---|
| **ESP32-H2** | No Wi-Fi (Thread/Zigbee/BLE only). |
| **ESP8266** | Older chip, different SDK (not ESP-IDF v5). Would need a separate port. |
| **Any board with under 4 MB flash** (2 MB modules) | Firmware, dual OTA slots, and the filesystem together need 4 MB. |

**Check your flash size:** with the board plugged in, run
`idf.py -p <PORT> flash_id`. The `Detected flash size` line needs to say
4MB or more.

**USB-to-serial chip** (this only matters for flashing): boards use either a
CP2102/CP2104 (Silicon Labs) or CH340/CH9102 (WCH) chip. Some operating
systems need a driver for these; see
[step 2](#2-install-the-usb-driver-if-needed).

---

## What you need

- A compatible ESP32 board (see above), 4 MB flash, with Wi-Fi.
- A USB data cable (it has to carry data; a lot of cheap cables are
  charge-only).
- A computer running macOS, Linux, or Windows.
- Your home Wi-Fi name and password (2.4 GHz; the ESP32 doesn't do 5 GHz).
- About 1 GB of free disk space for the toolchain, if you're building from
  source.

---

# Build from source (developers)

> Most people should use the
> [browser flasher](#quick-install-flash-from-your-browser) above; it needs
> none of this. Build from source if you want to change the code, use a
> non-ESP32 chip, or bake your Wi-Fi into the firmware. The steps below take
> about 30 to 45 minutes, most of it the one-time ESP-IDF install.

## 1. Install the ESP-IDF toolchain

ESP-IDF is Espressif's official development framework. PocketDNS uses
v5.5.x. Install it with the official installer for your OS:

**https://docs.espressif.com/projects/esp-idf/en/v5.5/esp32/get-started/**

Quick summary per OS:

**Windows (easiest):** download the ESP-IDF Windows Installer from the link
above, pick v5.5, and let it install everything (Python, toolchain, Git). It
creates an "ESP-IDF CMD" (and PowerShell) shortcut; use that for all the
commands below.

**macOS / Linux:**

```bash
mkdir -p ~/esp && cd ~/esp
git clone -b v5.5.4 --recursive https://github.com/espressif/esp-idf.git
cd esp-idf
./install.sh esp32
```

After installing, you activate ESP-IDF in your terminal so the `idf.py`
command works. Do this once per terminal session:

```bash
# macOS / Linux
. ~/esp/esp-idf/export.sh
# Windows: just open the "ESP-IDF CMD" shortcut, it's already activated
```

You'll know it worked when `idf.py --version` prints something like
`ESP-IDF v5.5.4`.

---

## 2. Install the USB driver (if needed)

When you plug in the board, your computer needs to recognize its
USB-serial chip. Plug it in first; if a new serial port shows up (see
[step 6](#6-connect-the-board-and-find-its-port)), you can skip this step.

If it doesn't show up, install the driver for your board's chip:

- **CP2102 / CP2104:** Silicon Labs "CP210x VCP" driver,
  https://www.silabs.com/developers/usb-to-uart-bridge-vcp-drivers
- **CH340 / CH9102:** WCH driver, http://www.wch-ic.com/downloads/CH341SER_ZIP.html
  (on macOS, search "CH340 macOS driver").

> Recent macOS and Linux usually have the CP2102 driver built in already.
> CH340 more often needs a manual install.

---

## 3. Download PocketDNS

In your activated ESP-IDF terminal:

```bash
git clone https://github.com/Agastsya/DNS-Adblocker-ESP32-.git
cd DNS-Adblocker-ESP32-
```

---

## 4. Configure Wi-Fi and timezone

There are two ways to set the Wi-Fi. Pick one.

### Option A: edit one file (simplest)

Open `sdkconfig.defaults` in any text editor and fill in your network:

```ini
CONFIG_POCKETDNS_WIFI_SSID="YourWiFiName"
CONFIG_POCKETDNS_WIFI_PASSWORD="YourWiFiPassword"
```

While you're there, set your timezone too (used for parental-control
schedules); more examples are in the file:

```ini
CONFIG_POCKETDNS_TIMEZONE="IST-5:30"     # India. UK: "GMT0BST,M3.5.0/1,M10.5.0"
```

> Use a 2.4 GHz network name. The ESP32 cannot connect to 5 GHz Wi-Fi.

### Option B: set it up from your phone after flashing (no editing)

Leave the two Wi-Fi lines blank. After flashing, the device creates its own
Wi-Fi hotspot named `PocketDNS-Setup`. Connect your phone to it and a setup
page appears where you type in your home Wi-Fi. This is the better option
if you're handing a flashed board to someone non-technical.

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
minutes. You'll know it's done when you see "Project build complete."

---

## 6. Connect the board and find its port

Plug the board into your computer with the USB cable, then find its serial
port:

- **macOS:** `ls /dev/cu.usbserial-* /dev/cu.SLAB_USBtoUART* 2>/dev/null`
  gives you something like `/dev/cu.usbserial-0001`
- **Linux:** `ls /dev/ttyUSB* /dev/ttyACM*`
  gives you something like `/dev/ttyUSB0`
  (you may need `sudo usermod -a -G dialout $USER`, then log out and back in)
- **Windows:** Device Manager → Ports (COM & LPT) → look for "Silicon Labs
  CP210x" or "USB-SERIAL CH340" → note the COMx number.

If nothing shows up, go back to
[step 2](#2-install-the-usb-driver-if-needed), or try a different
cable or USB port.

---

## 7. Flash the board

Replace `<PORT>` with what you found above:

```bash
idf.py -p <PORT> flash monitor
```

For example:
`idf.py -p /dev/cu.usbserial-0001 flash monitor` on macOS,
`idf.py -p /dev/ttyUSB0 flash monitor` on Linux,
`idf.py -p COM5 flash monitor` on Windows.

This writes the firmware and opens a live log. Some boards need you to hold
the BOOT button while flashing starts. If it sits at "Connecting...", press
and hold BOOT for a second. Press `Ctrl-]` to exit the log viewer when
you're done.

---

## 8. First boot: find your PocketDNS IP

Right after flashing, watch the log for:

```
I (xxxx) wifi_manager: Got IP: 192.168.0.42
...
I (xxxx) blocklist: Cloud blocklist active: 80000 domains (hash index on flash)
I (xxxx) web_server: HTTP server started - dashboard at http://<device-ip>/
```

That `Got IP` address is your PocketDNS box. Write it down. On the very
first boot it spends about a minute downloading and indexing the blocklist
in the background; it's usable immediately, and full blocking kicks in once
you see "Cloud blocklist active."

> **Tip:** give the ESP32 a fixed IP in your router (a DHCP reservation for
> its MAC address) so the address never changes on you later.

If you left Wi-Fi blank (Option B), the log says it's starting the captive
portal instead. Connect your phone to the `PocketDNS-Setup` Wi-Fi and follow
the setup page that appears.

---

## Using it

### Point your devices at PocketDNS

Set the DNS server on whatever you want filtered to the IP from above.
There are two ways to do this, and this is the step people most often get
wrong, so it's worth reading both options before picking one.

**Option 1: change it on your router (the one most people use).** Log into
your router's admin page, usually at `192.168.0.1` or `192.168.1.1` (check
the label on the router itself if you're not sure), and set its DHCP DNS
server to your PocketDNS IP. Every device on the network picks this up
automatically, including new ones that join later. This is the simplest
option if you want the whole house covered.

**Option 2: change it on each device individually**, in that device's
Wi-Fi or network settings. This works fine too, but you'll need to repeat
it on every phone, laptop, and tablet you own, and it won't apply to
anything new that joins the network afterward.

Either way, once it's set, your traffic flows like this for DNS lookups:

```
your phone or laptop -> PocketDNS (ESP32) -> your router -> the internet
```

Device-specific notes:

- **Android (Samsung and similar):** Settings > Connections > Wi-Fi > the
  settings icon on your network > IP settings > Static > set DNS 1 to the
  PocketDNS IP. Also turn off "Private DNS" (Settings > Connections > More
  connection settings > Private DNS > Off), otherwise your phone bypasses
  PocketDNS entirely.
- **Chrome:** also turn off Settings > Privacy > Use secure DNS, for the
  same reason.
- **iPhone / Mac / Windows:** set the DNS server in the Wi-Fi or network
  settings.

> **Quick way to test it's working**, from any computer:
> ```
> nslookup doubleclick.net <PocketDNS-IP>     # should fail / return nothing
> nslookup example.com    <PocketDNS-IP>     # should resolve normally
> ```

### Open the dashboard

Visit `http://<PocketDNS-IP>/` in a browser. Default login:

- **Username:** `admin`
- **Password:** `pocketdns`

You should change these before giving the dashboard URL to anyone else; see
[Configuration reference](#configuration-reference).

From the dashboard you can see live stats and a 24-hour activity graph,
block a website, upload your own blocklist, allow a domain the blocklist
got wrong, set parental-control schedules, and set your timezone.

---

## Configuration reference

Most things are editable live from the dashboard. A few are build-time, set
in `sdkconfig.defaults` (or through `idf.py menuconfig` under
*PocketDNS ...*):

| Setting | Where | Notes |
|---|---|---|
| Wi-Fi SSID / password | `sdkconfig.defaults` or captive portal | |
| Dashboard username / password | `menuconfig` → *PocketDNS Web Dashboard* | change this from the default |
| Timezone | dashboard Settings, or `sdkconfig.defaults` | used for schedules |
| Blocklist source URL | `components/dns/blocklist.c` (`BLOCKLIST_URL`) | any plain domain-per-line list works |

---

## How it works (architecture)

PocketDNS is a from-scratch implementation, organized as ESP-IDF
components:

```
main/            startup orchestration
components/
  storage/       LittleFS filesystem + persistence
  wifi/          Wi-Fi station + captive-portal setup AP
  dns/           the DNS engine:
                   dns_server     UDP/TCP :53 listener
                   dns_parser     DNS packet parsing
                   dns_forwarder  upstream resolver
                   dns_cache      TTL-aware response cache
                   blocklist      cloud hash index + manual/custom/allow lists
                   schedule       parental-control time windows + SNTP clock
                   dns_stats      counters + 24h history
  web/           HTTP dashboard + REST API (single embedded HTML page)
  ota/           over-the-air update check
```

A DNS query comes in on port 53, gets parsed, and is checked against your
allowlist, then your block/custom lists, then the roughly 80,000-domain
cloud index (binary-searched on flash), then any active schedule. If it's
blocked, PocketDNS returns NXDOMAIN. Otherwise the answer comes from cache
or gets forwarded upstream, gets cached, and is returned to whoever asked.

The blocklist is the part I'm most pleased with. The multi-megabyte source
list is hashed as it streams in during download, so the whole thing is
never held in memory at once, and the resulting hashes are kept in sorted
buckets on flash. That means the list size is bounded by the 4 MB flash
chip, not by the ESP32's tiny amount of free RAM.

---

## Troubleshooting

- **`idf.py: command not found`**: you haven't activated ESP-IDF in this
  terminal yet. Run `. ~/esp/esp-idf/export.sh` again on macOS or Linux, or
  use the "ESP-IDF CMD" shortcut on Windows.
- **Flashing stuck at "Connecting..."**: hold the BOOT button as flashing
  begins and let go once it starts. If that doesn't help, try a different
  data cable or USB port, and make sure no other program (a serial monitor,
  for instance) already has the port open.
- **"Could not open port" / "port is busy" / the port disappears**: close
  any open serial monitor, unplug and replug the board (the cheap
  USB-serial chips on some boards do this from time to time), and try
  again.
- **Board connects but never gets an IP**: make sure you're on a 2.4 GHz
  network, not 5 GHz, and double-check the SSID and password.
- **Dashboard won't load from your computer, but your phone can reach it**:
  your router probably has AP or Client Isolation turned on, which is
  common on guest networks and mesh systems. Turn off "AP Isolation,"
  "Client Isolation," or "Wireless Isolation" in the router settings.
- **Blocking doesn't seem to be doing anything**: almost always Chrome's
  "Secure DNS" or Android's "Private DNS" is switched on somewhere, which
  bypasses PocketDNS since the device picks its own resolver instead of
  using whatever the network hands it. Turn both off. Also keep in mind
  your browser and OS cache recently visited sites for a few minutes on
  their own.
- **Parental schedules fire at the wrong time**: set your timezone in the
  dashboard's Settings tab; schedules are evaluated in local time.

---

## Updating and resetting

**Update the firmware**, pull the latest code and re-flash:
```bash
git pull
idf.py build
idf.py -p <PORT> flash
```
(If the project has published GitHub Releases, the device also checks for
updates and applies them over-the-air once a day.)

**Wipe everything** (clears saved Wi-Fi, lists, and stats; a full factory
reset):
```bash
idf.py -p <PORT> erase-flash
idf.py -p <PORT> flash
```

**Change the Wi-Fi network later:** the simplest way is the erase-and-flash
above, which then triggers the captive portal if you didn't bake
credentials in. You can also just edit `sdkconfig.defaults` and re-flash.

---

## Limitations and honesty

- Can't block YouTube ads or other first-party ads (see the section near
  the top; this is true of every DNS blocker, not a gap specific to this
  one).
- Best suited to a personal or home network. The ESP32 isn't a
  high-throughput resolver. It's plenty for a household, not an office with
  hundreds of people.
- The daily blocklist rebuild takes about a minute in the background (the
  device keeps serving from a small built-in list during that window, so
  nothing actually goes unprotected).

---

## Why I built this

I picked up an ESP32 a while back because I wanted to learn more about
microcontrollers, and once it was sitting on my desk I started looking into
what people actually build with these things. That's how I found
network-wide ad blockers, the kind that block ads, trackers, and malware
across an entire network instead of just one browser. Almost everything I
found doing this well was built for something more powerful, like a
Raspberry Pi. Nobody seemed to be doing it on something as small and cheap
as an ESP32, so I decided to try it myself.

PocketDNS is what came out of that. It's built from scratch in C against
ESP-IDF: its own DNS parser, its own blocklist index living on flash instead
of RAM so it isn't boxed in by the chip's tiny amount of memory, and a
dashboard that doesn't need an app or an account to use. If you end up
trying it, I'd genuinely like to hear how it goes for you, good or bad.

---

## Contributing

Issues and pull requests welcome. Good first contributions: confirming an
ESP32-S3/C3 board works, alternate blocklist sources, dashboard
improvements, IPv6/AAAA handling, or a "top blocked domains" view.

## License

MIT. See [LICENSE](LICENSE) for details. Built with
[ESP-IDF](https://github.com/espressif/esp-idf) and
[LittleFS](https://github.com/joltwallet/esp_littlefs); blocklist by
[Hagezi](https://github.com/hagezi/dns-blocklists).
