# PocketDNS

A lightweight, Pi-hole-inspired DNS filtering appliance built from scratch on
an **ESP32 (DevKit V1)** with **ESP-IDF v5.5.x**. Not a Pi-hole port — a
ground-up implementation of a DNS server, forwarder, blocklist engine, cache,
web dashboard, and OTA updater.

> **Status:** Feature-complete — all 12 roadmap phases implemented. A working
> DNS ad-blocker with cloud blocklist sync, TTL cache, a dark-mode dashboard
> (auth + whitelist + parental-control schedules), OTA updates, and captive-
> portal Wi-Fi setup.

---

## Phase 1: what this build does

1. Initialises **NVS** (needed later by the Wi-Fi stack).
2. Mounts a **LittleFS** filesystem on a dedicated flash partition.
3. Reads/increments/writes a **boot counter** to prove data survives reboot.

No Wi-Fi or DNS yet — this phase verifies the foundation: build system,
flash partitioning, filesystem, and persistence.

---

## Prerequisites

- ESP-IDF **v5.5.x** installed and exported (`. $IDF_PATH/export.sh`)
- An ESP32 DevKit V1 and a USB cable
- Your serial port (e.g. `/dev/ttyUSB0` on Linux, `/dev/cu.usbserial-*` on
  macOS, `COMx` on Windows)

## Build, flash, and watch

```bash
# 1. one-time: tell IDF this is a classic ESP32
idf.py set-target esp32

# 2. (optional) confirm your flash size really is 4 MB
idf.py -p <PORT> flash_id

# 3. build (the component manager auto-downloads LittleFS here)
idf.py build

# 4. flash + open the serial monitor in one go
idf.py -p <PORT> flash monitor      # Ctrl-] to exit the monitor
```

### Expected output

```
I (xxx) pocketdns: === PocketDNS booting (Phase 1) ===
I (xxx) pocketdns: No boot counter file yet - first ever boot
I (xxx) pocketdns: LittleFS mounted at /littlefs | used 8192 / 851968 bytes (0%)
I (xxx) pocketdns: >>> This device has booted 1 time(s) <<<
I (xxx) pocketdns: Free heap: ~290000 bytes
I (xxx) pocketdns: Phase 1 complete. Press the RESET button and watch the count rise.
```

**The test:** press the **EN/RESET** button on the board. The counter should
read `2`, then `3`, ... That rising number is your proof that flash +
filesystem + persistence all work.

---

## Flash map (`partitions.csv`)

| Partition | Purpose                          | Size   |
|-----------|----------------------------------|--------|
| nvs       | Wi-Fi/config key-value store     | 24 KB  |
| otadata   | which OTA slot is active         | 8 KB   |
| phy_init  | RF calibration data              | 4 KB   |
| ota_0     | app slot A                       | 1.5 MB |
| ota_1     | app slot B (for OTA rollback)    | 1.5 MB |
| littlefs  | blocklist, config, web assets    | 832 KB |
| coredump  | reserved for crash dumps         | 64 KB  |

Designed OTA-ready up front so we never have to repartition (which erases the
whole chip).

---

## Roadmap

1. ✅ Skeleton + LittleFS persistence
2. ✅ Wi-Fi manager
3. ✅ Raw UDP socket on :53
4. ✅ DNS packet parser
5. ✅ Upstream forwarder (1.1.1.1) — working DNS proxy
6. ✅ Blocklist + whitelist — **it blocks ads**
7. ✅ TTL-aware cache
8. ✅ Statistics + logging
9. ✅ HTTP server + dark-mode dashboard + REST API
10. ✅ Cloud blocklist sync (daily, conditional)
11. ✅ OTA firmware updates
12. ✅ Polish: auth, captive portal, parental controls

---

## Using it

Point a device's DNS at the PocketDNS IP (shown in the serial log as `Got IP`)
and it filters ads for that device. Open `http://<that-ip>/` for the dashboard
(default login `admin` / `pocketdns`, changeable in `idf.py menuconfig` →
*PocketDNS Web Dashboard*). The dashboard shows live stats and lets you:

- **Whitelist** domains the blocklist gets wrong (persisted to flash).
- Set **parental-control schedules** — block a domain during a daily time
  window, e.g. `youtube.com` from 21:00–07:00. Set your timezone via
  `menuconfig` → *PocketDNS DNS / Schedules* so windows use local time.

**Wi-Fi setup:** credentials in `menuconfig` are used as a default/seed. If
none are set (or a saved network can't be joined), the device starts a
`PocketDNS-Setup` Wi-Fi access point — connect to it from a phone, and a setup
page lets you enter your home Wi-Fi; the device saves it and reboots to join.

**OTA updates:** the device checks this repo's GitHub Releases daily and
installs a `pocketdns.bin` asset whose release tag differs from the running
`version.txt`.

## Blocklist engine

The cloud blocklist holds ~80,000 ad/tracker domains (Hagezi's list), stored as
32-bit hashes in sorted buckets **on flash**, not in RAM — so list size is
bounded by the 4 MB flash, not the ESP32's ~tens of KB of free heap. The
multi-MB source is **stream-hashed during download** (never stored whole), and
lookups binary-search each parent suffix of the queried name on flash. Add your
own domains via the dashboard's *Block a website* box; those (and the whitelist)
are checked first, in RAM.

### What DNS blocking can and can't do (read before claiming "blocks all ads")

This is a **DNS** filter, like Pi-hole. It blocks third-party ad/tracker
**domains**. It fundamentally **cannot**:

- **Block YouTube ads** — they're served from `googlevideo.com`, the same
  domain as the videos; DNS can't tell ad from content, and the stream is
  encrypted. No DNS blocker (Pi-hole, AdGuard-DNS, NextDNS) can do this. Only
  in-app/in-browser blockers (uBlock Origin, Brave, ReVanced) can, because they
  run inside the client with the decrypted page.
- **Block first-party ads** served from the same domain as the content (common
  on news sites) — same reason.
