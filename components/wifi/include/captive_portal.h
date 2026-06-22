#pragma once

/* Bring up a "PocketDNS-Setup" SoftAP and serve a Wi-Fi setup form.
 * A catch-all DNS responder points every lookup at the device so phones
 * pop the captive-portal page automatically. When the user submits their
 * home SSID/password, it's saved to NVS and the device reboots to join
 * that network. This call does not return (it runs until the reboot). */
void captive_portal_run(void);
