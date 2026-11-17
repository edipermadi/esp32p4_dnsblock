#pragma once

// ---------------------------------------------------------------------------
// Network (on-board Ethernet only; Wi-Fi is not used)
// ---------------------------------------------------------------------------
// The IP101 PHY pins come from the "ESP32P4 Dev Module" variant defaults:
// MDC 31, MDIO 52, PHY reset 51, PHY address 1, RMII clock in on GPIO50.

// A DNS server should have a fixed address. Set to 0 to use DHCP instead.
#define USE_STATIC_IP 1
#define STATIC_IP      192, 168, 1, 53
#define STATIC_GATEWAY 192, 168, 1, 1
#define STATIC_SUBNET  255, 255, 255, 0

// Where queries for domains that are not blocked get forwarded.
#define UPSTREAM_DNS 1, 1, 1, 1

// ---------------------------------------------------------------------------
// Blocklist (compiled in from blocklist_data.h; refresh it with
// tools/update_blocklist.py and re-upload)
// ---------------------------------------------------------------------------
// 1 = also block subdomains of listed domains (x.ads.example.com is blocked
//     when ads.example.com is listed). 0 = exact match, like a hosts file.
#define BLOCK_SUBDOMAINS 1

// TTL (seconds) of the 0.0.0.0 / :: answers for blocked domains.
#define BLOCKED_TTL 300
