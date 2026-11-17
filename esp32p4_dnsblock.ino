// DNS ad/malware blocker for the Guition JC-ESP32P4-M3 (ESP32-P4, Ethernet).
//
// Answers 0.0.0.0 / :: for domains in the StevenBlack hosts list and relays
// everything else to an upstream resolver. The list is downloaded on the PC
// by tools/update_blocklist.py into blocklist_data.h, compiled into the
// firmware as a sorted table in flash, and binary-searched in place.
//
// Arduino IDE settings (Tools menu):
//   Board:            ESP32P4 Dev Module
//   Flash Size:       16MB
//   Partition Scheme: Custom (uses this sketch's partitions.csv, 6 MB app)
//
// Serial commands (115200 baud):
//   check <domain>  show whether a domain is blocked
//   stats           print counters

#include <ETH.h>
#include "config.h"
#include "blocklist.h"
#include "dns_server.h"

static void onNetworkEvent(arduino_event_id_t event, arduino_event_info_t) {
  switch (event) {
    case ARDUINO_EVENT_ETH_START:
      ETH.setHostname("dnsblock");
      break;
    case ARDUINO_EVENT_ETH_CONNECTED:
      Serial.printf("[eth] link up, %u Mbps %s duplex\n", ETH.linkSpeed(), ETH.fullDuplex() ? "full" : "half");
      break;
    case ARDUINO_EVENT_ETH_GOT_IP:
      Serial.printf("[eth] IP %s  gateway %s\n", ETH.localIP().toString().c_str(), ETH.gatewayIP().toString().c_str());
      break;
    case ARDUINO_EVENT_ETH_LOST_IP:
    case ARDUINO_EVENT_ETH_DISCONNECTED:
    case ARDUINO_EVENT_ETH_STOP:
      Serial.println("[eth] down");
      break;
    default:
      break;
  }
}

static void printStats() {
  DnsServer::Stats s = DnsServer::stats();
  Serial.printf("[stats] queries %u, blocked %u, forwarded %u, answered %u, timeouts %u, malformed %u | heap %u\n",
                (unsigned)s.queries, (unsigned)s.blocked, (unsigned)s.forwarded, (unsigned)s.answered,
                (unsigned)s.timeouts, (unsigned)s.malformed, (unsigned)ESP.getFreeHeap());
}

static void handleSerial() {
  static String line;
  while (Serial.available()) {
    char c = Serial.read();
    if (c != '\n' && c != '\r') {
      line += c;
      continue;
    }
    line.trim();
    if (line.startsWith("check ")) {
      String d = line.substring(6);
      d.trim();
      uint32_t t0 = micros();
      bool b = Blocklist::isBlocked(d.c_str());
      Serial.printf("%s: %s (%lu us)\n", d.c_str(), b ? "BLOCKED" : "allowed", (unsigned long)(micros() - t0));
    } else if (line == "stats") {
      printStats();
    } else if (line.length()) {
      Serial.println("commands: check <domain> | stats");
    }
    line = "";
  }
}

void setup() {
  Serial.begin(115200);
  delay(500);
  Serial.printf("\nESP32-P4 DNS blocker: %u domains (list from %s)\n", (unsigned)Blocklist::count(),
                Blocklist::created());

  Network.onEvent(onNetworkEvent);
  if (!ETH.begin()) {  // IP101 on the variant's default RMII/MDIO pins
    Serial.println("ETH.begin() failed");
  }
#if USE_STATIC_IP
  ETH.config(IPAddress(STATIC_IP), IPAddress(STATIC_GATEWAY), IPAddress(STATIC_SUBNET), IPAddress(UPSTREAM_DNS));
#endif

  if (!DnsServer::begin(IPAddress(UPSTREAM_DNS))) {
    Serial.println("DNS server failed to start");
  }
}

void loop() {
  handleSerial();
  static uint32_t lastStats = 0;
  if (millis() - lastStats > 60000) {
    lastStats = millis();
    printStats();
  }
  delay(10);
}
