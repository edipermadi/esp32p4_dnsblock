#pragma once
#include <Arduino.h>

namespace DnsServer {

struct Stats {
  uint32_t queries;
  uint32_t blocked;
  uint32_t forwarded;
  uint32_t answered;   // upstream replies relayed to clients
  uint32_t timeouts;   // forwarded queries that got no reply
  uint32_t malformed;
};

// Start the UDP DNS server on port 53 in its own task. Queries for blocked
// domains get 0.0.0.0 (A) / :: (AAAA) / empty answer (other types); all
// others are relayed to the upstream resolver.
bool begin(IPAddress upstream);

Stats stats();

}  // namespace DnsServer
