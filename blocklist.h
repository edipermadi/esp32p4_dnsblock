#pragma once
#include <Arduino.h>

// Sorted domain list compiled into the firmware (blocklist_data.h, generated
// by tools/update_blocklist.py). It lives in flash (.rodata) and is searched
// in place with binary search.
namespace Blocklist {

// Number of domains in the list.
uint32_t count();

// When the list was generated.
const char *created();

// Check a domain (any case, optional trailing dot). With BLOCK_SUBDOMAINS
// the parent domains are checked as well.
bool isBlocked(const char *domain);

}  // namespace Blocklist
