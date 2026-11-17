#include "blocklist.h"
#include "blocklist_data.h"
#include "config.h"

namespace Blocklist {
namespace {

constexpr size_t kMaxDomainLen = 253;

bool findExact(const char *name) {
  uint32_t lo = 0, hi = BLOCKLIST_COUNT;
  while (lo < hi) {
    uint32_t mid = lo + (hi - lo) / 2;
    int c = strcmp(name, BLOCKLIST_STRINGS + BLOCKLIST_INDEX[mid]);
    if (c == 0) {
      return true;
    }
    if (c < 0) {
      hi = mid;
    } else {
      lo = mid + 1;
    }
  }
  return false;
}

}  // namespace

uint32_t count() {
  return BLOCKLIST_COUNT;
}

const char *created() {
  return BLOCKLIST_CREATED;
}

bool isBlocked(const char *domain) {
  char name[kMaxDomainLen + 1];
  size_t len = 0;
  for (; domain[len] && len < kMaxDomainLen; len++) {
    char c = domain[len];
    name[len] = (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
  }
  if (domain[len]) {
    return false;  // too long to be in the list
  }
  while (len && name[len - 1] == '.') len--;
  name[len] = 0;
  if (len == 0) {
    return false;
  }

  const char *p = name;
  while (true) {
    if (findExact(p)) {
      return true;
    }
#if BLOCK_SUBDOMAINS
    const char *dot = strchr(p, '.');
    // Stop before the bare TLD ("com").
    if (!dot || !strchr(dot + 1, '.')) {
      return false;
    }
    p = dot + 1;
#else
    return false;
#endif
  }
}

}  // namespace Blocklist
