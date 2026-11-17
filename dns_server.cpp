#include "dns_server.h"
#include "blocklist.h"
#include "config.h"

#include <lwip/sockets.h>

namespace DnsServer {
namespace {

constexpr uint16_t kPort = 53;
constexpr size_t kBufSize = 4096;            // room for EDNS-sized replies
constexpr uint32_t kUpstreamTimeoutMs = 5000;
constexpr int kMaxPending = 256;             // low byte of the upstream ID

constexpr uint16_t kTypeA = 1;
constexpr uint16_t kTypeAAAA = 28;
constexpr uint16_t kTypeANY = 255;
constexpr uint16_t kClassIN = 1;

struct Pending {
  bool used;
  uint16_t upId;      // ID sent upstream
  uint16_t clientId;  // ID the client used
  sockaddr_in client;
  uint32_t ts;
};

int g_srv = -1;
int g_up = -1;
sockaddr_in g_upstream;
Pending g_pending[kMaxPending];
uint8_t g_nextSlot = 0;
Stats g_stats;  // written only by the DNS task

inline uint16_t rd16(const uint8_t *p) {
  return (uint16_t)(p[0] << 8 | p[1]);
}
inline void wr16(uint8_t *p, uint16_t v) {
  p[0] = v >> 8;
  p[1] = v & 0xFF;
}

// Parse the single question. Returns false if the packet should not be
// treated as a blockable query (it is then simply forwarded).
bool parseQuestion(const uint8_t *buf, size_t len, char *name, size_t *qEnd, uint16_t *qtype, uint16_t *qclass) {
  size_t pos = 12, nl = 0;
  while (true) {
    if (pos >= len) {
      return false;
    }
    uint8_t l = buf[pos++];
    if (l == 0) {
      break;
    }
    if ((l & 0xC0) || pos + l > len || nl + l + 1 > 254) {
      return false;  // compression in the question or oversized name
    }
    if (nl) {
      name[nl++] = '.';
    }
    for (uint8_t i = 0; i < l; i++) {
      char c = (char)buf[pos + i];
      if (c == 0 || c == '.') {
        return false;
      }
      name[nl++] = c;
    }
    pos += l;
  }
  name[nl] = 0;
  if (pos + 4 > len) {
    return false;
  }
  *qtype = rd16(buf + pos);
  *qclass = rd16(buf + pos + 2);
  *qEnd = pos + 4;
  return true;
}

// Turn the query in buf into a "blocked" reply in place. Returns its length.
size_t buildBlockedReply(uint8_t *buf, size_t qEnd, uint16_t qtype) {
  buf[2] = 0x80 | (buf[2] & 0x79);  // QR=1, keep opcode + RD, clear AA/TC
  buf[3] = 0x80;                    // RA=1, RCODE=NOERROR
  uint16_t rtype = (qtype == kTypeANY) ? kTypeA : qtype;
  bool answer = (rtype == kTypeA || rtype == kTypeAAAA);
  wr16(buf + 4, 1);           // QDCOUNT
  wr16(buf + 6, answer);      // ANCOUNT
  wr16(buf + 8, 0);           // NSCOUNT
  wr16(buf + 10, 0);          // ARCOUNT (drops any EDNS OPT record)
  size_t p = qEnd;
  if (answer) {
    uint16_t rdlen = (rtype == kTypeA) ? 4 : 16;
    wr16(buf + p, 0xC00C);    // name: pointer to the question
    wr16(buf + p + 2, rtype);
    wr16(buf + p + 4, kClassIN);
    buf[p + 6] = (BLOCKED_TTL >> 24) & 0xFF;
    buf[p + 7] = (BLOCKED_TTL >> 16) & 0xFF;
    buf[p + 8] = (BLOCKED_TTL >> 8) & 0xFF;
    buf[p + 9] = BLOCKED_TTL & 0xFF;
    wr16(buf + p + 10, rdlen);
    memset(buf + p + 12, 0, rdlen);  // 0.0.0.0 or ::
    p += 12 + rdlen;
  }
  return p;
}

void handleQuery(uint8_t *buf) {
  sockaddr_in from;
  socklen_t fromLen = sizeof(from);
  int n = recvfrom(g_srv, buf, kBufSize, 0, (sockaddr *)&from, &fromLen);
  if (n <= 0) {
    return;
  }
  size_t len = (size_t)n;
  if (len < 12 || (buf[2] & 0x80)) {  // too short, or a response
    g_stats.malformed++;
    return;
  }
  g_stats.queries++;

  uint8_t opcode = (buf[2] >> 3) & 0x0F;
  char name[256];
  size_t qEnd;
  uint16_t qtype, qclass;
  if (opcode == 0 && rd16(buf + 4) == 1 && parseQuestion(buf, len, name, &qEnd, &qtype, &qclass)
      && (qclass == kClassIN || qclass == kTypeANY) && Blocklist::isBlocked(name)) {
    size_t out = buildBlockedReply(buf, qEnd, qtype);
    sendto(g_srv, buf, out, 0, (sockaddr *)&from, fromLen);
    g_stats.blocked++;
    log_d("blocked %s (type %u)", name, qtype);
    return;
  }

  // Forward upstream under a new ID; the low byte selects the pending slot,
  // the high byte is random so spoofed replies are hard to match.
  uint8_t slot = g_nextSlot++;
  Pending &p = g_pending[slot];
  if (p.used) {
    g_stats.timeouts++;  // slot recycled before its reply came back
  }
  p.used = true;
  p.clientId = rd16(buf);
  p.upId = (uint16_t)((esp_random() & 0xFF00) | slot);
  p.client = from;
  p.ts = millis();
  wr16(buf, p.upId);
  if (sendto(g_up, buf, len, 0, (sockaddr *)&g_upstream, sizeof(g_upstream)) < 0) {
    p.used = false;
    return;
  }
  g_stats.forwarded++;
}

void handleReply(uint8_t *buf) {
  sockaddr_in from;
  socklen_t fromLen = sizeof(from);
  int n = recvfrom(g_up, buf, kBufSize, 0, (sockaddr *)&from, &fromLen);
  if (n < 12) {
    return;
  }
  if (from.sin_addr.s_addr != g_upstream.sin_addr.s_addr || from.sin_port != g_upstream.sin_port) {
    return;
  }
  uint16_t id = rd16(buf);
  Pending &p = g_pending[id & 0xFF];
  if (!p.used || p.upId != id) {
    return;  // late, duplicate or spoofed
  }
  wr16(buf, p.clientId);
  sendto(g_srv, buf, n, 0, (sockaddr *)&p.client, sizeof(p.client));
  p.used = false;
  g_stats.answered++;
}

void expirePending() {
  uint32_t now = millis();
  for (auto &p : g_pending) {
    if (p.used && now - p.ts > kUpstreamTimeoutMs) {
      p.used = false;
      g_stats.timeouts++;
    }
  }
}

void serverTask(void *) {
  uint8_t *buf = (uint8_t *)malloc(kBufSize);
  uint32_t lastExpire = millis();
  while (true) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(g_srv, &rfds);
    FD_SET(g_up, &rfds);
    timeval tv = {1, 0};
    int r = select(std::max(g_srv, g_up) + 1, &rfds, nullptr, nullptr, &tv);
    if (r > 0) {
      if (FD_ISSET(g_srv, &rfds)) {
        handleQuery(buf);
      }
      if (FD_ISSET(g_up, &rfds)) {
        handleReply(buf);
      }
    }
    if (millis() - lastExpire > 1000) {
      expirePending();
      lastExpire = millis();
    }
  }
}

}  // namespace

bool begin(IPAddress upstream) {
  memset(&g_upstream, 0, sizeof(g_upstream));
  g_upstream.sin_family = AF_INET;
  g_upstream.sin_port = htons(53);
  g_upstream.sin_addr.s_addr = (uint32_t)upstream;

  g_srv = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  g_up = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (g_srv < 0 || g_up < 0) {
    log_e("socket() failed");
    return false;
  }
  sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(kPort);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  if (bind(g_srv, (sockaddr *)&addr, sizeof(addr)) < 0) {
    log_e("bind(:53) failed");
    return false;
  }
  return xTaskCreate(serverTask, "dns", 8192, nullptr, 5, nullptr) == pdPASS;
}

Stats stats() {
  Stats s;
  s.queries = g_stats.queries;
  s.blocked = g_stats.blocked;
  s.forwarded = g_stats.forwarded;
  s.answered = g_stats.answered;
  s.timeouts = g_stats.timeouts;
  s.malformed = g_stats.malformed;
  return s;
}

}  // namespace DnsServer
