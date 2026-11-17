# esp32p4_dnsblock

A network-wide DNS ad and malware blocker running on an ESP32-P4. Point your
router's or devices' DNS at the board: queries for domains on the
[StevenBlack hosts list](https://github.com/StevenBlack/hosts) are answered
with `0.0.0.0` (or `::`), everything else is relayed to an upstream resolver.

Built for the **Guition JC-ESP32P4-M3** using its on-board Ethernet (Wi-Fi is
not used).

## How it works

- **Blocklist in flash.** `tools/update_blocklist.py` downloads the hosts file
  on your PC, keeps the `0.0.0.0 <domain>` entries, lowercases, de-duplicates
  and sorts them, and writes `blocklist_data.h`: an offset index plus a
  NUL-separated string table. It is compiled into the firmware and lives in
  flash (`.rodata`), so it uses no RAM. Around 76k domains take about 1.9 MB.
- **Binary search.** Lookups search the sorted table in place, about 17 string
  compares per name.
- **Subdomains.** With `BLOCK_SUBDOMAINS 1` (default), `x.ads.example.com` is
  blocked when `ads.example.com` is listed. Set it to `0` for exact matches
  only, like a normal hosts file.
- **Answers for blocked names.** `A` gets `0.0.0.0`, `AAAA` gets `::`, any
  other type gets an empty `NOERROR` answer.
- **Everything else** is forwarded over UDP to the upstream resolver with a
  rewritten (partly random) query ID and relayed back to the client. Up to 256
  queries can be in flight; unanswered ones expire after 5 s.

## Hardware

| | |
|---|---|
| Board | Guition JC-ESP32P4-M3 (ESP32-P4, 16 MB flash) |
| Network | On-board 100 Mbit Ethernet (IP101 PHY) |
| Ethernet pins | Core defaults for ESP32-P4: MDC 31, MDIO 52, PHY reset 51, PHY addr 1, RMII clock in on GPIO50 |

If the Ethernet link never comes up, compare these pins with your board's
schematic and pass them to `ETH.begin()` in `esp32p4_dnsblock.ino`.

## Building

Requirements: Arduino IDE 2.x (or `arduino-cli`) with the **esp32 core 3.3.x**
and Python 3.

1. Edit `config.h`:
   - `STATIC_IP`, `STATIC_GATEWAY`, `STATIC_SUBNET` to match your LAN
     (or `USE_STATIC_IP 0` for DHCP; a fixed address is recommended).
   - `UPSTREAM_DNS` (default `1.1.1.1`).
   - `BLOCK_SUBDOMAINS`, `BLOCKED_TTL`.
2. Tools menu:
   - Board: **ESP32P4 Dev Module**
   - Flash Size: **16MB**
   - Partition Scheme: **Custom** (uses `partitions.csv`, 6 MB app)
3. Upload.

With `arduino-cli`:

```sh
arduino-cli compile --upload -p /dev/ttyACM0 \
  -b esp32:esp32:esp32p4:FlashSize=16M,PartitionScheme=custom .
```

## Updating the blocklist

```sh
python3 tools/update_blocklist.py            # download the latest list
python3 tools/update_blocklist.py hosts.txt  # or use a local hosts file
```

Then build and upload again. The script refuses to write a list with fewer
than 1000 domains.

## Usage

Set the board's IP as the DNS server in your router's DHCP settings (or on
individual devices), then check:

```sh
nslookup doubleclick.net 192.168.1.53   # -> 0.0.0.0
nslookup github.com 192.168.1.53        # -> real address
```

Serial console (115200 baud):

| Command | |
|---|---|
| `check <domain>` | Whether a domain is blocked, and the lookup time |
| `stats` | Query, blocked, forwarded, answered, timeout counters |

Counters are also printed every 60 s.

## Files

| File | |
|---|---|
| `esp32p4_dnsblock.ino` | Ethernet setup, serial console |
| `config.h` | Network and blocking settings |
| `dns_server.cpp/.h` | UDP DNS server and upstream forwarder |
| `blocklist.cpp/.h` | Binary search over the compiled-in list |
| `blocklist_data.h` | Generated sorted list (do not edit) |
| `tools/update_blocklist.py` | Downloads the hosts file, generates `blocklist_data.h` |
| `partitions.csv` | Flash layout |

## Limitations

- UDP only, no DNS over TCP. Large replies that are truncated upstream make
  clients retry over TCP, which this server does not answer.
- One upstream resolver, no failover.
- The list only changes when you regenerate it and re-flash.

## License

MIT, see [LICENSE](LICENSE). The blocklist data comes from
[StevenBlack/hosts](https://github.com/StevenBlack/hosts) under its own license.
