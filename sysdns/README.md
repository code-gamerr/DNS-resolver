# sysDNS

A DNS resolver written from scratch in C11. It builds DNS packets itself,
sends them with UDP sockets, and parses the bytes that come back. It does
not call `getaddrinfo()`, `gethostbyname()`, or the system resolver.

## What DNS is

DNS maps a name such as `example.com` to data: an IPv4 address (A), an IPv6
address (AAAA), a mail server (MX), a nameserver (NS), an alias (CNAME), or
text (TXT). The conversation is a binary request and response, normally over
UDP port 53.

## What sysDNS does

```text
./sysdns example.com A
./sysdns example.com AAAA --server 1.1.1.1
./sysdns example.com MX --debug
./sysdns example.com A --recursive
```

Forward mode sends one query with the recursion-desired bit set and trusts
that server (by default `8.8.8.8`) to do the rest.

`--recursive` starts at a root server (`198.41.0.4`, a.root-servers.net) and
follows referrals until an answer is found. Nameserver addresses come from
glue records in the packet, or from another iterative lookup. No libc
resolver is used to find the next server.

## Why it was built

This is a systems-programming exercise: sockets, byte order, untrusted input,
and a real protocol, with the moving parts left visible.

## Packet layout

```text
 0                   16                  31
 +-------------------+-------------------+
 |        ID         |       Flags       |
 +-------------------+-------------------+
 |      QDCOUNT      |      ANCOUNT      |
 +-------------------+-------------------+
 |      NSCOUNT      |      ARCOUNT      |
 +-------------------+-------------------+
 | Question (name, type, class)          |
 | Answer / Authority / Additional RRs   |
 +---------------------------------------+
```

Multi-byte integers are big-endian. The code reads them one byte at a time.
It never casts a packet buffer to a struct.

## Header flags

| Bit | Name | Meaning |
|-----|------|---------|
| 15 | QR | 0 query, 1 response |
| 14–11 | OPCODE | 0 for a standard query |
| 10 | AA | Authoritative answer |
| 9 | TC | Truncated (UDP packet was cut) |
| 8 | RD | Recursion desired |
| 7 | RA | Recursion available |
| 3–0 | RCODE | NOERROR, FORMERR, SERVFAIL, NXDOMAIN, NOTIMP, REFUSED |

## Question

A question is a length-prefixed name, a 16-bit type, and a 16-bit class.
Class IN is 1. `example.com` on the wire is:

```text
07 65 78 61 6d 70 6c 65 03 63 6f 6d 00
```

Labels are at most 63 bytes. The whole encoded name is at most 255 bytes.

## Resource records

```text
NAME  TYPE  CLASS  TTL  RDLENGTH  RDATA
```

Supported RDATA: A (4 bytes), AAAA (16 bytes), CNAME and NS (a name),
MX (preference + name), TXT (length-prefixed strings). Anything else is
skipped by its RDLENGTH so a surprise type cannot walk off the packet.

## Name compression

A label with the top two bits set (`0xC0`) is a pointer to an earlier offset.
`dns_name_decode()` follows those pointers, counts jumps, and remembers
offsets it has already visited so a pointer loop stops instead of spinning.
A pointer that lands outside the packet is rejected.

## UDP

```text
socket(AF_INET, SOCK_DGRAM) -> sendto() -> wait -> recvfrom() -> close()
```

The server address is a numeric IPv4 address parsed with `inet_pton()`.
`recv` uses a timeout so a dead server cannot block the process forever.
`--retries` is how many attempts to make. The clock starts before the first
send and stops when a parseable response arrives.

## Why getaddrinfo() is not used

`getaddrinfo()` would ask the operating system to resolve the name. That
hides the protocol this project exists to show. Root and glue addresses are
taken from DNS packets or from compiled-in root hints.

## Cache

The cache is a fixed table in the process. A hit requires the same name and
type and a TTL that has not expired. `--no-cache` skips it. Starting the
program again starts with an empty cache, so two separate commands cannot
show HIT then MISS. The unit test covers expiry with a fake clock.

## Recursive resolution

```text
sysDNS
  |  google.com A
  v
Root (198.41.0.4)
  |  NS for .com + glue
  v
.com servers
  |  NS for google.com + glue
  v
google.com servers
  |  A record
  v
answer
```

The walk stops at a depth limit, refuses a name already on the stack, and
only treats the answer section as the answer. Extra-section A records are
used as glue only when their owner is a nameserver from the authority
section.

## Security

Responses are untrusted. Every field checks that enough bytes remain.
Compression pointers cannot loop. TTLs stored in the cache are capped at
seven days. This is still a teaching resolver: it does not authenticate
with DNSSEC, it does not speak TCP, and it does not randomize source ports
beyond what the kernel does.

## Build

```sh
make
make test
make debug
make sanitize
```

On Windows with MinGW:

```sh
mingw32-make
mingw32-make test
```

`make sanitize` needs AddressSanitizer and UBSan. The MinGW toolchain used
here does not ship those libraries. The flags are in the Makefile for Linux.

## Usage

```text
sysdns <domain> [A|AAAA|CNAME|MX|NS|TXT]
       [--server ip] [--timeout ms] [--retries n]
       [--no-cache] [--recursive] [--debug]
```

```text
sysDNS
--------------------------------
Query: example.com
Type: A
Server: 1.1.1.1
Mode: iterative
--------------------------------

ANSWER

    example.com.    60    A    93.184.216.34

--------------------------------
Query time: 21 ms
Cache: MISS
--------------------------------
```

`--debug` adds the header, each section, and a hex dump of the datagram.

## Layout

```text
sysdns/src/
  main.c            CLI
  wire.c            checked big-endian reads and writes
  dns_hdr.c         12-byte header
  dns_encode.c      presentation name -> wire name
  dns_name.c        wire name -> text, including pointers
  dns_query.c       query packet
  dns_socket.c      UDP exchange
  dns_records.c     questions and resource records
  dns_resolver.c    timeout, retries, latency
  dns_cache.c       in-memory TTL cache
  recursive.c       root-to-authoritative walk
```

## Tests

`make test` covers encoding, header I/O, query layout, header checks,
compression (including pointer loops and truncated packets), A/AAAA/CNAME/
MX/NS/TXT parsing, and cache expiry. Live lookups are not part of `make test`
because addresses change.

## Limitations

- IPv4 transport only (AAAA records are parsed, not used as the next hop)
- UDP only, so truncated answers are reported, not retried over TCP
- No DNSSEC
- No EDNS
- Cache is not shared across processes
- Recursive mode depends on public root and TLD servers answering UDP
