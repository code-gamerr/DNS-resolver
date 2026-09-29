# sysDNS

[`sysdns/`](sysdns/) is a from-scratch DNS resolver in C.

It encodes queries, sends them over UDP, parses answers (including compressed
names), retries on timeout, caches records for their TTL inside one process,
and can walk from a root server with `--recursive`.

```sh
cd sysdns
mingw32-make test
./sysdns.exe example.com A --server 1.1.1.1
```

See [sysdns/README.md](sysdns/README.md) for the protocol notes and the build.
