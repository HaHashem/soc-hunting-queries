# JA4 fingerprints from packet captures and Zeek

## Goal
Extract TLS client fingerprints from a capture or from Zeek logs and stack them to see which client implementations are present.

## About JA4
JA4 is a readable fingerprint of a TLS ClientHello: protocol, TLS version, SNI presence, cipher and extension counts, ALPN, then truncated hashes of the sorted ciphers and of the sorted extensions plus signature algorithms. Because cipher suites and extensions are sorted before hashing, a client that randomizes extension order still produces a stable value.

## tshark
Check that your build knows the JA4 fields (recent versions do):
```
tshark -G fields | grep -i ja4
```
Stack client fingerprints from a capture:
```
tshark -r edge.pcapng -Y "tls.handshake.type == 1" \
  -T fields -e ip.src -e tls.handshake.ja4 \
  | sort | uniq -c | sort -rn | head -20
```

## Zeek
Install the JA4 package for Zeek, which adds JA4 fields to its logs. Field names depend on the package version, so check your log header first, then:
```
zeek-cut id.orig_h ja4 < ssl.log | sort | uniq -c | sort -rn | head
```

## Reading the output
- Count **distinct source IPs per fingerprint**, not only total connections.
- A fingerprint shared by many unrelated sources, new compared with your baseline, deserves a look.
- A popular fingerprint tells you the client library, not the intent. Corroborate with request behavior.

## Limits
A fingerprint is not attribution. Tools that imitate a browser's handshake can blend in, and proxies or CDNs change what you observe.
