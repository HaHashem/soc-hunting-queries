# Hunting with Suricata EVE JSON

## Goal
Search Suricata's `eve.json` for alerts, TLS fingerprints, DNS, HTTP and flow behavior, using `jq`.

## Data needed
Suricata `eve.json` with `alert`, `dns`, `http`, `tls`, `flow` and `fileinfo` event types enabled. JA3/JA4 fields appear in TLS events when enabled in the config, and field names vary by version.

## ATT&CK
T1071 Application Layer Protocol · T1573 Encrypted Channel · T1048 Exfiltration Over Alternative Protocol · T1190 Exploit Public-Facing Application

> Run on a copy. Replace `eve.json` with your path. Use `zcat` for rotated `.gz` files.

## 1. Alerts by signature
```
jq -r 'select(.event_type=="alert") | .alert.signature' eve.json | sort | uniq -c | sort -rn | head -30
```

## 2. Sources hitting many different signatures
```
jq -r 'select(.event_type=="alert") | [.src_ip,.alert.signature] | @tsv' eve.json \
  | sort -u | cut -f1 | sort | uniq -c | sort -rn | head -20
```

## 3. High-severity alerts with context
```
jq -c 'select(.event_type=="alert" and .alert.severity<=2) | {t:.timestamp,src:.src_ip,dst:.dest_ip,port:.dest_port,sig:.alert.signature,cat:.alert.category}' eve.json | head -50
```

## 4. TLS: SNI and fingerprints stacked
```
jq -r 'select(.event_type=="tls") | [.src_ip,.tls.sni,.tls.ja3.hash,.tls.ja4] | @tsv' eve.json \
  | sort | uniq -c | sort -rn | head -30
```

## 5. Rare JA3 or JA4 values
```
jq -r 'select(.event_type=="tls") | .tls.ja3.hash // empty' eve.json | sort | uniq -c | sort -n | head -30
jq -r 'select(.event_type=="tls") | .tls.ja4 // empty' eve.json | sort | uniq -c | sort -n | head -30
```

## 6. Fingerprint pivot: who uses this value and where does it connect
```
jq -r 'select(.event_type=="tls" and .tls.ja4=="<ja4 value>") | [.timestamp,.src_ip,.dest_ip,.dest_port,.tls.sni] | @tsv' eve.json
```

## 7. TLS without SNI
```
jq -r 'select(.event_type=="tls" and (.tls.sni==null or .tls.sni=="")) | [.src_ip,.dest_ip,.dest_port] | @tsv' eve.json | sort | uniq -c | sort -rn | head -30
```

## 8. Expired, self-signed or odd certificates
```
jq -r 'select(.event_type=="tls" and (.tls.subject==.tls.issuerdn)) | [.src_ip,.dest_ip,.tls.sni,.tls.subject] | @tsv' eve.json | sort -u | head -30
```
Many internal devices and appliances use self-signed certificates, so separate internal and external destinations.

## 9. DNS: long queries and many unique subdomains
```
jq -r 'select(.event_type=="dns" and .dns.type=="query") | [.src_ip,.dns.rrname] | @tsv' eve.json | awk 'length($2)>60' | head -50
```

## 10. HTTP: user agents and executable downloads
```
jq -r 'select(.event_type=="http") | .http.http_user_agent // "-"' eve.json | sort | uniq -c | sort -n | head -30
jq -r 'select(.event_type=="http" and (.http.url|test("\\.(exe|dll|ps1|bat|msi|scr)(\\?|$)";"i"))) | [.src_ip,.http.hostname,.http.url] | @tsv' eve.json | head -50
```

## 11. Large outbound flows
```
jq -r 'select(.event_type=="flow" and .flow.bytes_toserver>50000000) | [.src_ip,.dest_ip,.dest_port,.flow.bytes_toserver] | @tsv' eve.json | sort -k4 -rn | head -20
```

## 12. Files seen (fileinfo) by type
```
jq -r 'select(.event_type=="fileinfo") | [.src_ip,.http.hostname,.fileinfo.filename,.fileinfo.magic,.fileinfo.sha256] | @tsv' eve.json | grep -Ei "PE32|executable|Zip" | head -50
```
SHA256 appears only if file hashing is configured.

## False positives and tuning
Signature noise varies widely. Tune by suppressing confirmed benign sources and focus on correlation: several alert types, TLS oddities and rare destinations for the same host.

## Next steps
Combine the Suricata findings with Zeek and endpoint data. Pivot from an IP or fingerprint to the internal host and process. See [zeek-hunting.md](zeek-hunting.md).
