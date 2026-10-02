# Hunting with Zeek logs

## Goal
Use Zeek's connection, DNS, HTTP, SSL and file logs from the command line (or any log platform) to find beaconing, odd protocols, suspicious DNS and rare destinations.

## Data needed
Zeek logs in TSV format (`conn.log`, `dns.log`, `http.log`, `ssl.log`, `files.log`, `x509.log`) and the `zeek-cut` utility. If your logs are JSON, use `jq` instead (examples at the end). Field names such as `id.orig_h` come from Zeek's standard schema.

## ATT&CK
T1071 Application Layer Protocol · T1095 Non-Application Layer Protocol · T1568 Dynamic Resolution · T1572 Protocol Tunneling · T1041 Exfiltration Over C2

> Run on a copy of your logs. Zeek's log directory names and compression vary: use `zcat` for `.gz` files.

## 1. Top talkers by bytes sent out
```
zeek-cut id.orig_h id.resp_h orig_bytes < conn.log \
  | awk '$3!="-"{s[$1" "$2]+=$3} END{for(k in s) print s[k], k}' | sort -rn | head -20
```

## 2. Long-lived connections
```
zeek-cut id.orig_h id.resp_h id.resp_p proto duration < conn.log \
  | awk '$5!="-" && $5>3600' | sort -k5 -rn | head -20
```
Connections lasting hours can be remote access tools, tunnels or legitimate streaming and VPN sessions.

## 3. Beaconing: count connections per pair and inspect interval regularity
```
zeek-cut ts id.orig_h id.resp_h id.resp_p < conn.log \
  | awk '{k=$2" "$3" "$4; c[k]++} END{for(k in c) if(c[k]>40) print c[k], k}' | sort -rn | head -20
```
Then check the timing of a candidate pair:
```
zeek-cut ts id.orig_h id.resp_h < conn.log | awk '$2=="10.1.2.31" && $3=="203.0.113.77"{print $1}' \
  | awk 'NR>1{print $1-p} {p=$1}' | sort -n | uniq -c | sort -rn | head
```
Repeated identical intervals suggest automation.

## 3b. Uncommon destination ports from internal hosts
```
zeek-cut id.resp_p proto < conn.log | sort | uniq -c | sort -n | head -30
```
Rare ports on external connections are worth reviewing.

## 4. Rare external destinations contacted by one internal host
```
zeek-cut id.orig_h id.resp_h < conn.log \
  | awk '!($2 ~ /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)/){print $2" "$1}' \
  | sort -u | awk '{c[$1]++; h[$1]=$2} END{for(d in c) if(c[d]==1) print d, h[d]}' | head -50
```

## 5. DNS: most queried domains and rare names
```
zeek-cut query < dns.log | sort | uniq -c | sort -rn | head -30
zeek-cut query < dns.log | sort | uniq -c | sort -n | head -50
```

## 6. DNS: long queries and unusual record types
```
zeek-cut id.orig_h query qtype_name < dns.log | awk 'length($2)>60' | head -50
zeek-cut qtype_name < dns.log | sort | uniq -c | sort -rn
```
Many `TXT` or `NULL` queries from a workstation can indicate tunneling.

## 7. DNS: NXDOMAIN bursts per host
```
zeek-cut id.orig_h rcode_name < dns.log | awk '$2=="NXDOMAIN"{c[$1]++} END{for(h in c) print c[h], h}' | sort -rn | head
```

## 8. HTTP: unusual User-Agents
```
zeek-cut user_agent < http.log | sort | uniq -c | sort -n | head -50
```
Empty or tool-like agents (`python-requests`, `curl`, `Go-http-client`, `WindowsPowerShell`) on workstations are worth a look.

## 9. HTTP: executable and archive downloads
```
zeek-cut ts id.orig_h host uri resp_mime_types < http.log \
  | grep -Ei "application/(x-dosexec|x-msdownload|zip|x-rar|x-7z)" | head -50
```

## 10. HTTP: direct IP hosts
```
zeek-cut id.orig_h host uri < http.log | awk '$2 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/' | head -50
```

## 11. TLS: missing SNI and self-signed certificates
```
zeek-cut id.orig_h id.resp_h server_name validation_status < ssl.log \
  | awk '$3=="-" || $4 ~ /self.signed/' | sort | uniq -c | sort -rn | head -30
```
Field availability for `validation_status` depends on your Zeek configuration.

## 12. TLS fingerprints
With the JA3 (built in on many builds) or JA4 package installed:
```
zeek-cut id.orig_h ja4 < ssl.log | sort | uniq -c | sort -rn | head -30
```
See [tshark-zeek-ja4.md](tshark-zeek-ja4.md) and [../splunk/tls-fingerprint-hunting.md](../splunk/tls-fingerprint-hunting.md).

## 13. Files seen on the wire
```
zeek-cut ts tx_hosts rx_hosts mime_type filename sha1 md5 < files.log \
  | grep -Ei "dosexec|msword|zip" | head -50
```
Hashes depend on your file-hashing configuration.

## 14. JSON logs with jq
```
jq -r 'select(.["id.resp_p"]==443 and .orig_bytes>10000000) | [.ts,.["id.orig_h"],.["id.resp_h"],.orig_bytes] | @tsv' conn.log
jq -r 'select(.query|length>60) | [.["id.orig_h"],.query] | @tsv' dns.log
```

## False positives and tuning
Backups, software updates, VPNs, streaming and cloud sync dominate bulk and long-lived traffic. Baseline normal behavior first and keep lists of known scanners, resolvers and update services.

## Next steps
Take any internal host that stands out to the endpoint, find the process behind the connection, and extract the indicators (IP, domain, JA4, hash).
