# tshark hunting cheatsheet

## Goal
Quickly answer investigation questions from a packet capture: who talked to whom, what DNS and HTTP was seen, which TLS clients and servers, and what was transferred.

## Data needed
A `.pcap` or `.pcapng` and Wireshark's `tshark`. Newer builds include fields for JA3 and JA4. Check with `tshark -G fields | grep -i ja`. Filters use Wireshark display-filter syntax.

## ATT&CK
T1071 Application Layer Protocol · T1048 Exfiltration · T1105 Ingress Tool Transfer · T1046 Network Service Discovery

> Work on a copy and consider the sensitivity of captures. Replace `cap.pcapng` with your file.

## 1. Conversation summary (who talked most)
```
tshark -r cap.pcapng -q -z conv,ip | head -30
tshark -r cap.pcapng -q -z endpoints,ip | head -30
```

## 2. Protocol hierarchy
```
tshark -r cap.pcapng -q -z io,phs
```

## 3. DNS queries and answers
```
tshark -r cap.pcapng -Y "dns.flags.response==0" -T fields -e frame.time -e ip.src -e dns.qry.name | sort -k4 | uniq -c | sort -rn | head -30
tshark -r cap.pcapng -Y "dns.flags.response==1" -T fields -e dns.qry.name -e dns.a -e dns.aaaa -e dns.resp.type | head -50
```

## 4. Long or unusual DNS names
```
tshark -r cap.pcapng -Y "dns.qry.name && dns.flags.response==0" -T fields -e ip.src -e dns.qry.name | awk 'length($2)>60'
tshark -r cap.pcapng -Y "dns.qry.type==16 || dns.qry.type==10" -T fields -e ip.src -e dns.qry.name
```
Types 16 (TXT) and 10 (NULL) in volume can indicate tunneling.

## 5. HTTP requests, hosts and user agents
```
tshark -r cap.pcapng -Y "http.request" -T fields -e frame.time -e ip.src -e http.host -e http.request.method -e http.request.uri -e http.user_agent
```

## 6. Export HTTP objects
```
tshark -r cap.pcapng --export-objects http,./http_objects
sha256sum ./http_objects/* | head
```
Hash exported files and check them against intelligence. Handle samples safely.

## 7. TLS ClientHello: SNI and fingerprints
```
tshark -r cap.pcapng -Y "tls.handshake.type==1" -T fields -e ip.src -e ip.dst -e tls.handshake.extensions_server_name -e tls.handshake.ja3 -e tls.handshake.ja4
```
Stack the output with `sort | uniq -c | sort -rn` to see which clients are present.

## 8. TLS certificates
```
tshark -r cap.pcapng -Y "tls.handshake.type==11" -T fields -e ip.src -e x509sat.printableString -e x509ce.dNSName
```

## 9. Connections without a ClientHello SNI
```
tshark -r cap.pcapng -Y "tls.handshake.type==1 && !tls.handshake.extensions_server_name" -T fields -e ip.src -e ip.dst
```

## 10. SMB and lateral movement signals
```
tshark -r cap.pcapng -Y "smb2.cmd==5 || smb2.cmd==3" -T fields -e ip.src -e ip.dst -e smb2.filename | head -50
tshark -r cap.pcapng -Y "smb2.tree" -T fields -e ip.src -e ip.dst -e smb2.tree | sort | uniq -c | sort -rn
```
Look for admin shares (`ADMIN$`, `C$`) and executable file names.

## 11. Port scanning: many SYN packets without replies
```
tshark -r cap.pcapng -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields -e ip.src -e ip.dst -e tcp.dstport | sort | uniq -c | sort -rn | head -30
```
One source reaching many destinations or ports is scanning.

## 12. Beacon timing for one pair
```
tshark -r cap.pcapng -Y "ip.src==10.1.2.31 && ip.dst==203.0.113.77 && tcp.flags.syn==1 && tcp.flags.ack==0" -T fields -e frame.time_epoch \
  | awk 'NR>1{print int($1-p)} {p=$1}' | sort -n | uniq -c | sort -rn | head
```
Repeated identical gaps point to automation.

## 13. Large outbound data per destination
```
tshark -r cap.pcapng -q -z conv,tcp | sort -k9 -rn | head -20
```
Column order can vary by version, so inspect the header before sorting.

## 14. Extract a TCP stream for review
```
tshark -r cap.pcapng -q -z follow,tcp,ascii,0
```
Replace `0` with the stream number from the conversation table.

## False positives and tuning
Backups, updates, VPNs and cloud sync create bulk traffic. Always compare against what is normal for the capture point and time.

## Next steps
Record the IPs, domains, SNI values, JA3/JA4 and file hashes you find, and carry them into the endpoint and log hunts. See [tshark-zeek-ja4.md](tshark-zeek-ja4.md).
