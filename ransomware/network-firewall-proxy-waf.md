# Ransomware network analysis: firewall, proxy and WAF logs (Splunk)

## Goal
Use network-side logs to find the stages of a ransomware intrusion that endpoints may miss: exposed-service attacks, command-and-control, internal scanning and spread, and **data exfiltration** (which precedes encryption in "double extortion" cases).

## Data needed
Firewall, web proxy and WAF logs in Splunk. Assumed field names (adjust to your data or CIM mapping):
- **Firewall:** `src_ip`, `dest_ip`, `dest_port`, `action`, `bytes_in`, `bytes_out`, `app`, `src_zone`, `dest_zone`
- **Proxy:** `src_ip`, `user`, `dest_host`, `dest_ip`, `url`, `http_method`, `http_user_agent`, `bytes_in`, `bytes_out`, `category`
- **WAF:** `client_ip`, `uri_path`, `http_method`, `rule`, `action`, `status`, `ja4`
- Index names (`firewall`, `proxy`, `waf`) are placeholders.

## ATT&CK
T1190 Exploit Public-Facing Application · T1133 External Remote Services · T1071 Application Layer Protocol · T1046 Network Service Discovery · T1021 Remote Services · T1048/T1567 Exfiltration · T1105 Ingress Tool Transfer

> Choose thresholds from your own baseline. Backups, updates and cloud sync make byte-based rules noisy until allowlisted.

---

# A. Initial access (firewall, WAF)

## A1. Brute force or spray against VPN, RDP and remote access (firewall)
```
index=firewall earliest=-1h dest_port IN (3389,443,1194,500,4500,22) action=allowed
| stats count dc(dest_ip) as targets by src_ip, dest_port
| where count>200
| sort - count
```
Better: use VPN gateway authentication logs for failed logons by source and account, if available.

## A2. RDP or SSH exposed to the internet
```
index=firewall earliest=-24h dest_port IN (3389,22,5985,5986,445,23) action=allowed
| where NOT (cidrmatch("10.0.0.0/8",src_ip) OR cidrmatch("172.16.0.0/12",src_ip) OR cidrmatch("192.168.0.0/16",src_ip))
| stats count dc(src_ip) as sources values(dest_port) as ports by dest_ip
| sort - sources
```
Inbound allowed connections to these ports from the internet are exposure, and a common ransomware entry route.

## A3. Successful connection after many denied attempts from one source
```
index=firewall earliest=-6h dest_port IN (3389,22,443)
| stats count(eval(action="blocked" OR action="denied" OR action="drop")) as denied count(eval(action="allowed")) as allowed by src_ip, dest_ip, dest_port
| where denied>=50 AND allowed>=1
| sort - denied
```

## A4. WAF: exploit-style requests to edge applications
```
index=waf earliest=-24h
| where match(uri_path,"(?i)(/\.\./|%2e%2e|/cgi-bin/|/vpn/|/remote/|/dana-na/|/\+CSCOE\+/|/owa/auth|/ecp/|/autodiscover|/sslvpn|/admin/|/api/v\d/.*(exec|cmd|shell))") OR match(rule,"(?i)(rce|command|injection|traversal|deserial)")
| stats count dc(client_ip) as clients values(rule) as rules by uri_path, status
| sort - count
```
Internet-facing VPN, mail and remote-access appliances are frequent ransomware entry points. Compare against the product vendors' recent advisories.

## A5. WAF: one client or fingerprint probing many paths
```
index=waf earliest=-1h
| stats count dc(uri_path) as paths dc(status) as statuses values(status) as codes by client_ip, ja4
| where paths>50
| sort - paths
```
See [the JA4 write-up](../splunk/waf-ja4-hunting.md) for clustering distributed attacks.

---

# B. Command and control and tooling (proxy, firewall)

## B1. Beaconing in proxy logs
```
index=proxy earliest=-24h
| sort 0 src_ip dest_host _time
| streamstats current=f last(_time) as prev by src_ip dest_host
| eval delta=_time-prev
| stats count avg(delta) as avg_s stdev(delta) as sd_s values(http_user_agent) as ua by src_ip, dest_host
| eval jitter=round(sd_s/avg_s,2)
| where count>40 AND jitter<0.25
| sort - count
```

## B2. Newly seen destinations contacted by few hosts
```
index=proxy earliest=-30d
| stats min(_time) as first_seen dc(src_ip) as hosts count by dest_host
| where first_seen>relative_time(now(),"-1d") AND hosts<=2
| convert ctime(first_seen)
| sort - count
```

## B3. Download of tools and loaders
```
index=proxy earliest=-24h http_method=GET
| where match(url,"(?i)\.(exe|dll|msi|ps1|bat|vbs|js|hta|iso|img|zip|7z|rar|scr)(\?|$)")
| stats count values(url) as urls by src_ip, user, dest_host
| sort - count
```

## B4. Tool-like User-Agents and direct-to-IP requests
```
index=proxy earliest=-24h
| where match(http_user_agent,"(?i)(python-requests|curl/|wget/|go-http-client|powershell|winhttp|java/)") OR match(dest_host,"^\d{1,3}(\.\d{1,3}){3}$")
| stats count dc(src_ip) as hosts values(dest_host) as destinations by http_user_agent
| sort - count
```

## B5. Remote-management and tunneling services
```
index=proxy earliest=-7d
| where match(dest_host,"(?i)(anydesk|teamviewer|screenconnect|connectwise|splashtop|ngrok|rustdesk|atera|rport|tailscale|cloudflared|trycloudflare|serveo|localtunnel)")
| stats count dc(src_ip) as hosts values(user) as users by dest_host
| sort - count
```
Attackers frequently install a legitimate remote-access tool for persistence. Compare with the tools your organization approves.

---

# C. Internal scanning and spread (firewall)

## C1. One host connecting to many internal hosts on SMB, RDP, WinRM, SSH
```
index=firewall earliest=-1h dest_port IN (445,3389,5985,5986,22,135,139) action=allowed
| where cidrmatch("10.0.0.0/8",dest_ip) OR cidrmatch("172.16.0.0/12",dest_ip) OR cidrmatch("192.168.0.0/16",dest_ip)
| stats dc(dest_ip) as targets dc(dest_port) as ports count by src_ip
| where targets>20
| sort - targets
```
Your vulnerability scanner and management hosts will appear. Allowlist them.

## C2. Many denied internal connections (scanning blocked by segmentation)
```
index=firewall earliest=-1h action IN (blocked,denied,drop)
| where cidrmatch("10.0.0.0/8",src_ip) OR cidrmatch("172.16.0.0/12",src_ip) OR cidrmatch("192.168.0.0/16",src_ip)
| stats dc(dest_ip) as targets dc(dest_port) as ports count by src_ip
| where targets>50 OR ports>50
| sort - count
```

## C3. Workstation-to-workstation SMB (unusual in most networks)
```
index=firewall earliest=-24h dest_port=445 action=allowed src_zone="workstations" dest_zone="workstations"
| stats dc(dest_ip) as targets count by src_ip
| where targets>3
| sort - targets
```
Zone names are placeholders for your own network.

---

# D. Exfiltration (proxy, firewall)

## D1. Large uploads per source and destination (proxy)
```
index=proxy earliest=-24h http_method IN (POST,PUT)
| stats sum(bytes_out) as total_out dc(url) as urls by src_ip, user, dest_host
| where total_out>100000000
| eval total_out_mb=round(total_out/1048576,1)
| sort - total_out
```

## D2. Outbound volume far above normal (firewall)
```
index=firewall earliest=-24h
| where NOT (cidrmatch("10.0.0.0/8",dest_ip) OR cidrmatch("172.16.0.0/12",dest_ip) OR cidrmatch("192.168.0.0/16",dest_ip))
| stats sum(bytes_out) as out by src_ip
| eventstats avg(out) as avg_out stdev(out) as sd_out
| where out > avg_out + 3*sd_out AND out>500000000
| eval out_gb=round(out/1073741824,2)
| sort - out
```
This compares hosts to each other. A baseline per host over 30 days is better when you have it.

## D3. Cloud storage and file-sharing destinations
```
index=proxy earliest=-7d
| where match(dest_host,"(?i)(mega\.nz|mega\.io|dropbox|wetransfer|anonfiles|gofile|transfer\.sh|file\.io|pixeldrain|sendspace|temp\.sh|bashupload|storage\.googleapis|blob\.core\.windows|s3\.amazonaws|backblazeb2|r2\.cloudflarestorage|filebin)")
| stats sum(bytes_out) as out dc(src_ip) as hosts values(user) as users by dest_host
| eval out_mb=round(out/1048576,1)
| where out_mb>50
| sort - out
```
Cloud storage is also normal for business use. Look for **unapproved services** and **unusual volume**, and for destinations new to the host.

## D3b. Data leaving over unusual ports and protocols
```
index=firewall earliest=-24h action=allowed dest_port IN (21,22,990,2049,20,873,8080,8443,4444,8888,1337)
| where NOT (cidrmatch("10.0.0.0/8",dest_ip) OR cidrmatch("172.16.0.0/12",dest_ip) OR cidrmatch("192.168.0.0/16",dest_ip))
| stats sum(bytes_out) as out dc(dest_ip) as dests by src_ip, dest_port
| where out>50000000
| sort - out
```

## D4. A host that suddenly sends much more than its normal outbound volume
```
index=firewall earliest=-30d
| where NOT (cidrmatch("10.0.0.0/8",dest_ip) OR cidrmatch("172.16.0.0/12",dest_ip) OR cidrmatch("192.168.0.0/16",dest_ip))
| bin _time span=1d
| stats sum(bytes_out) as daily_out by src_ip, _time
| eventstats avg(daily_out) as avg_out stdev(daily_out) as sd_out by src_ip
| where _time>=relative_time(now(),"-1d@d") AND daily_out>avg_out+3*sd_out AND daily_out>200000000
| eval daily_out_mb=round(daily_out/1048576,1)
| sort - daily_out
```
The most useful network-side ransomware signal is a host moving far more data out than its own history. The latest day is included in its own baseline, so this is a rough guide. Split baseline and current windows for stricter results.

## D5. DNS or ICMP tunneling as an exfiltration path
```
index=dns earliest=-1h
| eval parts=split(query,"."), n=mvcount(parts), qlen=len(query)
| eval base=mvindex(parts,n-2).".".mvindex(parts,n-1)
| stats count dc(query) as unique_names avg(qlen) as avg_len by src_ip, base
| where unique_names>200 AND avg_len>30
```
More DNS queries in [dns-hunting.md](../splunk/dns-hunting.md).

---

# E. Putting it together

## E1. A host with several network signals in the same day
Save the outputs of the queries above to a summary index with a `signal` field, or run each as a saved search that writes a `signal` and `src_ip`, then:
```
index=signals earliest=-24h
| stats dc(signal) as signal_types values(signal) as signals by src_ip
| where signal_types>=3
| sort - signal_types
```
Several different signals for one host (beaconing plus a new remote tool plus large upload, for example) is a far stronger lead than any single rule. Name the summary index and signal values to fit your environment.

## False positives and tuning
Backups, patching, updates, CDNs, cloud sync, vulnerability scanning, and monitoring agents. Baseline for 30 days, maintain allowlists, and prefer combining signals over alerting on any single one.

## Next steps
Tie the source IP to a host and user, then use endpoint telemetry to find the process responsible ([crowdstrike.md](crowdstrike.md), [microsoft-kql.md](microsoft-kql.md), [splunk.md](splunk.md)). For confirmed exfiltration, preserve proxy and firewall logs early, since retention can be short.
