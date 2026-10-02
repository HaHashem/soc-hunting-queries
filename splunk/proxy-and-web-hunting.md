# Proxy and web traffic hunting: Splunk

## Goal
Find command-and-control, malware downloads and data exfiltration in web proxy or firewall logs.

## Data needed
Proxy logs (field names assumed here: `src_ip`, `user`, `dest_host`, `dest_ip`, `url`, `http_method`, `http_user_agent`, `bytes_in`, `bytes_out`, `status`, `category`). Adjust to your data model. The CIM `Web` data model works with `tstats` for speed.

## ATT&CK
T1071.001 Web Protocols · T1105 Ingress Tool Transfer · T1041/T1567 Exfiltration · T1568 Dynamic Resolution · T1573 Encrypted Channel

## 1. Beaconing: regular requests from one host to one destination
```
index=proxy earliest=-24h
| sort 0 src_ip dest_host _time
| streamstats current=f last(_time) as prev by src_ip dest_host
| eval delta=_time-prev
| stats count avg(delta) as avg_s stdev(delta) as sd_s by src_ip, dest_host
| eval jitter=round(sd_s/avg_s,2)
| where count>40 AND jitter<0.25
| sort - count
```
Low jitter with many requests suggests automation. Updaters and monitoring agents also beacon, so check the destination and user agent.

## 2. Newly seen domains
```
index=proxy earliest=-30d
| stats min(_time) as first_seen dc(src_ip) as hosts count by dest_host
| where first_seen>relative_time(now(),"-1d") AND hosts<=2
| convert ctime(first_seen)
| sort - count
```

## 3. Unusual User-Agents
```
index=proxy earliest=-7d
| stats count dc(src_ip) as hosts by http_user_agent
| where hosts<=2
| sort - count
```
Empty, very short, or tool-like agents (`python-requests`, `curl`, `Go-http-client`, `WindowsPowerShell`) on workstations deserve a look.

## 4. Downloads of executables and archives
```
index=proxy earliest=-24h http_method=GET
| where match(url,"(?i)\.(exe|dll|msi|ps1|bat|vbs|js|hta|iso|img|zip|7z|rar|scr)(\?|$)")
| stats count values(url) as urls by src_ip, user, dest_host
| sort - count
```

## 5. Large uploads (possible exfiltration)
```
index=proxy earliest=-24h http_method IN (POST,PUT)
| stats sum(bytes_out) as total_out dc(url) as urls by src_ip, user, dest_host
| where total_out>50000000
| eval total_out_mb=round(total_out/1048576,1)
| sort - total_out
```
Choose the threshold from your baseline. Cloud storage, backup and update services will appear.

## 6. Direct-to-IP requests (no domain name)
```
index=proxy earliest=-24h
| where match(dest_host,"^\d{1,3}(\.\d{1,3}){3}$")
| stats count dc(src_ip) as hosts values(url) as urls by dest_host
| sort - count
```

## 7. Likely domain generation: long, high-entropy hostnames
```
index=proxy earliest=-24h
| eval label=mvindex(split(dest_host,"."),0)
| eval len=len(label)
| where len>=20 AND match(label,"^[a-z0-9]+$")
| stats count dc(src_ip) as hosts by dest_host
| sort - count
```
This is a crude filter. CDNs and cloud services also produce long hostnames.

## 8. Uncategorized or newly registered categories
```
index=proxy earliest=-24h category IN ("Uncategorized","Newly Registered Domain","Newly Observed Domain","Parked")
| stats count dc(src_ip) as hosts values(url) as urls by dest_host
| sort - count
```
Use the category names your proxy produces.

## 9. Known-bad matching with a lookup
```
index=proxy earliest=-7d
| lookup ioc_domains.csv domain AS dest_host OUTPUT source AS ioc_source
| where isnotnull(ioc_source)
| stats count min(_time) as first by src_ip, user, dest_host, ioc_source
```
Keep indicator lists current and record where each came from.

## 10. CIM data model version (faster across large data)
```
| tstats summariesonly=true count from datamodel=Web
    where Web.http_method="POST" by Web.src, Web.dest, Web.user
| sort - count
```

## False positives and tuning
CDNs, software updates, telemetry, and SaaS tools produce much of the rare and regular traffic. Baseline for 30 days and apply allowlists for known services.

## Next steps
Take the source host to the endpoint data and find the **process** that made the request. See [powershell-hunting.md](powershell-hunting.md) and the Falcon [powershell-download-hunting.md](../crowdstrike-falcon/powershell-download-hunting.md).
