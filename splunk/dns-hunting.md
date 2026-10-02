# DNS hunting: Splunk

## Goal
Find DNS tunneling, command-and-control over DNS, DGA-like domains and newly seen names.

## Data needed
DNS logs from resolvers, Zeek `dns.log`, Sysmon Event ID 22, or a DNS security product. Assumed fields: `src_ip`, `query`, `query_type`, `answer`, `rcode_name`. Adjust to your data.

## ATT&CK
T1071.004 DNS · T1568.002 Domain Generation Algorithms · T1048 Exfiltration Over Alternative Protocol · T1572 Protocol Tunneling

## 1. Query volume per registered domain from one host (tunneling)
```
index=dns earliest=-1h
| eval parts=split(query,".")
| eval n=mvcount(parts), qlen=len(query)
| eval base=mvindex(parts,n-2).".".mvindex(parts,n-1)
| stats count dc(query) as unique_names avg(qlen) as avg_len by src_ip, base
| where unique_names>200 AND avg_len>30
| sort - unique_names
```
Many unique, long subdomains under one parent domain is a tunneling pattern. This simple split mishandles domains like `co.uk`. Use a public-suffix lookup if you have one.

## 2. Long queries
```
index=dns earliest=-24h
| eval qlen=len(query)
| where qlen>=60
| stats count dc(src_ip) as hosts max(qlen) as max_len by query
| sort - max_len
```

## 3. TXT, NULL and unusual record types
```
index=dns earliest=-24h query_type IN ("TXT","NULL","CNAME","MX")
| stats count dc(query) as unique_names by src_ip, query_type
| where unique_names>50
| sort - unique_names
```
Heavy TXT or NULL lookups from a workstation are uncommon.

## 4. NXDOMAIN bursts (DGA or scanning)
```
index=dns earliest=-1h rcode_name=NXDOMAIN
| stats count dc(query) as unique_failed by src_ip
| where unique_failed>100
| sort - unique_failed
```

## 5. Newly seen domains
```
index=dns earliest=-30d
| stats min(_time) as first_seen dc(src_ip) as hosts count by query
| where first_seen>relative_time(now(),"-1d") AND hosts<=2
| convert ctime(first_seen)
```

## 6. Beaconing in DNS lookups
```
index=dns earliest=-24h
| sort 0 src_ip query _time
| streamstats current=f last(_time) as prev by src_ip query
| eval delta=_time-prev
| stats count avg(delta) as avg_s stdev(delta) as sd_s by src_ip, query
| eval jitter=round(sd_s/avg_s,2)
| where count>30 AND jitter<0.2
| sort - count
```

## 7. Hosts bypassing the corporate resolver
Check firewall logs for DNS (port 53, 853) or DNS-over-HTTPS going to anything other than approved resolvers:
```
index=firewall earliest=-24h dest_port IN (53,853) action=allowed
| search NOT dest_ip IN ("10.0.0.53","10.0.0.54")
| stats count dc(src_ip) as hosts values(dest_ip) as resolvers by dest_port
```
Replace the example resolver addresses with yours.

## 8. Known-bad matching
```
index=dns earliest=-7d
| lookup ioc_domains.csv domain AS query OUTPUT source AS ioc_source
| where isnotnull(ioc_source)
| stats count min(_time) as first by src_ip, query, ioc_source
```

## False positives and tuning
Security products, CDNs, email security tools and antivirus cloud lookups produce long and random-looking names, and many TXT queries (SPF and DKIM checks). Exclude confirmed sources.

## Next steps
Identify the process making the lookups using endpoint DNS events (Falcon `DnsRequest`, Sysmon Event ID 22).
