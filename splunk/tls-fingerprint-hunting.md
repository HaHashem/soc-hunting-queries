# TLS fingerprint (JA3 and JA4) hunting: Splunk

## Goal
Use TLS client fingerprints from Zeek or Suricata logs to find unusual clients, pivot to hosts and IPs, and spot beaconing.

## Data needed
Zeek `ssl.log` with `ja3`/`ja4` fields or Suricata `tls` events. Assumed fields: `id.orig_h`, `id.resp_h`, `server_name`, `ja3`, `ja4`, `ja4s`. Suricata uses `tls.ja3.hash` and `tls.ja4`. Adjust to your data.

## ATT&CK
T1071.001 Web Protocols · T1573 Encrypted Channel · T1095 Non-Application Layer Protocol

> Full explanation of JA3 vs JA4: [Network traffic hunting with JA3 and JA4](https://hahashem.github.io/article.html?slug=network-tls-fingerprint-hunting-ja3-ja4).

## 1. Stack fingerprints
```
index=zeek sourcetype=zeek_ssl earliest=-24h
| stats count dc(id.orig_h) as hosts dc(server_name) as sni_count values(server_name) as sample_sni by ja4
| sort - hosts
```
Repeat with `ja3`. The long tail is where hunting happens.

## 2. New fingerprints on few hosts
```
index=zeek sourcetype=zeek_ssl earliest=-30d
| stats min(_time) as first_seen count dc(id.orig_h) as hosts values(id.orig_h) as src by ja4
| where hosts<=2 AND first_seen>relative_time(now(),"-1d")
| convert ctime(first_seen)
```

## 3. Pivot from one fingerprint to hosts and destinations
```
index=zeek sourcetype=zeek_ssl ja4="<ja4 value>"
| stats count min(_time) as first max(_time) as last values(server_name) as sni by id.orig_h, id.resp_h
| convert ctime(first) ctime(last)
| sort - count
```

## 4. Same JA3 or JA4 across many external IPs and hosts
```
index=zeek sourcetype=zeek_ssl earliest=-24h
| stats dc(id.orig_h) as clients dc(id.resp_h) as servers by ja4
| where servers>50 AND clients<=3
```
A rare client talking to very many external destinations can indicate scanning or a proxy-like tool.

## 5. Missing SNI or IP-only SNI
```
index=zeek sourcetype=zeek_ssl earliest=-24h
| where isnull(server_name) OR server_name="" OR match(server_name,"^\d{1,3}(\.\d{1,3}){3}$")
| stats count dc(id.orig_h) as hosts values(ja4) as ja4 by id.resp_h
| sort - count
```
TLS without a server name is more common for malware and tools than for browsers.

## 6. Beaconing by fingerprint
```
index=zeek sourcetype=zeek_ssl earliest=-24h
| sort 0 id.orig_h id.resp_h _time
| streamstats current=f last(_time) as prev by id.orig_h id.resp_h
| eval delta=_time-prev
| stats count avg(delta) as avg_s stdev(delta) as sd_s values(ja4) as ja4 values(server_name) as sni by id.orig_h, id.resp_h
| eval jitter=round(sd_s/avg_s,2)
| where count>50 AND jitter<0.2
```

## 7. Match against known-bad fingerprints
```
index=zeek sourcetype=zeek_ssl earliest=-7d
| lookup ioc_ja3.csv ja3 OUTPUT source AS ja3_source
| lookup ioc_ja4.csv ja4 OUTPUT source AS ja4_source
| where isnotnull(ja3_source) OR isnotnull(ja4_source)
| stats count min(_time) as first by id.orig_h, id.resp_h, server_name, ja3, ja4
```

## 8. JA4S: servers sharing a rare configuration
```
index=zeek sourcetype=zeek_ssl earliest=-30d
| stats dc(id.orig_h) as clients values(server_name) as sni by id.resp_h, ja4s
| where clients<=3
```

## False positives and tuning
Common values reflect the library, not intent: browsers, OS agents, `curl`, Python and Go share fingerprints. Baseline first. Tools that imitate browsers can blend in, and TLS-terminating proxies hide the real client.

## Next steps
Corroborate with timing, destination reputation, SNI and endpoint evidence. For web-attack clustering see [waf-ja4-hunting.md](waf-ja4-hunting.md).
