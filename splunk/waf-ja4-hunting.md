# JA4 clustering of distributed web attacks (Splunk)

## Goal
Cluster a distributed application-layer attack that rotates IP addresses and User-Agents by grouping requests on the TLS client fingerprint (JA4).

## Data needed
WAF, CDN or load balancer logs that record the JA4 fingerprint of the client, indexed in Splunk. Field names (`ja4`, `src_ip`, `asn`, `http_user_agent`, `uri_path`) are examples. Adapt to your log source. If a CDN terminates TLS, your origin sees the CDN's fingerprint, so collect at the edge.

## Query 1: stack by fingerprint during the incident
```
index=waf earliest=-1h
| stats count as requests dc(src_ip) as ips dc(asn) as asns dc(http_user_agent) as user_agents
        values(uri_path) as paths by ja4
| eval req_per_ip=round(requests/ips,1)
| sort - requests
```
**What to look for:** one fingerprint with very high IP diversity, low requests per IP, many "different" User-Agents and a path list concentrated on one or two endpoints.

## Query 2: fingerprints that are new
```
index=waf earliest=-30d
| stats min(_time) as first_seen max(_time) as last_seen dc(src_ip) as ips by ja4
| where first_seen > relative_time(now(), "-2h")
| sort - ips
```
A fingerprint that did not exist yesterday and has thousands of IPs today is not organic traffic.

## False positives and tuning
- Popular legitimate clients share one JA4: every copy of a browser version, `curl`, Python `requests`, monitoring agents, mobile SDKs. A common fingerprint identifies the **library**, not the intent.
- Build a 30-day baseline of your top fingerprints before an incident so "unusual" has meaning.
- Tools that imitate browser handshakes can evade a pure JA4 match. Corroborate with JA4H, header order, behavior and ASN mix.

## Next steps
1. Corroborate with request behavior (no asset loads, fixed timing, missing headers) and the ASN mix.
2. Enrich a sample of IPs in threat intelligence.
3. Apply controls to the fingerprint combined with path and rate, not JA4 alone, then measure collateral damage.
4. Look back 30 to 90 days for earlier use of the same fingerprint.
