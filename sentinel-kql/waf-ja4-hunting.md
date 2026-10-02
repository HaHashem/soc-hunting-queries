# JA4 clustering of distributed web attacks (Microsoft Sentinel, KQL)

## Goal
Group requests on the TLS client fingerprint (JA4) to expose a distributed attack that rotates IPs and User-Agents.

## Data needed
WAF or gateway logs that include the client JA4 fingerprint, in a Sentinel table. `WafLogs`, `Ja4`, `ClientIP`, `ClientASN`, `UserAgent` and `UriPath` below are placeholders. Replace them with your table and column names.

## Query: stack by fingerprint
```
WafLogs
| where TimeGenerated > ago(1h)
| summarize Requests=count(), IPs=dcount(ClientIP), ASNs=dcount(ClientASN),
            UAs=dcount(UserAgent), Paths=make_set(UriPath, 5) by Ja4
| extend ReqPerIP = round(todouble(Requests)/IPs, 1)
| order by Requests desc
```

## Query: fingerprints first seen recently
```
WafLogs
| where TimeGenerated > ago(30d)
| summarize FirstSeen=min(TimeGenerated), IPs=dcount(ClientIP) by Ja4
| where FirstSeen > ago(2h)
| order by IPs desc
```

## Interpreting results
Suspicious pattern: one JA4 with very high IP and ASN counts, low requests per IP, many distinct User-Agents and traffic concentrated on a small set of paths.

## False positives and tuning
Common browsers, `curl`, Python and Go clients, and monitoring agents share fingerprints. Compare against a 30-day baseline, and corroborate with header order, behavior and ASN mix before taking action.

## Alerting idea
Alert when a fingerprint not seen in the previous 30 days reaches more than N distinct IPs within 10 minutes. Choose N from your own baseline.
