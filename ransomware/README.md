# Ransomware hunting

Queries organized around the stages of a ransomware intrusion, so you can hunt **before** encryption starts, when there is still time to act.

> **Read this first.** These are templates. Field names, tables and sensor telemetry differ by environment. Test on a short time range and tune before alerting. Nothing here comes from any employer, and examples use invented hosts and documentation-range IPs. Treat a confirmed hit on the **impact** or **recovery-inhibition** stages as an incident: isolate first, investigate second.

## Query sets

| File | Platform | Covers |
|---|---|---|
| [`crowdstrike.md`](crowdstrike.md) | CrowdStrike Falcon | Precursors, mass file activity, tools, encryption indicators |
| [`microsoft-kql.md`](microsoft-kql.md) | Microsoft Defender advanced hunting and Sentinel (KQL) | Same stages with Defender and Sentinel tables |
| [`splunk.md`](splunk.md) | Splunk (Sysmon and Windows Security) | Same stages with Windows event logs |
| [`network-firewall-proxy-waf.md`](network-firewall-proxy-waf.md) | Splunk over firewall, proxy and WAF logs | Initial access, C2, internal spread, exfiltration |
| [`identity-backup-and-email.md`](identity-backup-and-email.md) | Splunk and KQL | Domain controller activity, backup tampering, email delivery |

## The intrusion stages and where to look

| Stage | What you may see | Best data source |
|---|---|---|
| Initial access | Phishing, ClickFix, exposed VPN or RDP, stolen credentials, exploited edge device | Email, proxy, firewall, WAF, identity logs |
| Execution and loader | PowerShell, LOLBins, new tooling dropped to disk | Endpoint |
| Discovery | `net`, `nltest`, AD enumeration, network scanning | Endpoint, firewall |
| Credential access | LSASS access, SAM/NTDS extraction, Kerberoasting | Endpoint, domain controllers |
| Lateral movement | PsExec, WMI, RDP, SMB admin shares | Endpoint, Windows logs, firewall |
| Exfiltration | Large uploads to cloud storage, `rclone`, FTP, odd domains | Proxy, firewall, DNS |
| **Inhibit recovery** | Shadow copies deleted, backups removed, security tools stopped | Endpoint, backup system |
| **Impact** | Mass renames, ransom notes, high file-write rate | Endpoint, file servers |

## Triage order when you find something

1. **Isolate** the affected host (and any host the same account touched).
2. Disable the compromised account(s) and rotate credentials, including privileged and service accounts.
3. Check **backups**: are they intact, offline or immutable?
4. Identify patient zero and the entry point, so you can close it.
5. Scope with the hashes, tools, domains and IPs you collect.
6. Preserve evidence before rebuilding.

## Caveats

- Ransomware operators often spend days or weeks in a network. The earlier stages give the best chance to stop it.
- Many commands here (`vssadmin`, `wevtutil`, `rclone`-like sync tools) have legitimate administrative uses. Allowlist confirmed approved activity.
- Thresholds (counts, bytes, time windows) are examples. Set them from your own baseline.
