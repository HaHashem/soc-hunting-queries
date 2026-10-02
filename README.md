# soc-hunting-queries

A small, growing collection of hunting and detection queries I use as starting points in SOC and DFIR work, each with the context needed to adapt it: what it finds, which data source it needs, expected false positives and the ATT&CK mapping.

> **Read this first.** These are **templates**, not production detections. Field names, table names and telemetry vary by tenant, sensor version and log pipeline. Test every query on a short time range in your own environment and tune it against your normal activity before alerting on it. Nothing here comes from, or contains data from, any employer. Hostnames, domains and IPs in examples are invented.

## Contents

### CrowdStrike Falcon

| Query set | Covers |
|---|---|
| [`crowdstrike-falcon/clickfix-hunting.md`](crowdstrike-falcon/clickfix-hunting.md) | ClickFix (fake CAPTCHA, Win+R paste) |
| [`crowdstrike-falcon/powershell-download-hunting.md`](crowdstrike-falcon/powershell-download-hunting.md) | PowerShell downloads: file name, hash, source URL, scoping |
| [`crowdstrike-falcon/credential-access.md`](crowdstrike-falcon/credential-access.md) | LSASS, SAM, NTDS, Kerberoasting |
| [`crowdstrike-falcon/persistence-hunting.md`](crowdstrike-falcon/persistence-hunting.md) | Scheduled tasks, Run keys, services, WMI |
| [`crowdstrike-falcon/lateral-movement.md`](crowdstrike-falcon/lateral-movement.md) | PsExec, WMI, WinRM, SMB, RDP |
| [`crowdstrike-falcon/defense-evasion-and-discovery.md`](crowdstrike-falcon/defense-evasion-and-discovery.md) | Shadow copy deletion, log clearing, tool tampering, recon, LOLBins |

### Splunk

| Query set | Covers |
|---|---|
| [`splunk/powershell-hunting.md`](splunk/powershell-hunting.md) | Encoded, hidden and download-cradle PowerShell; script blocks |
| [`splunk/windows-authentication-hunting.md`](splunk/windows-authentication-hunting.md) | Brute force, spraying, logon types, Kerberoasting, account changes |
| [`splunk/lateral-movement-and-persistence.md`](splunk/lateral-movement-and-persistence.md) | Services, tasks, WMI, admin shares, Run keys |
| [`splunk/proxy-and-web-hunting.md`](splunk/proxy-and-web-hunting.md) | Beaconing, new domains, downloads, uploads, user agents |
| [`splunk/dns-hunting.md`](splunk/dns-hunting.md) | Tunneling, NXDOMAIN bursts, DGA-like names, resolver bypass |
| [`splunk/tls-fingerprint-hunting.md`](splunk/tls-fingerprint-hunting.md) | JA3 and JA4 stacking, rare clients, pivots, beaconing |
| [`splunk/office-child-process.md`](splunk/office-child-process.md) | Office spawning scripting hosts (Sysmon) |
| [`splunk/waf-ja4-hunting.md`](splunk/waf-ja4-hunting.md) | JA4 clustering of distributed web attacks |

### Microsoft Sentinel (KQL)

| Query set | Covers |
|---|---|
| [`sentinel-kql/entra-signin-hunting.md`](sentinel-kql/entra-signin-hunting.md) | Spray, MFA fatigue, legacy auth, travel, token replay |
| [`sentinel-kql/m365-mailbox-and-app-abuse.md`](sentinel-kql/m365-mailbox-and-app-abuse.md) | Inbox rules, forwarding, OAuth consent, role changes |
| [`sentinel-kql/defender-endpoint-hunting.md`](sentinel-kql/defender-endpoint-hunting.md) | PowerShell, LOLBins, LSASS, persistence, ransomware precursors |
| [`sentinel-kql/network-and-beaconing-hunting.md`](sentinel-kql/network-and-beaconing-hunting.md) | Beaconing, new destinations, exfiltration, DNS abuse |
| [`sentinel-kql/azure-activity-hunting.md`](sentinel-kql/azure-activity-hunting.md) | Role assignments, tampering, Key Vault, NSG exposure |
| [`sentinel-kql/suspicious-scheduled-task.md`](sentinel-kql/suspicious-scheduled-task.md) | Suspicious scheduled tasks |
| [`sentinel-kql/waf-ja4-hunting.md`](sentinel-kql/waf-ja4-hunting.md) | JA4 clustering of distributed web attacks |

### Network (command line)

| Query set | Covers |
|---|---|
| [`network/zeek-hunting.md`](network/zeek-hunting.md) | Zeek conn, dns, http, ssl and files logs |
| [`network/suricata-eve-hunting.md`](network/suricata-eve-hunting.md) | Suricata EVE JSON with jq |
| [`network/tshark-hunting-cheatsheet.md`](network/tshark-hunting-cheatsheet.md) | Packet capture triage with tshark |
| [`network/tshark-zeek-ja4.md`](network/tshark-zeek-ja4.md) | JA4 from captures and Zeek |

## How each file is laid out

Every query set follows the same structure so it can be reviewed quickly:

1. **Goal:** the behavior being hunted
2. **Data needed:** the telemetry or log source
3. **ATT&CK:** technique mapping
4. **Query:** the template
5. **False positives and tuning:** what normally triggers it and how to cut noise
6. **Next steps:** what to pivot on when it fires

## Related write-ups

The reasoning behind these queries is written up in my articles:

- [ClickFix and CrowdStrike hunting](https://hahashem.github.io/article.html?slug=dfir-clickfix-investigation)
- [Hunting distributed attacks with JA4](https://hahashem.github.io/article.html?slug=ja4-fingerprint-hunting)
- [DFIR case study: phishing to lateral movement](https://hahashem.github.io/article.html?slug=dfir-phishing-to-lateral-movement)

## Contributing and feedback

Found a field that is wrong for your sensor version, or a better filter? Open an issue or pull request with what you changed and why.

## License

[MIT](LICENSE)
