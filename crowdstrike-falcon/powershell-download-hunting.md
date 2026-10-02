# PowerShell download hunting: CrowdStrike Falcon

## Goal
Find PowerShell (and similar tools) downloading content, then recover the **file name, path, SHA256, source URL, domain and IP**, and scope it across the fleet.

## Data needed
Falcon Advanced Event Search (LogScale syntax): `ProcessRollup2`, `NewExecutableWritten`, `NewScriptWritten`, `DnsRequest`, `NetworkConnectIP4`.

## ATT&CK
T1059.001 PowerShell · T1105 Ingress Tool Transfer · T1036.003 Rename System Utilities

> Full walk-through: [Hunting PowerShell downloads in CrowdStrike and Splunk](https://hahashem.github.io/article.html?slug=crowdstrike-powershell-download-hunting). Validate field names on a short time range first.

## 1. PowerShell with download behavior, URL extracted
```
#event_simpleName=ProcessRollup2 event_platform=Win
| FileName=/^(powershell|pwsh)\.exe$/i
| CommandLine=/(downloadstring|downloadfile|downloaddata|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b|start-bitstransfer|net\.webclient)/i
| CommandLine=/(?<source_url>https?:\/\/[^\s"'`)]+)/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, SHA256HashData, source_url, CommandLine], limit=200)
```

## 2. Encoded commands
```
#event_simpleName=ProcessRollup2 event_platform=Win
| FileName=/^(powershell|pwsh)\.exe$/i
| CommandLine=/\s-e(nc|ncodedcommand)?\s+[A-Za-z0-9+\/=]{40,}/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, CommandLine])
```
Decode the base64 as UTF-16LE to read it.

## 3. Files written by PowerShell (name, path, hash)
```
#event_simpleName=NewExecutableWritten event_platform=Win
| ContextBaseFileName=/^(powershell|pwsh)\.exe$/i
| table([@timestamp, ComputerName, UserName, TargetFileName, SHA256HashData])
```

## 4. Domains PowerShell resolved, rarest first
```
#event_simpleName=DnsRequest event_platform=Win
| ContextBaseFileName=/^(powershell|pwsh)\.exe$/i
| groupBy([DomainName], function=[count(aid, distinct=true, as=hosts), min(@timestamp, as=first_seen)])
| sort(hosts, order=asc, limit=100)
```

## 5. PowerShell outside its normal location
```
#event_simpleName=ProcessRollup2 event_platform=Win
| FileName=/^(powershell|pwsh)\.exe$/i
| not ImageFileName=/\\(Windows\\(System32|SysWOW64)\\WindowsPowerShell\\v1\.0|Program Files\\PowerShell\\\d+)\\(powershell|pwsh)\.exe$/i
| table([@timestamp, ComputerName, UserName, ImageFileName, SHA256HashData, CommandLine])
```

## 6. Scope a hash across the fleet
```
(#event_simpleName=ProcessRollup2 or #event_simpleName=NewExecutableWritten)
| SHA256HashData="<sha256>"
| groupBy([ComputerName, #event_simpleName], function=[min(@timestamp, as=first_seen)])
| sort(first_seen, order=asc)
```

## False positives and tuning
Software deployment, monitoring agents and admin scripts download legitimately. Allowlist by parent process, destination domain and host group after confirming each.

## Next steps
Record name, path, SHA256, URL, domain and IP. Check the parent process. Look for persistence ([persistence-hunting.md](persistence-hunting.md)). Confirm in proxy and firewall logs.
