# ClickFix hunting: CrowdStrike Falcon Advanced Event Search

## Goal
Find hosts where a user was tricked into pasting and running a command (fake CAPTCHA or "fix this error" pages that tell the user to press Win+R, Ctrl+V, Enter), and follow the resulting process activity.

## Data needed
Falcon sensor telemetry in Advanced Event Search (LogScale query language): `ProcessRollup2`, `DnsRequest`, `NetworkConnectIP4`, `NewExecutableWritten`, `ScheduledTaskRegistered`, and optionally registry events such as `RegGenericValueUpdate`. Registry visibility depends on your prevention policy.

## ATT&CK
T1204.004 Malicious Copy and Paste · T1189 Drive-by Compromise · T1059.001 PowerShell · T1218.005 Mshta · T1105 Ingress Tool Transfer · T1053.005 Scheduled Task

> **Validate before use.** Field names are standard Falcon telemetry but can differ by sensor version and tenant. Start with a short time range.

---

## 1. Explorer launching a scripting host with download or hidden-window behavior
```
#event_simpleName=ProcessRollup2 event_platform=Win
| ParentBaseFileName=/^explorer\.exe$/i
| FileName=/^(powershell|pwsh|mshta|cmd|wscript|cscript|curl|bitsadmin|certutil)\.exe$/i
| CommandLine=/(-w(indowstyle)?\s+hidden|-enc|iex|invoke-expression|\birm\b|\biwr\b|downloadstring|https?:\/\/)/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine], limit=200)
| sort(@timestamp, order=desc)
```
**False positives:** admin scripts, software installers, helpdesk tools. Build an allowlist from confirmed benign results.

## 2. Lure phrasing inside the command line
```
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(captcha|not a robot|verification id|human verification|verify you are human|cloudflare)/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
```
Catches the trailing-comment trick even if the downloader changes.

## 3. Other launch paths (Windows Terminal variant)
```
#event_simpleName=ProcessRollup2 event_platform=Win
| ParentBaseFileName=/^(WindowsTerminal|wt|explorer)\.exe$/i
| FileName=/^(powershell|pwsh|cmd)\.exe$/i
| CommandLine=/(\birm\b|\biwr\b|iex|downloadstring|mshta|https?:\/\/)/i
| groupBy([ComputerName, UserName, ParentBaseFileName, FileName], function=[count(as=hits), min(@timestamp, as=first_seen)])
| sort(hits, order=desc)
```

## 4. Pivot from a suspect process
Note the `aid` and `TargetProcessId` of the suspicious process from query 1, then:
```
// Children of the suspect process
#event_simpleName=ProcessRollup2 aid=<AID> ParentProcessId=<TargetProcessId>
| table([@timestamp, FileName, CommandLine, SHA256HashData])
```
```
// DNS lookups made by the suspect process
#event_simpleName=DnsRequest aid=<AID> ContextProcessId=<TargetProcessId>
| table([@timestamp, DomainName])
```
```
// Network connections made by the suspect process
#event_simpleName=NetworkConnectIP4 aid=<AID> ContextProcessId=<TargetProcessId>
| table([@timestamp, RemoteAddressIP4, RemotePort])
```

**Advanced (join parent and children in one query, untested pattern):**
```
#event_simpleName=ProcessRollup2 event_platform=Win
| case {
    ParentBaseFileName=/^explorer\.exe$/i FileName=/^powershell\.exe$/i | key := TargetProcessId ;
    * | key := ParentProcessId
  }
| selfJoinFilter([aid, key], where=[
    { ParentBaseFileName=/^explorer\.exe$/i FileName=/^powershell\.exe$/i CommandLine=/https?:\/\//i },
    { ParentBaseFileName=/^powershell\.exe$/i }
  ])
| table([@timestamp, ComputerName, ParentBaseFileName, FileName, CommandLine])
```

## 5. Executables written to user-writable folders by scripting hosts
```
#event_simpleName=NewExecutableWritten event_platform=Win
| ContextBaseFileName=/^(powershell|pwsh|mshta|cmd|curl)\.exe$/i
| TargetFileName=/\\(AppData|Temp|ProgramData|Users\\Public)\\/i
| table([@timestamp, ComputerName, UserName, ContextBaseFileName, TargetFileName, SHA256HashData])
```

## 6. Stack rare domains contacted by scripting hosts (fleet-wide)
```
#event_simpleName=DnsRequest event_platform=Win
| ContextBaseFileName=/^(powershell|pwsh|mshta|wscript|cscript)\.exe$/i
| groupBy([DomainName], function=[count(aid, distinct=true, as=hosts), count(as=lookups)])
| sort(hosts, order=asc, limit=100)
```
Domains contacted from only one or two hosts are the interesting ones.

## 7. Run dialog evidence in the registry (if registry telemetry is enabled)
```
#event_simpleName=RegGenericValueUpdate event_platform=Win
| RegObjectName=/\\Explorer\\RunMRU/i
| table([@timestamp, ComputerName, UserName, RegObjectName, RegValueName, RegStringValue])
```
If registry events aren't collected, take `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` from the host directly.

## 8. Persistence follow-up
```
#event_simpleName=ScheduledTaskRegistered event_platform=Win
| TaskExecCommand=/(powershell|mshta|AppData|Temp)/i
| table([@timestamp, ComputerName, UserName, TaskName, TaskExecCommand])
```

## 9. Scope: who else ran the same command?
```
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/<indicator-domain-or-distinctive-string>/i
| groupBy([ComputerName, UserName], function=[count(as=runs), min(@timestamp, as=first_seen)])
```

## Next steps when it fires
1. Network-contain the host and collect RunMRU, browser history, PowerShell logs and any dropped binary.
2. Treat browser-saved credentials and session cookies as exposed: reset the password **and** revoke sessions and tokens.
3. Block the domain and IP, then scope with query 9.
