# Ransomware hunting: CrowdStrike Falcon

## Goal
Find ransomware activity at each stage using Falcon Advanced Event Search (LogScale syntax).

## Data needed
`ProcessRollup2`, `NewExecutableWritten`, `NewScriptWritten`, `DnsRequest`, `NetworkConnectIP4`, `UserLogon`, `ScheduledTaskRegistered`, and file-write events such as `FileWritten`-style telemetry **if** your tenant records them. Event availability depends on sensor version and policy.

## ATT&CK
T1490 Inhibit System Recovery · T1486 Data Encrypted for Impact · T1489 Service Stop · T1562.001 Disable Tools · T1070.001 Clear Logs · T1021 Remote Services · T1048 Exfiltration · T1078 Valid Accounts

> Validate field names on a short range. Hits on queries 1 to 4 are high priority.

## 1. Shadow copy, backup and recovery deletion
```
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(vssadmin.*delete\s+shadows|vssadmin.*resize\s+shadowstorage|wmic.*shadowcopy.*delete|get-wmiobject.*shadowcopy.*delete|bcdedit.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)|wbadmin.*delete\s+(catalog|backup|systemstatebackup)|diskshadow.*delete)/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
```

## 2. Security tools and backup services stopped
```
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/((net(1)?\s+stop|sc(\.exe)?\s+(stop|config)|taskkill.*\/im|stop-service|set-service.*disabled).*(sql|veeam|backup|vss|sophos|defender|windefend|sense|crowdstrike|csagent|csfalcon|mcafee|symantec|exchange|vmms|vmware))/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, CommandLine])
```
Any attempt to stop the Falcon service or sensor should be escalated immediately.

## 3. Defender exclusions and tampering
```
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(set-mppreference.*(disablerealtimemonitoring|disableioavprotection|exclusionpath)|add-mppreference.*exclusion|reg(\.exe)?\s+add.*(disableantispyware|disablerealtimemonitoring)|netsh\s+advfirewall\s+set.*state\s+off)/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, CommandLine])
```

## 4. Event log clearing
```
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(wevtutil.*\s(cl|clear-log)\s|clear-eventlog|remove-eventlog)/i
| table([@timestamp, ComputerName, UserName, CommandLine])
```

## 5. Ransom note file names written to disk
```
(#event_simpleName=NewScriptWritten OR #event_simpleName=NewExecutableWritten OR #event_simpleName=FileOpenInfo)
| TargetFileName=/(readme|how[_ -]?to[_ -]?(decrypt|recover|restore)|restore[_ -]?files|decrypt[_ -]?(instructions|files)|recover[_ -]?files|_readme|!!!.*(read|decrypt)).*\.(txt|html|hta|rtf)$/i
| groupBy([ComputerName, TargetFileName], function=[count(as=copies), min(@timestamp, as=first_seen)])
| sort(copies, order=desc)
```
Ransom notes are usually dropped in many directories. A high `copies` count for one file name on one host is a strong sign. Use the file-event names your tenant provides.

## 6. A process creating the same new extension on very many files
Where file-write telemetry exists:
```
#event_simpleName=/^(NewExecutableWritten|PeFileWritten|FileWritten|FileOpenInfo)$/
| TargetFileName=/\.(?<ext>[A-Za-z0-9_\-]{3,12})$/
| groupBy([aid, ComputerName, ContextProcessId, ext], function=[count(as=files), min(@timestamp, as=first), max(@timestamp, as=last)])
| files > 500
| sort(files, order=desc)
```
One process writing hundreds of files with the same unusual extension within minutes is the encryption pattern. Backup and archive tools also show up, so allowlist by process name.

## 7. Mass rename or extension change from the command line
```
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(for\s+\/r.*(ren|rename)|get-childitem.*rename-item|\.(locked|encrypted|crypt|enc|lockbit|akira|blackcat)\b)/i
| table([@timestamp, ComputerName, UserName, FileName, CommandLine])
```

## 8. Exfiltration and sync tools
```
#event_simpleName=ProcessRollup2 event_platform=Win
| FileName=/^(rclone|megasync|megacmd|winscp|pscp|psftp|cyberduck|filezilla|freefilesync)\.exe$/i OR CommandLine=/(rclone\s+(copy|sync|move)|mega-put|--transfers|\bscp\s+-r)/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
```
`rclone` renamed to look like another binary is common. Also check for processes with the known rclone hash (query 9).

## 9. A hash seen on many hosts within a short time (mass deployment)
```
#event_simpleName=ProcessRollup2 event_platform=Win
| not ImageFileName=/\\(Windows|Program Files|Program Files \(x86\))\\/i
| groupBy([SHA256HashData, FileName], function=[count(aid, distinct=true, as=hosts), min(@timestamp, as=first_seen), max(@timestamp, as=last_seen)])
| hosts > 5
| sort(hosts, order=desc)
```
A non-standard binary appearing on many machines within minutes can be the encryptor being pushed by PsExec, Group Policy or a management tool.

## 10. Remote execution used to spread (PsExec, WMI, remote services)
```
#event_simpleName=ProcessRollup2 event_platform=Win
| (FileName=/^(psexec|psexec64|psexesvc|paexec|remcom)\.exe$/i OR ParentBaseFileName=/^(wmiprvse|wsmprovhost|psexesvc)\.exe$/i)
| groupBy([ComputerName], function=[count(as=events), collect([FileName, CommandLine])])
| sort(events, order=desc)
```

## 11. Safe-mode and boot-config changes (some families reboot before encrypting)
```
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(bcdedit.*safeboot|bcdedit.*\{default\}.*(safeboot|minimal|network)|reg\s+add.*\\safeboot)/i
| table([@timestamp, ComputerName, UserName, CommandLine])
```

## 12. Group Policy or logon-script changes that deploy to many hosts
```
(#event_simpleName=NewScriptWritten OR #event_simpleName=NewExecutableWritten)
| TargetFileName=/\\(SYSVOL|NETLOGON)\\/i
| table([@timestamp, ComputerName, ContextBaseFileName, TargetFileName, SHA256HashData])
```
New executables or scripts written into `SYSVOL` or `NETLOGON` can mean mass deployment is being prepared.

## 13. Timeline for one suspect host
```
aid=<aid>
| #event_simpleName=/^(ProcessRollup2|NewExecutableWritten|NewScriptWritten|DnsRequest|NetworkConnectIP4|ScheduledTaskRegistered|UserLogon)$/
| table([@timestamp, #event_simpleName, FileName, CommandLine, TargetFileName, DomainName, RemoteAddressIP4, UserName], limit=1000)
| sort(@timestamp, order=asc)
```

## False positives and tuning
Administrators, backup products, patching and imaging tools use many of these commands and create many files. Baseline by account, host group and parent process, then allowlist.

## Next steps
Isolate hosts with confirmed hits, collect the encryptor hash and note, scope the hash and account fleet-wide, and review domain controllers and backups ([identity-backup-and-email.md](identity-backup-and-email.md)).
