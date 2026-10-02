# Ransomware hunting: Microsoft Defender advanced hunting and Sentinel (KQL)

## Goal
Hunt ransomware stages using Defender for Endpoint tables, which work in the Defender portal's advanced hunting or in Sentinel through the Defender XDR connector.

## Data needed
`DeviceProcessEvents`, `DeviceFileEvents`, `DeviceNetworkEvents`, `DeviceRegistryEvents`, `DeviceLogonEvents`, `DeviceEvents`, `EmailEvents`, `AlertEvidence`. In Defender advanced hunting the time column is `Timestamp`. In Sentinel with native tables it may be `TimeGenerated`. Check your schema.

## ATT&CK
T1490 Inhibit System Recovery · T1486 Data Encrypted for Impact · T1489 Service Stop · T1562.001 Disable Tools · T1070.001 Clear Logs · T1021 Remote Services · T1048 Exfiltration

> Validate on a short range. Hits on queries 1 to 5 are high priority.

## 1. Shadow copy, backup and recovery deletion
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine matches regex @"(?i)(vssadmin.*(delete\s+shadows|resize\s+shadowstorage)|wmic.*shadowcopy.*delete|bcdedit.*(recoveryenabled\s+no|ignoreallfailures)|wbadmin.*delete\s+(catalog|backup|systemstatebackup)|diskshadow.*delete)"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

## 2. Security and backup services stopped
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine matches regex @"(?i)((net1?\s+stop|sc(\.exe)?\s+(stop|config)|taskkill.*/im|stop-service|set-service.*disabled).*(sql|veeam|backup|vss|sophos|defender|windefend|sense|mcafee|symantec|exchange|vmms|vmware))"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```

## 3. Defender tampering
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine matches regex @"(?i)(set-mppreference.*(disablerealtimemonitoring|disableioavprotection|exclusionpath)|add-mppreference.*exclusion|reg(\.exe)?\s+add.*(disableantispyware|disablerealtimemonitoring)|netsh\s+advfirewall\s+set.*state\s+off)"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType in ("AntivirusDisabled", "TamperingAttempt", "AntivirusReport")
| where ActionType != "AntivirusReport" or AdditionalFields has "Exclusion"
| project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, AdditionalFields
```

## 4. Event log clearing
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine matches regex @"(?i)(wevtutil.*\s(cl|clear-log)\s|clear-eventlog|remove-eventlog)"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```

## 5. Mass file modification by one process (encryption pattern)
```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType in ("FileModified", "FileRenamed", "FileCreated")
| summarize Files=count(), Dirs=dcount(FolderPath), Exts=dcount(tostring(split(FileName, ".")[-1])), First=min(Timestamp), Last=max(Timestamp)
    by DeviceName, InitiatingProcessFileName, InitiatingProcessSHA256, bin(Timestamp, 5m)
| where Files > 500 and Dirs > 20
| order by Files desc
```
Backup, antivirus and sync tools also modify many files, so allowlist by process and hash after review.

## 6. Renames to a new extension on many files
```kql
DeviceFileEvents
| where Timestamp > ago(1d) and ActionType == "FileRenamed"
| extend NewExt = tostring(split(FileName, ".")[-1])
| summarize Files=count(), Hosts=dcount(DeviceName), Procs=make_set(InitiatingProcessFileName, 3) by NewExt
| where Files > 500
| order by Files desc
```

## 7. Ransom notes
```kql
DeviceFileEvents
| where Timestamp > ago(1d) and ActionType == "FileCreated"
| where FileName matches regex @"(?i)(readme|how[_ -]?to[_ -]?(decrypt|recover|restore)|restore[_ -]?files|decrypt[_ -]?(instructions|files)|recover[_ -]?files).*\.(txt|html|hta|rtf)$"
| summarize Copies=count(), Folders=dcount(FolderPath), First=min(Timestamp) by DeviceName, FileName, InitiatingProcessFileName
| where Copies > 5
| order by Copies desc
```
The same note dropped into many folders is very characteristic.

## 8. One binary appearing on many devices quickly (mass deployment)
```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FolderPath !startswith @"C:\Windows" and FolderPath !startswith @"C:\Program Files"
| summarize Devices=dcount(DeviceName), First=min(Timestamp), Last=max(Timestamp) by SHA256, FileName
| where Devices > 5 and datetime_diff('minute', Last, First) < 60
| order by Devices desc
```

## 9. PsExec, WMI and remote services as spread methods
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("psexec.exe", "psexec64.exe", "psexesvc.exe", "paexec.exe", "remcom.exe")
    or InitiatingProcessFileName in~ ("wmiprvse.exe", "wsmprovhost.exe", "psexesvc.exe")
| summarize Cmds=count(), Samples=make_set(ProcessCommandLine, 3) by DeviceName, InitiatingProcessFileName, FileName
| order by Cmds desc
```

## 10. Safe-mode changes
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine matches regex @"(?i)(bcdedit.*safeboot|reg\s+add.*\\safeboot)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

## 11. Exfiltration tools
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("rclone.exe", "megasync.exe", "megacmd.exe", "winscp.exe", "pscp.exe", "psftp.exe", "filezilla.exe")
    or ProcessCommandLine matches regex @"(?i)(rclone\s+(copy|sync|move)|mega-put|--transfers)"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

## 12. Large outbound transfers from a device
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteIPType == "Public" and ActionType == "ConnectionSuccess"
| summarize Connections=count(), Destinations=dcount(RemoteIP), Urls=make_set(RemoteUrl, 5) by DeviceName, InitiatingProcessFileName, bin(Timestamp, 1h)
| where Connections > 500
| order by Connections desc
```
Defender network events do not give byte counts, so use firewall or proxy logs for volume ([network-firewall-proxy-waf.md](network-firewall-proxy-waf.md)).

## 13. Credential access that usually precedes spread
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine matches regex @"(?i)(comsvcs.*(minidump|#24)|procdump.*lsass|sekurlsa|lsadump|ntdsutil.*ifm|reg\s+save\s+hklm\\(sam|system|security))"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```

## 14. Defender alerts that together suggest ransomware (triage view)
```kql
AlertInfo
| where Timestamp > ago(7d)
| where Title has_any ("ransom", "shadow", "backup", "tamper", "credential", "lateral", "Cobalt", "Mimikatz", "PsExec")
| join kind=inner AlertEvidence on AlertId
| where EntityType == "Machine"
| summarize Alerts=dcount(AlertId), Titles=make_set(Title, 8) by DeviceName
| where Alerts >= 3
| order by Alerts desc
```
Several different alert types on one device in a short window is worth escalating.

## False positives and tuning
Administrators, patching and imaging tools, backup products and sync clients. Allowlist by device group, initiating process and hash, and set thresholds from your own baseline.

## Next steps
Isolate the device in Defender, collect the encryptor hash, scope it across `DeviceProcessEvents`, and review domain controllers and backups ([identity-backup-and-email.md](identity-backup-and-email.md)).
