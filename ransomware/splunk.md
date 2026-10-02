# Ransomware hunting: Splunk (Sysmon and Windows Security)

## Goal
Find ransomware stages in Windows endpoint logs: recovery inhibition, tool tampering, mass file activity, spread, and credential access.

## Data needed
Sysmon (Event ID 1 process, 11 file create, 23/26 file delete, 13 registry), Windows Security (4624, 4688, 4697, 4698, 4672, 1102) and System (7036, 7040, 7045). Index and sourcetype names are placeholders:
`index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"`.

## ATT&CK
T1490 Inhibit System Recovery · T1486 Data Encrypted for Impact · T1489 Service Stop · T1562.001 Disable Tools · T1070.001 Clear Logs · T1021 Remote Services · T1003 Credential Dumping

> Validate on a short range. Hits on queries 1 to 4 are high priority.

## 1. Shadow copy, backup and recovery deletion
```
index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  (CommandLine="*vssadmin*delete*shadows*" OR CommandLine="*vssadmin*resize*shadowstorage*" OR CommandLine="*wmic*shadowcopy*delete*"
   OR CommandLine="*bcdedit*recoveryenabled*no*" OR CommandLine="*bcdedit*ignoreallfailures*" OR CommandLine="*wbadmin*delete*" OR CommandLine="*diskshadow*delete*")
| table _time Computer User ParentImage Image CommandLine
```

## 2. Services stopped: security, backup, database
```
index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  (CommandLine="*net stop*" OR CommandLine="*net1 stop*" OR CommandLine="*sc stop*" OR CommandLine="*sc config*" OR CommandLine="*taskkill*/im*" OR CommandLine="*Stop-Service*")
  (CommandLine="*sql*" OR CommandLine="*veeam*" OR CommandLine="*backup*" OR CommandLine="*vss*" OR CommandLine="*defender*" OR CommandLine="*windefend*" OR CommandLine="*sophos*" OR CommandLine="*exchange*" OR CommandLine="*vmms*")
| stats count values(CommandLine) as cmds by Computer, User, ParentImage
```
Many services stopped in a short window by one account is characteristic. Check the System log too:
```
index=wineventlog source="WinEventLog:System" EventCode=7036 Message="*stopped*" earliest=-1h
| stats count dc(Service_Name) as services values(Service_Name) as list by host
| where services>=8
```
Field names depend on your Windows add-on version.

## 3. Defender tampering
```
index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  (CommandLine="*Set-MpPreference*Disable*" OR CommandLine="*Add-MpPreference*Exclusion*" OR CommandLine="*DisableAntiSpyware*" OR CommandLine="*DisableRealtimeMonitoring*" OR CommandLine="*advfirewall*state*off*")
| table _time Computer User ParentImage CommandLine
```
Microsoft Defender events (Event ID 5001 real-time protection disabled, 5007 configuration changed) are also valuable:
```
index=wineventlog source="WinEventLog:Microsoft-Windows-Windows Defender/Operational" (EventCode=5001 OR EventCode=5007 OR EventCode=5010 OR EventCode=5012)
| table _time host EventCode Message
```

## 4. Event log cleared
```
index=wineventlog (source="WinEventLog:Security" EventCode=1102) OR (source="WinEventLog:System" EventCode=104)
| table _time host EventCode Account_Name
```

## 5. Mass file creation or deletion by one process (Sysmon 11 and 23)
```
index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=11 OR EventCode=23 OR EventCode=26) earliest=-1h
| bin _time span=5m
| stats count dc(TargetFilename) as files by _time, Computer, Image
| where files>500
| sort - files
```
Filter out known backup, antivirus and sync processes after review. Sysmon file delete events (23/26) must be enabled in your configuration.

## 6. Ransom notes created in many folders
```
index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11 earliest=-1h
| regex TargetFilename="(?i)(readme|how[_ -]?to[_ -]?(decrypt|recover|restore)|restore[_ -]?files|decrypt[_ -]?(instructions|files)|recover[_ -]?files).*\.(txt|html|hta|rtf)$"
| rex field=TargetFilename "(?<note>[^\\\\]+)$"
| stats count dc(TargetFilename) as locations by Computer, Image, note
| where locations>5
```

## 7. New extension appearing on many files
```
index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11 earliest=-1h
| rex field=TargetFilename "\.(?<ext>[A-Za-z0-9_\-]{3,12})$"
| stats count dc(TargetFilename) as files by Computer, Image, ext
| where files>300
| sort - files
```
Compare the extensions against what is normal for the process.

## 8. Spread: PsExec, services and remote execution
```
index=wineventlog source="WinEventLog:System" EventCode=7045 earliest=-24h
| where match(Service_File_Name,"(?i)(psexe|cmd\.exe|powershell|\\\\users\\\\|\\\\temp\\\\|\\\\programdata\\\\)")
| table _time host Service_Name Service_File_Name
```
```
index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  (Image IN ("*\\psexesvc.exe","*\\paexec.exe") OR ParentImage IN ("*\\wmiprvse.exe","*\\wsmprovhost.exe","*\\psexesvc.exe"))
| stats count values(CommandLine) as cmds by Computer, User, ParentImage
```

## 9. One binary running on many hosts at once
```
index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-1h
| where NOT match(Image,"(?i)^C:\\\\(Windows|Program Files)")
| rex field=Hashes "SHA256=(?<sha256>[A-Fa-f0-9]{64})"
| stats dc(Computer) as hosts min(_time) as first max(_time) as last values(Image) as images by sha256
| where hosts>5
| convert ctime(first) ctime(last)
| sort - hosts
```

## 10. Credential dumping that precedes spread
```
index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  (CommandLine="*comsvcs*minidump*" OR CommandLine="*procdump*lsass*" OR CommandLine="*sekurlsa*" OR CommandLine="*ntdsutil*ifm*" OR CommandLine="*reg*save*hklm\\sam*" OR CommandLine="*reg*save*hklm\\system*")
| table _time Computer User ParentImage CommandLine
```
LSASS access (Sysmon Event ID 10) also helps. Tune it carefully because many security products read LSASS:
```
index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10 TargetImage="*\\lsass.exe" earliest=-24h
| search NOT SourceImage IN ("*\\MsMpEng.exe","*\\csrss.exe","*\\wininit.exe","*\\svchost.exe","*\\services.exe","*\\CSFalconService.exe")
| stats count values(GrantedAccess) as access by Computer, SourceImage
```

## 11. Exfiltration tools on endpoints
```
index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  (Image IN ("*\\rclone.exe","*\\megasync.exe","*\\megacmd.exe","*\\winscp.exe","*\\pscp.exe","*\\psftp.exe") OR CommandLine="*rclone*copy*" OR CommandLine="*rclone*sync*" OR CommandLine="*--transfers*")
| table _time Computer User ParentImage Image CommandLine
```

## 12. Safe-mode boot changes
```
index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 CommandLine="*bcdedit*safeboot*"
| table _time Computer User CommandLine
```

## 13. Windows Security: privileged logons outside business hours
```
index=wineventlog source="WinEventLog:Security" EventCode=4672 earliest=-7d
| eval hour=strftime(_time,"%H")
| where (hour<6 OR hour>=22) AND NOT match(Account_Name,"\$$") AND Account_Name!="SYSTEM"
| stats count dc(host) as hosts values(host) as host_list by Account_Name
| where hosts>=3
| sort - hosts
```
Adjust hours and exclude service accounts you have verified.

## False positives and tuning
Administrators, patching, imaging and backup tools. Build allowlists by account, host group and process after review, and base thresholds on your own baseline.

## Next steps
Isolate confirmed hosts, collect the encryptor hash, scope it across all hosts, and review domain controllers and backups ([identity-backup-and-email.md](identity-backup-and-email.md)).
