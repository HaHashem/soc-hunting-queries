# Lateral movement and persistence hunting: Splunk (Sysmon and Security logs)

## Goal
Find remote execution, new services and tasks, Run key changes and WMI persistence.

## Data needed
Sysmon: Event ID 1 (process), 11 (file create), 12/13 (registry), 19/20/21 (WMI). Windows Security: 4698 (task created), 7045 in the System log (service installed), 5140/5145 (share access). Index and sourcetype names are placeholders.

## ATT&CK
T1021.002 SMB/Admin Shares · T1569.002 Service Execution · T1047 WMI · T1053.005 Scheduled Task · T1543.003 Windows Service · T1547.001 Run Keys · T1546.003 WMI Subscription

## 1. New service installed (7045)
```
index=wineventlog source="WinEventLog:System" EventCode=7045 earliest=-24h
| table _time host Service_Name Service_File_Name Service_Type Service_Start_Type
| where match(Service_File_Name,"(?i)(cmd\.exe|powershell|\\\\users\\\\|\\\\temp\\\\|\\\\programdata\\\\|%comspec%)")
```
A service running `cmd /c` or a path in a user-writable folder is a strong lead.

## 2. PsExec and look-alikes
```
index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  (Image="*\\psexesvc.exe" OR Image="*\\paexec.exe" OR Image="*\\psexec*.exe" OR ParentImage="*\\psexesvc.exe")
| table _time Computer User ParentImage Image CommandLine
```

## 3. Remote process creation by WMI and WinRM
```
index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  ParentImage IN ("*\\wmiprvse.exe","*\\wsmprovhost.exe")
  Image IN ("*\\cmd.exe","*\\powershell.exe","*\\pwsh.exe","*\\rundll32.exe","*\\mshta.exe","*\\regsvr32.exe")
| stats count values(CommandLine) as cmds by Computer, User, ParentImage
```

## 4. Admin share file writes (5145)
```
index=wineventlog source="WinEventLog:Security" EventCode=5145 Share_Name IN ("\\\\*\\ADMIN$","\\\\*\\C$") Relative_Target_Name IN ("*.exe","*.dll","*.bat","*.ps1")
| stats count values(Relative_Target_Name) as files by Account_Name, Source_Address, host
```
Executables written to an admin share by a remote account are a classic lateral tool transfer.

## 5. Scheduled task creation (4698) and command-line creation
```
index=wineventlog source="WinEventLog:Security" EventCode=4698 earliest=-24h
| rex field=Task_Content "<Command>(?<cmd>[^<]+)</Command>"
| rex field=Task_Content "<Arguments>(?<args>[^<]+)</Arguments>"
| table _time host Account_Name Task_Name cmd args
```
```
index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  Image="*\\schtasks.exe" CommandLine="*/create*"
| table _time Computer User ParentImage CommandLine
```

## 6. Run key and startup persistence (Sysmon 13)
```
index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
  TargetObject IN ("*\\CurrentVersion\\Run\\*","*\\CurrentVersion\\RunOnce\\*","*\\Winlogon\\Shell*","*\\Winlogon\\Userinit*")
| stats count values(Details) as value by Computer, Image, TargetObject
| sort - count
```

## 7. WMI event subscription (Sysmon 19, 20, 21)
```
index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode IN (19,20,21)
| table _time Computer User EventCode Name Query Destination Consumer Filter
```

## 8. Executables created in startup folders (Sysmon 11)
```
index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
  TargetFilename="*\\Start Menu\\Programs\\Startup\\*"
| table _time Computer Image TargetFilename
```

## False positives and tuning
Software installers, patch agents, backup and EDR products create services and tasks. Find items present on only one or two hosts, and compare against change records.

## Next steps
Hash the binary or script, check its creation time and creating process, and search for it across the environment.
