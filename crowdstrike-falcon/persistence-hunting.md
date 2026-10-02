# Persistence hunting: CrowdStrike Falcon

## Goal
Find how an attacker keeps access after the first execution: scheduled tasks, Run keys, services, WMI and startup folders.

## Data needed
`ScheduledTaskRegistered`, `AsepValueUpdate`, `ServiceStarted`/`ProcessRollup2`, `NewExecutableWritten`, `NewScriptWritten`. Event availability depends on sensor version and policy.

## ATT&CK
T1053.005 Scheduled Task · T1547.001 Registry Run Keys / Startup Folder · T1543.003 Windows Service · T1546.003 WMI Event Subscription

> Validate field names in your tenant first.

## 1. Scheduled tasks pointing at user-writable paths or scripts
```
#event_simpleName=ScheduledTaskRegistered event_platform=Win
| TaskExecCommand=/(\\appdata\\|\\temp\\|\\users\\public\\|\\programdata\\|powershell|mshta|wscript|cscript|cmd\.exe\s+\/c|https?:\/\/)/i
| table([@timestamp, ComputerName, UserName, TaskName, TaskExecCommand, TaskExecArguments])
```

## 2. Task creation from the command line
```
#event_simpleName=ProcessRollup2 event_platform=Win
| FileName=/^schtasks\.exe$/i
| CommandLine=/\/create/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, CommandLine])
```
Pay attention to `/ru SYSTEM`, `/sc onlogon`, `/sc minute` and tasks pointing at scripts.

## 3. Run and RunOnce keys
```
#event_simpleName=AsepValueUpdate event_platform=Win
| RegObjectName=/\\(Run|RunOnce)$/i
| table([@timestamp, ComputerName, RegObjectName, RegValueName, RegStringValue])
```

## 4. New services running from odd places
```
#event_simpleName=ProcessRollup2 event_platform=Win
| ParentBaseFileName=/^services\.exe$/i
| ImageFileName=/\\(users|programdata|temp|appdata)\\/i
| table([@timestamp, ComputerName, FileName, ImageFileName, CommandLine, SHA256HashData])
```

## 5. Service creation from the command line
```
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(sc(\.exe)?\s+(\\\\\S+\s+)?create|new-service|binpath=)/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, CommandLine])
```

## 6. WMI persistence
```
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(__eventfilter|commandlineeventconsumer|activescripteventconsumer|set-wmiinstance.*eventconsumer)/i
| table([@timestamp, ComputerName, UserName, FileName, CommandLine])
```

## 7. Scripts or executables dropped in startup folders
```
(#event_simpleName=NewExecutableWritten OR #event_simpleName=NewScriptWritten)
| TargetFileName=/\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\/i
| table([@timestamp, ComputerName, ContextBaseFileName, TargetFileName, SHA256HashData])
```

## False positives and tuning
Software updaters create tasks and Run keys constantly. Group by `TaskName` or `RegValueName` across the fleet and focus on items that exist on one or two hosts.

## Next steps
Get the full task or service definition, the binary hash and the creating process, then search that hash fleet-wide ([powershell-download-hunting.md](powershell-download-hunting.md), query 6).
