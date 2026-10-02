# Lateral movement hunting: CrowdStrike Falcon

## Goal
Find remote execution and movement between hosts: PsExec-style services, WMI, WinRM, RDP tunnelling and admin share use.

## Data needed
`ProcessRollup2`, `NetworkConnectIP4`, `UserLogon`, `DnsRequest`. Logon fields such as `LogonType` and `RemoteAddressIP4` depend on your telemetry.

## ATT&CK
T1021.001 RDP · T1021.002 SMB/Admin Shares · T1021.006 WinRM · T1047 WMI · T1569.002 Service Execution · T1570 Lateral Tool Transfer

> Validate field names on a short range first.

## 1. PsExec and clones
```
#event_simpleName=ProcessRollup2 event_platform=Win
| FileName=/^(psexec|psexec64|psexesvc|paexec|remcom)\.exe$/i OR CommandLine=/psexec/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
```

## 2. Services started by a remote service-control connection
```
#event_simpleName=ProcessRollup2 event_platform=Win
| ParentBaseFileName=/^services\.exe$/i
| CommandLine=/(cmd(\.exe)?\s+\/c|powershell|\\\\127\.0\.0\.1\\(admin|c)\$)/i
| table([@timestamp, ComputerName, FileName, CommandLine])
```
A service whose command line runs `cmd /c` with output redirected to an admin share is typical of tools such as Impacket's `smbexec`.

## 3. WMI remote process creation
```
#event_simpleName=ProcessRollup2 event_platform=Win
| ParentBaseFileName=/^wmiprvse\.exe$/i
| FileName=/^(cmd|powershell|pwsh|rundll32|regsvr32|mshta)\.exe$/i
| table([@timestamp, ComputerName, UserName, FileName, CommandLine])
```

## 4. WinRM
```
#event_simpleName=ProcessRollup2 event_platform=Win
| ParentBaseFileName=/^wsmprovhost\.exe$/i
| table([@timestamp, ComputerName, UserName, FileName, CommandLine])
```
Also search for `Enter-PSSession`, `Invoke-Command` and `winrs` in command lines.

## 5. Admin share and remote file copy from the command line
```
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(copy|xcopy|robocopy|move).*\\\\[^\\\s]+\\(c|admin|ipc)\$/i
| table([@timestamp, ComputerName, UserName, CommandLine])
```

## 6. Workstations connecting to many internal hosts on SMB, RDP or WinRM
```
#event_simpleName=NetworkConnectIP4 event_platform=Win
| in(RemotePort, values=[445, 3389, 5985, 5986])
| cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
| groupBy([ComputerName, RemotePort], function=[count(RemoteAddressIP4, distinct=true, as=targets), min(@timestamp, as=first_seen)])
| targets > 10
| sort(targets, order=desc)
```
Adjust the threshold to your environment. Administrative and vulnerability scanning hosts will appear, so allowlist them.

## 7. Interactive logons with unusual source
```
#event_simpleName=UserLogon event_platform=Win
| in(LogonType, values=[3, 10])
| groupBy([UserName], function=[count(ComputerName, distinct=true, as=hosts), count(as=logons)])
| hosts > 5
| sort(hosts, order=desc)
```
One account touching many machines in a short window deserves review.

## False positives and tuning
IT administration, patching, and remote management tools. Baseline which accounts and source hosts normally perform remote administration.

## Next steps
Identify the source host and the account used, then work backward to initial access and forward to the data or systems touched. See [credential-access.md](credential-access.md).
