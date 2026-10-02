# Endpoint hunting with Defender for Endpoint tables: Microsoft Sentinel (KQL)

## Goal
Hunt process, file, registry and network activity on endpoints using the Microsoft Defender XDR tables in Sentinel or in Defender advanced hunting.

## Data needed
`DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`, `DeviceLogonEvents`, `DeviceEvents`. These are available through the Microsoft Defender XDR connector in Sentinel, or directly in the Defender portal.

## ATT&CK
T1059.001 PowerShell · T1105 Ingress Tool Transfer · T1003 Credential Dumping · T1218 Signed Binary Proxy Execution · T1547 Run Keys · T1490 Inhibit System Recovery

> Validate column names in your tenant. Start with a short time range.

## 1. PowerShell download cradles with the URL
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("DownloadString", "DownloadFile", "Invoke-WebRequest", "iwr ", "Invoke-RestMethod", "irm ", "Net.WebClient", "Start-BitsTransfer")
| extend Url = extract(@"(https?://[^\s""'`)]+)", 1, ProcessCommandLine)
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, SHA256, Url, ProcessCommandLine
```

## 2. Encoded or hidden PowerShell
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)\s-(e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{40,}" or ProcessCommandLine has_any ("-WindowStyle Hidden", "-w hidden", "-nop")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```

## 3. Files PowerShell wrote (name, path, hash)
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| where InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe")
| where FileName endswith_cs ".exe" or FileName endswith_cs ".dll" or FileName endswith_cs ".ps1" or FileName endswith_cs ".bat"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FolderPath, FileName, SHA256
```

## 4. Who ran or wrote a hash (scoping)
```kql
let h = "<sha256>";
union
 (DeviceProcessEvents | where SHA256 == h | project Timestamp, DeviceName, Source="process", FileName, FolderPath),
 (DeviceFileEvents | where SHA256 == h | project Timestamp, DeviceName, Source="file", FileName, FolderPath)
| summarize First=min(Timestamp), Last=max(Timestamp) by DeviceName, Source
| order by First asc
```

## 5. Network connections from scripting hosts to public addresses
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe")
| where RemoteIPType == "Public"
| summarize Connections=count(), Devices=dcount(DeviceName), Urls=make_set(RemoteUrl, 5) by RemoteIP, RemotePort, InitiatingProcessFileName
| order by Devices asc, Connections desc
```
Destinations reached by one or two devices are the interesting ones.

## 6. LOLBin abuse with remote content
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine matches regex @"(?i)(mshta\s+https?:|regsvr32.*(/i:https?:|scrobj)|rundll32.*javascript:|certutil.*(-urlcache|-decode)|bitsadmin.*/transfer|msiexec.*/(i|q).*https?:)"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

## 7. Office applications spawning script hosts
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe")
| where FileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

## 8. LSASS access and dumping commands
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine matches regex @"(?i)(comsvcs.*(minidump|#24)|procdump.*lsass|sekurlsa|lsadump|reg\s+save\s+hklm\\(sam|system|security)|ntdsutil.*ifm)"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```

## 9. Persistence: Run keys and scheduled tasks
```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any (@"\CurrentVersion\Run", @"\CurrentVersion\RunOnce", @"\Winlogon")
| project Timestamp, DeviceName, InitiatingProcessFileName, RegistryKey, RegistryValueName, RegistryValueData
```

## 10. Ransomware precursors
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine matches regex @"(?i)(vssadmin.*delete\s+shadows|wmic.*shadowcopy.*delete|bcdedit.*(recoveryenabled\s+no|ignoreallfailures)|wbadmin.*delete|wevtutil.*\scl\s)"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```

## 11. Discovery burst: several recon tools from one parent
```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("whoami.exe","net.exe","net1.exe","nltest.exe","ipconfig.exe","systeminfo.exe","tasklist.exe","quser.exe","arp.exe","nslookup.exe","setspn.exe")
| summarize Cmds=dcount(FileName), List=make_set(FileName), First=min(Timestamp) by DeviceName, InitiatingProcessId, InitiatingProcessFileName, bin(Timestamp, 10m)
| where Cmds >= 4
```

## False positives and tuning
Admin scripts, deployment tools, security agents and developer workstations. Allowlist by device group, initiating process and destination after review.

## Next steps
Use `DeviceProcessEvents` parent/child chains (`InitiatingProcessId`, `ProcessId`) to rebuild the timeline, then scope the file hash and destination across all devices.
