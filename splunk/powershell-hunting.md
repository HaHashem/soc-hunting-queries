# PowerShell hunting: Splunk

## Goal
Find suspicious PowerShell use: encoded or hidden commands, download cradles, and script-block content that reveals what actually ran.

## Data needed
- **Sysmon** process creation (Event ID 1) via the Splunk Add-on for Sysmon or Windows TA: `Image`, `ParentImage`, `CommandLine`, `User`, `Computer`.
- **PowerShell Script Block Logging** (Event ID 4104) from `Microsoft-Windows-PowerShell/Operational`.
- Index and sourcetype names below are placeholders: `index=wineventlog`, `sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`.

## ATT&CK
T1059.001 PowerShell · T1027 Obfuscated Files · T1105 Ingress Tool Transfer · T1140 Deobfuscate/Decode

## 1. Encoded commands
```
index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  Image IN ("*\\powershell.exe","*\\pwsh.exe")
  (CommandLine="* -enc *" OR CommandLine="* -e *" OR CommandLine="* -encodedcommand *")
| stats count min(_time) as first values(ParentImage) as parents by Computer, User, CommandLine
| convert ctime(first)
| sort - count
```

## 2. Hidden window, no profile, bypass policy
```
index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  Image IN ("*\\powershell.exe","*\\pwsh.exe")
  CommandLine IN ("*-w hidden*","*-windowstyle hidden*","*-nop*","*-noprofile*","*-ep bypass*","*-executionpolicy bypass*")
| stats count values(ParentImage) as parents by Computer, User, CommandLine
| sort - count
```

## 3. Download cradles in command lines
```
index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  Image IN ("*\\powershell.exe","*\\pwsh.exe")
  CommandLine IN ("*downloadstring*","*downloadfile*","*invoke-webrequest*","* iwr *","*invoke-restmethod*","* irm *","*net.webclient*","*start-bitstransfer*")
| rex field=CommandLine "(?<url>https?://[^\s\"'`)]+)"
| stats count values(url) as urls by Computer, User, ParentImage
| sort - count
```

## 4. Script block content (Event ID 4104)
```
index=wineventlog source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
  (ScriptBlockText="*FromBase64String*" OR ScriptBlockText="*DownloadString*" OR ScriptBlockText="*Invoke-Expression*"
   OR ScriptBlockText="*Net.WebClient*" OR ScriptBlockText="*VirtualAlloc*" OR ScriptBlockText="*AmsiUtils*")
| stats count min(_time) as first values(ScriptBlockText) as snippet by Computer, UserID
| convert ctime(first)
```
Script block logging captures the **deobfuscated** code, so it's often more revealing than the command line.

## 5. AMSI bypass strings
```
index=wineventlog source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
  (ScriptBlockText="*amsiInitFailed*" OR ScriptBlockText="*AmsiScanBuffer*" OR ScriptBlockText="*amsi.dll*")
| table _time Computer UserID ScriptBlockText
```

## 6. PowerShell launched by Office, browsers or script hosts
```
index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  Image IN ("*\\powershell.exe","*\\pwsh.exe")
  ParentImage IN ("*\\winword.exe","*\\excel.exe","*\\outlook.exe","*\\powerpnt.exe","*\\wscript.exe","*\\cscript.exe","*\\mshta.exe","*\\chrome.exe","*\\msedge.exe","*\\firefox.exe")
| stats count values(CommandLine) as cmd by Computer, User, ParentImage
```

## 7. Rare PowerShell command lines (stacking)
```
index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  Image IN ("*\\powershell.exe","*\\pwsh.exe") earliest=-30d
| stats count dc(Computer) as hosts by CommandLine
| where hosts=1 AND count<=2
| sort - count
```

## False positives and tuning
Management agents, installers, login scripts and admin tools. Group by `ParentImage` and `CommandLine` to find the repeating legitimate ones and exclude them.

## Next steps
Decode encoded content, extract URLs and hashes, and pivot to network logs ([proxy-and-web-hunting.md](proxy-and-web-hunting.md)).
