# Office applications spawning scripting hosts (Splunk, Sysmon)

## Goal
Detect Word, Excel or other Office processes launching PowerShell, cmd or script hosts, a classic sign of a malicious macro.

## Data needed
Sysmon Event ID 1 (process creation) indexed in Splunk. Field names below follow common Sysmon add-on extractions; adjust to your sourcetype.

## ATT&CK
T1566.001 Spearphishing Attachment · T1204.002 User Execution · T1059.001 PowerShell

## Query
```
index=sysmon EventCode=1 ParentImage="*\\WINWORD.EXE" Image IN ("*\\powershell.exe","*\\cmd.exe","*\\wscript.exe")
| stats count min(_time) as first by host, user, CommandLine
```

Variant covering more Office parents:
```
index=sysmon EventCode=1
  ParentImage IN ("*\\WINWORD.EXE","*\\EXCEL.EXE","*\\POWERPNT.EXE","*\\OUTLOOK.EXE")
  Image IN ("*\\powershell.exe","*\\pwsh.exe","*\\cmd.exe","*\\wscript.exe","*\\cscript.exe","*\\mshta.exe")
| stats count min(_time) as first_seen values(CommandLine) as commands by host, user, ParentImage, Image
```

## False positives and tuning
- Legitimate add-ins and finance macros that call scripts. Allowlist by `CommandLine` pattern and host group once confirmed.
- Document management and reporting tools.
- Look for encoded or download-style commands to raise confidence: `-enc`, `-w hidden`, `DownloadString`, `http`.

## Next steps
1. Pull the full command line and decode any base64.
2. Check PowerShell Script Block Logging (4104) for the decoded content, if enabled.
3. Look at what the child process did next: network connections, file writes, scheduled tasks.
