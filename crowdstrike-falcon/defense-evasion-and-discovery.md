# Defense evasion, discovery and impact precursors: CrowdStrike Falcon

## Goal
Find tampering with security tools and logs, attacker reconnaissance commands, and the preparation steps that precede ransomware.

## Data needed
`ProcessRollup2` and, where available, `CommandHistory`.

## ATT&CK
T1562.001 Disable or Modify Tools · T1070.001 Clear Windows Event Logs · T1490 Inhibit System Recovery · T1087/T1018/T1082/T1016 Discovery · T1218 Signed Binary Proxy Execution

> Validate on a short range. Several of these have real administrative uses.

## 1. Shadow copy and backup deletion (ransomware precursor)
```
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(vssadmin.*delete\s+shadows|wmic.*shadowcopy.*delete|bcdedit.*(recoveryenabled\s+no|ignoreallfailures)|wbadmin.*delete\s+(catalog|backup)|get-wmiobject.*shadowcopy.*delete)/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, CommandLine])
```
Treat a hit as high priority.

## 2. Event log clearing
```
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(wevtutil.*\s(cl|clear-log)\s|clear-eventlog|remove-eventlog)/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, CommandLine])
```

## 3. Defender and security tool tampering
```
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(set-mppreference.*(disable|exclusionpath|exclusionextension)|add-mppreference.*exclusion|sc(\.exe)?\s+(stop|config).*(windefend|sense|csagent|csfalconservice)|netsh\s+advfirewall.*(off|disable))/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, CommandLine])
```
Any attempt to stop or modify the Falcon sensor service should be escalated immediately.

## 4. Initial discovery burst: several recon commands from one parent
```
#event_simpleName=ProcessRollup2 event_platform=Win
| FileName=/^(whoami|net|net1|nltest|ipconfig|systeminfo|tasklist|quser|arp|route|nslookup|hostname|netstat|dsquery|setspn)\.exe$/i
| groupBy([aid, ComputerName, ParentProcessId], function=[count(FileName, distinct=true, as=distinct_cmds), collect([FileName]), min(@timestamp, as=first_seen)])
| distinct_cmds >= 4
| sort(distinct_cmds, order=desc)
```
Several different recon tools launched by the same parent within a short time is a common post-exploitation pattern.

## 5. Domain and privileged group discovery
```
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(net1?\s+(group|user|localgroup).*(domain admins|enterprise admins|administrators)|nltest.*(dclist|domain_trusts)|adfind|bloodhound|sharphound|get-adcomputer|get-aduser)/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, CommandLine])
```

## 6. Signed-binary proxy execution (LOLBins with remote content)
```
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/((regsvr32.*\/i:https?:|regsvr32.*scrobj)|(mshta\s+https?:|mshta.*javascript:)|(rundll32.*(javascript:|\\\\\S+\\)|certutil.*(-urlcache|-decode|-encode)|bitsadmin.*\/transfer|msiexec.*\/(i|q).*https?:))/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
```

## 7. Archive creation in staging paths (possible collection)
```
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(7z(a)?|rar|winrar|compress-archive).*\s(a|-a|a\s+-)\s?.*(\\users\\public|\\programdata|\\temp)/i
| table([@timestamp, ComputerName, UserName, FileName, CommandLine])
```

## False positives and tuning
Backup software, patching tools, security products, and administrators legitimately use many of these commands. Allowlist by account, host group and parent process after confirmation.

## Next steps
For a shadow-copy deletion or log-clear hit, check for encryption activity on the same host and its neighbors right away. For tool tampering, confirm sensor health and isolate if needed.
