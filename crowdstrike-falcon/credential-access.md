# Credential access hunting: CrowdStrike Falcon

## Goal
Find attempts to dump credentials from memory, the registry or the domain controller.

## Data needed
`ProcessRollup2`, `CommandHistory`, and (where your policy records them) `ProcessInjection`-style or handle-access detections. Memory-access telemetry is limited, so these queries rely mostly on **command lines** and **tool names**. Falcon prevention may already block the most common techniques, so also review detections in the console.

## ATT&CK
T1003.001 LSASS Memory · T1003.002 SAM · T1003.003 NTDS · T1003.006 DCSync · T1558.003 Kerberoasting · T1552 Unsecured Credentials

> Validate on a short range. Findings are leads, not verdicts.

## 1. LSASS dumping with built-in tools
```
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(comsvcs(\.dll)?[, ]+(#?24|minidump)|procdump.*lsass|lsass.*\.dmp|sqldumper|createdump.*lsass|rundll32.*comsvcs)/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
```

## 2. Registry hive saves (SAM, SYSTEM, SECURITY)
```
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/reg(\.exe)?\s+save\s+hklm\\(sam|system|security)/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, CommandLine])
```

## 3. NTDS.dit extraction
```
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(ntdsutil.*(ifm|snapshot)|ntds\.dit|vssadmin.*create\s+shadow|diskshadow)/i
| table([@timestamp, ComputerName, UserName, FileName, CommandLine])
```

## 4. Well-known credential tool names and arguments
```
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(sekurlsa|lsadump|kerberos::|privilege::debug|invoke-mimikatz|rubeus|kerberoast|asktgt|dcsync|secretsdump)/i
| table([@timestamp, ComputerName, UserName, FileName, CommandLine])
```

## 5. Dump files written to disk
```
#event_simpleName=NewExecutableWritten OR #event_simpleName=PeFileWritten OR #event_simpleName=NewScriptWritten
| TargetFileName=/(lsass|ntds|sam|system).*\.(dmp|dit|hiv|bak|zip|7z|rar)$/i
| table([@timestamp, ComputerName, ContextBaseFileName, TargetFileName])
```
Dump files are not always classified as executables, so also check file-written events your tenant records.

## 6. Kerberoasting-style tooling (command line)
```
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(setspn.*-q.*\*|get-domainspnticket|invoke-kerberoast|GetUserSPNs)/i
| table([@timestamp, ComputerName, UserName, CommandLine])
```

## False positives and tuning
Backup and crash-dump tools, authorized red-team and pen-test activity, and admin use of `setspn`. Maintain a list of approved testing hosts and accounts.

## Next steps
Isolate the host if confirmed. Treat every credential on that machine as exposed and plan resets. Look for the next hop with [lateral-movement.md](lateral-movement.md).
