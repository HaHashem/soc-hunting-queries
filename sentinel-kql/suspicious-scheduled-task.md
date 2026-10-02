# Suspicious scheduled task creation (Microsoft Sentinel, KQL)

## Goal
Find scheduled tasks created with commands pointing at user-writable paths or encoded PowerShell, a common persistence method.

## Data needed
Windows Security Event 4698 ("A scheduled task was created") ingested into the `SecurityEvent` table. Requires the matching audit policy (Other Object Access Events).

## ATT&CK
T1053.005 Scheduled Task

## Query
```
SecurityEvent
| where EventID == 4698
| extend Task = tostring(EventData)
| where Task has_any ("AppData", "Temp", "-enc")
| project TimeGenerated, Computer, SubjectUserName, Task
```

## False positives and tuning
- Software updaters that legitimately create tasks under `AppData`.
- Add exclusions for known vendors by task name or publisher once confirmed.
- Task names that imitate legitimate products (for example a "sync" or "update" task running from `AppData\Roaming`) deserve a closer look.

## Next steps
1. Read the task XML for the command, arguments and trigger.
2. Check whether the binary is signed and whether it has an install record.
3. Review what created the task (parent process) around the same time.
