# Ransomware: identity, backup and email hunting (Splunk and KQL)

## Goal
Cover the places ransomware operators use that endpoint and network rules often miss: **domain controllers**, **backup systems** and **email delivery**.

## Data needed
Windows Security logs from domain controllers, backup platform logs (Veeam and similar), hypervisor logs, and email telemetry (`EmailEvents`, `EmailUrlInfo`, `EmailAttachmentInfo` in Defender). Field names below are common defaults and may differ.

## ATT&CK
T1566 Phishing · T1003.006 DCSync · T1003.003 NTDS · T1484 Domain Policy Modification · T1098 Account Manipulation · T1490 Inhibit System Recovery · T1485 Data Destruction

> Validate on a short range. Domain controller and backup alerts deserve fast human review.

---

# A. Domain controllers and Active Directory

## A1. DCSync: replication rights used by a non-DC (Splunk, Event 4662)
```
index=wineventlog source="WinEventLog:Security" EventCode=4662 earliest=-24h
  (Properties="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*" OR Properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*" OR Properties="*89e95b76-444d-4c62-991a-0facbeda640c*")
| search NOT Account_Name="*$"
| table _time host Account_Name Properties
```
Requires the "Audit Directory Service Access" policy. Domain controller machine accounts end in `$`. A user account performing replication is a high-priority lead.

## A2. DCSync in KQL (Defender for Identity or Sentinel)
```kql
IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType == "Directory Services replication"
| project Timestamp, AccountUpn, DeviceName, IPAddress, ActionType, AdditionalFields
```
Table availability requires Microsoft Defender for Identity.

## A3. New privileged group members (Splunk)
```
index=wineventlog source="WinEventLog:Security" (EventCode=4728 OR EventCode=4732 OR EventCode=4756) earliest=-24h
  (Group_Name="Domain Admins" OR Group_Name="Enterprise Admins" OR Group_Name="Administrators" OR Group_Name="Backup Operators" OR Group_Name="Schema Admins")
| table _time host Subject_Account_Name Member_Name Group_Name
```

## A4. Group Policy objects created or changed (Splunk, 5136/5137)
```
index=wineventlog source="WinEventLog:Security" (EventCode=5136 OR EventCode=5137 OR EventCode=5141) earliest=-24h
  (Object_Class="groupPolicyContainer" OR Object_Class="gPLink")
| table _time host Subject_Account_Name Object_DN Attribute_Value
```
Mass-deployment of ransomware through Group Policy is common. Review GPO changes outside change windows.

## A5. NTDS.dit extraction and shadow copy on a domain controller
```
index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 host IN ("dc01*","dc02*")
  (CommandLine="*ntdsutil*" OR CommandLine="*vssadmin*create*shadow*" OR CommandLine="*diskshadow*" OR CommandLine="*ntds.dit*")
| table _time Computer User ParentImage CommandLine
```
Replace the host patterns with your domain controllers.

## A6. Admin logons to domain controllers from unusual sources (Splunk)
```
index=wineventlog source="WinEventLog:Security" EventCode=4624 host IN ("dc01*","dc02*") Logon_Type IN (3,10) earliest=-7d
| stats count min(_time) as first by Account_Name, Source_Network_Address
| where first>relative_time(now(),"-1d")
| convert ctime(first)
```

## A7. Many accounts disabled, reset or deleted quickly
```
index=wineventlog source="WinEventLog:Security" (EventCode=4725 OR EventCode=4723 OR EventCode=4724 OR EventCode=4726) earliest=-1h
| stats count dc(Target_Account_Name) as accounts by Subject_Account_Name
| where accounts>10
```

---

# B. Backup and recovery

## B1. Backup jobs, repositories or retention deleted (Veeam example, Windows event logs)
Veeam writes to the Windows "Veeam Backup" event log on the server. Event IDs vary by version, so check your own logs. As a starting point:
```
index=wineventlog source="WinEventLog:Veeam Backup" earliest=-7d
  (Message="*deleted*" OR Message="*removed*" OR Message="*retention*" OR Message="*repository*disabled*" OR Message="*password*changed*")
| table _time host EventCode Message
```

## B2. Logons to the backup server
```
index=wineventlog source="WinEventLog:Security" EventCode=4624 host="backup*" Logon_Type IN (3,10) earliest=-7d
| stats count min(_time) as first by Account_Name, Source_Network_Address
| where first>relative_time(now(),"-2d")
| convert ctime(first)
```
Replace `backup*` with your backup server names. Unexpected interactive logons to the backup infrastructure ahead of an attack are a known pattern.

## B3. Hypervisor and datastore tampering (ESXi syslog example)
```
index=esxi earliest=-24h
  (message="*esxcli vm process kill*" OR message="*vim-cmd vmsvc/power.off*" OR message="*datastore*delete*" OR message="*ssh*enabled*" OR message="*shell*enabled*" OR message="*ssh*logged in*")
| table _time host message
```
Several ransomware families encrypt virtual machine disks by stopping VMs first. Enable SSH and shell only when needed, and alert when they are turned on. Log field names depend on your syslog setup.

## B4. Windows: backup services stopped or backup software uninstalled (KQL)
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine matches regex @"(?i)((net1?\s+stop|sc(\.exe)?\s+(stop|delete|config)).*(veeam|backup|vss|acronis|commvault|bacula|dpm|wbengine))|(msiexec.*/x.*(veeam|backup|acronis))"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```

## B5. Cloud backup or snapshot deletion (Azure and AWS)
Azure (KQL):
```kql
AzureActivity
| where TimeGenerated > ago(7d)
| where OperationNameValue has_any ("MICROSOFT.RECOVERYSERVICES/VAULTS/BACKUPFABRICS", "MICROSOFT.COMPUTE/SNAPSHOTS/DELETE", "MICROSOFT.COMPUTE/RESTOREPOINTCOLLECTIONS/DELETE", "MICROSOFT.RECOVERYSERVICES/VAULTS/DELETE")
| where OperationNameValue has_any ("DELETE", "STOPPROTECTION")
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, ActivityStatusValue
```
AWS (Splunk with CloudTrail):
```
index=aws sourcetype="aws:cloudtrail" earliest=-7d eventName IN ("DeleteSnapshot","DeleteBackupVault","DeleteRecoveryPoint","DeleteDBSnapshot","DeleteDBInstance","PutBucketVersioning","DeleteObjectVersion")
| stats count values(eventName) as events by userIdentity.arn, sourceIPAddress
```
Enable soft delete, immutability and separate backup credentials. Alerts alone do not protect backups.

---

# C. Email delivery (Defender advanced hunting)

## C1. Delivered messages with executable, script or archive attachments
```kql
EmailAttachmentInfo
| where Timestamp > ago(7d)
| where FileType in~ ("exe", "dll", "js", "vbs", "wsf", "hta", "iso", "img", "lnk", "ps1", "bat", "scr", "one", "html")
    or FileName matches regex @"(?i)\.(exe|js|vbs|wsf|hta|iso|img|lnk|ps1|bat|scr|one|html?)$"
| join kind=inner (EmailEvents | where DeliveryAction == "Delivered") on NetworkMessageId
| summarize Recipients=dcount(RecipientEmailAddress), Samples=make_set(Subject, 3) by SenderFromAddress, FileName, SHA256
| order by Recipients desc
```

## C2. Messages with links to lookalike or newly seen domains
```kql
EmailUrlInfo
| where Timestamp > ago(7d)
| join kind=inner (EmailEvents | where DeliveryAction == "Delivered") on NetworkMessageId
| summarize Messages=dcount(NetworkMessageId), Recipients=dcount(RecipientEmailAddress) by UrlDomain, SenderFromDomain
| where Recipients <= 5
| order by Messages desc
```
Rare domains sent to few recipients show targeted lures. Combine with threat intelligence and domain age.

## C3. Users who clicked, then ran something
```kql
UrlClickEvents
| where Timestamp > ago(7d)
| where ActionType in ("ClickAllowed", "ClickedThrough")
| project ClickTime=Timestamp, AccountUpn, Url, NetworkMessageId
| join kind=inner (
    DeviceProcessEvents
    | where FileName in~ ("powershell.exe", "mshta.exe", "wscript.exe", "cscript.exe", "cmd.exe")
    | project ProcTime=Timestamp, AccountUpn, DeviceName, ProcessCommandLine
  ) on AccountUpn
| where ProcTime between (ClickTime .. ClickTime + 10m)
| project ClickTime, ProcTime, AccountUpn, DeviceName, Url, ProcessCommandLine
```
`DeviceProcessEvents` may use `AccountUpn` or `AccountName`, so check the column. This ties a click to endpoint execution within a short window, which is typical of ClickFix and loader delivery.

## C4. Same attachment hash or subject sent to many recipients
```kql
EmailAttachmentInfo
| where Timestamp > ago(1d)
| summarize Recipients=dcount(RecipientEmailAddress), Senders=dcount(SenderFromAddress), Names=make_set(FileName, 3) by SHA256
| where Recipients > 20
| order by Recipients desc
```

## False positives and tuning
Legitimate software distribution, IT scripts and business mail with archives. Prioritize items that combine rare sender, rare attachment and an endpoint execution event.

## Next steps
Disable affected accounts, purge the message from mailboxes, block the sender, URL and hash, and hunt the delivered file on endpoints ([microsoft-kql.md](microsoft-kql.md), [crowdstrike.md](crowdstrike.md)).
