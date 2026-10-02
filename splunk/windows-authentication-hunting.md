# Windows authentication hunting: Splunk

## Goal
Find brute force, password spraying, suspicious logon types, explicit-credential use and account manipulation using Windows Security events.

## Data needed
Windows Security log: 4624 (success), 4625 (failure), 4648 (explicit credentials), 4672 (special privileges), 4720/4728/4732/4738 (account and group changes), 4768/4769 (Kerberos), 1102/4719 (audit tampering). Field names follow the Splunk Add-on for Microsoft Windows (`Account_Name`, `Source_Network_Address`, `Logon_Type`, `Workstation_Name`) and vary by version.

## ATT&CK
T1110 Brute Force · T1078 Valid Accounts · T1021 Remote Services · T1136 Create Account · T1098 Account Manipulation · T1558.003 Kerberoasting

## 1. Brute force: many failures for one account
```
index=wineventlog source="WinEventLog:Security" EventCode=4625 earliest=-1h
| stats count dc(Source_Network_Address) as sources min(_time) as first max(_time) as last by Account_Name
| where count>=20
| convert ctime(first) ctime(last)
| sort - count
```

## 2. Password spraying: one source, many accounts
```
index=wineventlog source="WinEventLog:Security" EventCode=4625 earliest=-1h
| stats count dc(Account_Name) as accounts values(Account_Name) as sample by Source_Network_Address
| where accounts>=10
| sort - accounts
```

## 3. Failures followed by a success
```
index=wineventlog source="WinEventLog:Security" (EventCode=4625 OR EventCode=4624) earliest=-4h
| eval result=if(EventCode=4624,"success","fail")
| stats count(eval(result="fail")) as fails count(eval(result="success")) as successes max(eval(if(result="success",_time,null()))) as last_success by Account_Name, Source_Network_Address
| where fails>=10 AND successes>=1
| convert ctime(last_success)
```

## 4. Network logons (type 3) from workstations to many hosts
```
index=wineventlog source="WinEventLog:Security" EventCode=4624 Logon_Type=3 earliest=-4h
| where Account_Name!="ANONYMOUS LOGON" AND NOT match(Account_Name,"\$$")
| stats dc(host) as hosts values(host) as targets by Account_Name, Source_Network_Address
| where hosts>=8
| sort - hosts
```
One account touching many hosts quickly is a lateral-movement pattern. Scanners and admin tools will also appear.

## 5. Explicit credential use (4648)
```
index=wineventlog source="WinEventLog:Security" EventCode=4648 earliest=-24h
| stats count dc(Target_Server_Name) as targets values(Target_Server_Name) as target_list by Account_Name, Process_Name
| where targets>=5
```

## 6. Remote interactive (RDP) logons from unusual sources
```
index=wineventlog source="WinEventLog:Security" EventCode=4624 Logon_Type=10 earliest=-7d
| stats count min(_time) as first dc(host) as hosts by Account_Name, Source_Network_Address
| where first>relative_time(now(),"-1d")
| convert ctime(first)
```
New account-and-source pairs for RDP in the last day.

## 7. New accounts and privileged group changes
```
index=wineventlog source="WinEventLog:Security" (EventCode=4720 OR EventCode=4728 OR EventCode=4732 OR EventCode=4756) earliest=-24h
| table _time host EventCode Subject_Account_Name Member_Name Group_Name Target_Account_Name
```

## 8. Kerberoasting indicator: many service ticket requests with RC4
```
index=wineventlog source="WinEventLog:Security" EventCode=4769 Ticket_Encryption_Type=0x17 Service_Name!="krbtgt" Service_Name!="*$" earliest=-1h
| stats count dc(Service_Name) as services values(Service_Name) as sample by Account_Name, Client_Address
| where services>=5
```
RC4 tickets are less common in modern environments, which helps this stand out. Verify what your domain normally issues.

## 9. Audit log cleared or policy changed
```
index=wineventlog source="WinEventLog:Security" (EventCode=1102 OR EventCode=4719) earliest=-7d
| table _time host EventCode Subject_Account_Name
```

## False positives and tuning
Service accounts, vulnerability scanners, monitoring systems and shared jump hosts. Build allowlists by account and source and review them regularly. Choose thresholds from your own baseline.

## Next steps
For a successful logon after failures, identify what the account did next. Check for new sessions, services and process execution on the target ([lateral-movement-and-persistence.md](lateral-movement-and-persistence.md)).
