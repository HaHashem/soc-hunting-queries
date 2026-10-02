# Network, beaconing and exfiltration hunting: Microsoft Sentinel (KQL)

## Goal
Find command-and-control beaconing, rare or new external destinations, DNS abuse and large outbound transfers.

## Data needed
`DeviceNetworkEvents` (Defender for Endpoint), `CommonSecurityLog` (firewalls and proxies via CEF), `DnsEvents` (Windows DNS server) or vendor DNS tables, `AzureNetworkAnalytics_CL`/`AzureDiagnostics` for NSG flow logs. Column names for CEF data depend on the vendor mapping, so adjust.

## ATT&CK
T1071 Application Layer Protocol · T1568 Dynamic Resolution · T1041 Exfiltration Over C2 · T1048 Exfiltration Over Alternative Protocol · T1572 Protocol Tunneling

## 1. Beaconing from endpoints (regular intervals)
```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteIPType == "Public" and ActionType == "ConnectionSuccess"
| sort by DeviceName asc, RemoteIP asc, Timestamp asc
| extend Prev = prev(Timestamp), PrevDevice = prev(DeviceName), PrevIP = prev(RemoteIP)
| where DeviceName == PrevDevice and RemoteIP == PrevIP
| extend DeltaSec = datetime_diff('second', Timestamp, Prev)
| summarize Count=count(), AvgSec=avg(DeltaSec), StdSec=stdev(DeltaSec), Process=any(InitiatingProcessFileName) by DeviceName, RemoteIP, RemotePort
| extend Jitter = round(StdSec / AvgSec, 2)
| where Count > 40 and Jitter < 0.25
| order by Count desc
```
Low jitter with many connections suggests automation. Updaters and monitoring agents also beacon, so check the process and destination.

## 2. Newly seen external destinations
```kql
let known = DeviceNetworkEvents
    | where Timestamp between (ago(30d) .. ago(1d)) and RemoteIPType == "Public"
    | summarize by RemoteIP;
DeviceNetworkEvents
| where Timestamp > ago(1d) and RemoteIPType == "Public"
| join kind=leftanti known on RemoteIP
| summarize Devices=dcount(DeviceName), Connections=count(), Processes=make_set(InitiatingProcessFileName, 5) by RemoteIP, RemotePort
| where Devices <= 2
| order by Connections desc
```

## 3. Rare processes talking to the internet
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d) and RemoteIPType == "Public"
| summarize Devices=dcount(DeviceName), Connections=count(), Destinations=dcount(RemoteIP) by InitiatingProcessFileName, InitiatingProcessSHA256
| where Devices <= 2
| order by Connections desc
```

## 4. Large outbound transfers (firewall or proxy, CEF)
```kql
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where isnotempty(SentBytes)
| summarize TotalSent=sum(tolong(SentBytes)), Sessions=count() by SourceIP, DestinationIP, DestinationPort
| where TotalSent > 100000000
| extend SentMB = round(TotalSent / 1048576.0, 1)
| order by TotalSent desc
```
Choose the threshold from your baseline. Backups and cloud sync will appear.

## 5. Internal hosts scanning many addresses or ports
```kql
CommonSecurityLog
| where TimeGenerated > ago(1h)
| where DeviceAction in ("Deny", "Drop", "deny", "drop", "blocked")
| summarize Targets=dcount(DestinationIP), Ports=dcount(DestinationPort), Attempts=count() by SourceIP
| where Targets > 50 or Ports > 50
| order by Attempts desc
```

## 6. DNS: many unique long subdomains under one domain (tunneling)
```kql
DnsEvents
| where TimeGenerated > ago(1h)
| where isnotempty(Name)
| extend Labels = split(Name, ".")
| extend Base = strcat(tostring(Labels[array_length(Labels)-2]), ".", tostring(Labels[array_length(Labels)-1]))
| summarize Unique=dcount(Name), AvgLen=avg(strlen(Name)) by ClientIP, Base
| where Unique > 200 and AvgLen > 30
| order by Unique desc
```
The simple split does not handle suffixes such as `co.uk`.

## 7. DNS: NXDOMAIN bursts
```kql
DnsEvents
| where TimeGenerated > ago(1h)
| where ResultCode == 3
| summarize Failed=dcount(Name), Total=count() by ClientIP
| where Failed > 100
| order by Failed desc
```

## 8. Direct connections to IP addresses on web ports from scripting hosts
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe")
| where RemotePort in (80, 443, 8080, 8443) and isempty(RemoteUrl)
| summarize Count=count(), Devices=dcount(DeviceName) by RemoteIP, InitiatingProcessFileName
| order by Count desc
```

## 9. Match indicators from Threat Intelligence
```kql
let bad = ThreatIntelligenceIndicator
    | where TimeGenerated > ago(30d) and Active == true and ExpirationDateTime > now()
    | where isnotempty(NetworkIP)
    | summarize by NetworkIP, Description, ConfidenceScore;
DeviceNetworkEvents
| where Timestamp > ago(7d)
| join kind=inner bad on $left.RemoteIP == $right.NetworkIP
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort, Description, ConfidenceScore
```
Table and column names change if you use the newer threat intelligence tables, so check your schema.

## False positives and tuning
CDNs, software updates, telemetry, cloud sync and backup traffic dominate rare and regular connections. Baseline for 30 days and allowlist confirmed services.

## Next steps
Take the device and process to endpoint telemetry ([defender-endpoint-hunting.md](defender-endpoint-hunting.md)) and find what launched it.
