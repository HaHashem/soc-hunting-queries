# Azure control-plane and resource hunting: Microsoft Sentinel (KQL)

## Goal
Find suspicious changes to Azure subscriptions and resources: role assignments, security control tampering, new keys and secrets, and risky network exposure.

## Data needed
`AzureActivity` (subscription activity log connector), `AzureDiagnostics` for Key Vault and storage, `AuditLogs` for Entra ID. Column names such as `OperationNameValue`, `Caller`, `CallerIpAddress`, `ActivityStatusValue` are standard in `AzureActivity`.

## ATT&CK
T1098 Account Manipulation · T1562 Impair Defenses · T1578 Modify Cloud Compute Infrastructure · T1552.001 Credentials in Files · T1530 Data from Cloud Storage · T1496 Resource Hijacking

## 1. Role assignments at subscription or resource group scope
```kql
AzureActivity
| where TimeGenerated > ago(7d)
| where OperationNameValue =~ "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE" and ActivityStatusValue =~ "Success"
| project TimeGenerated, Caller, CallerIpAddress, ResourceGroup, _ResourceId, Properties
| order by TimeGenerated desc
```
Review who granted Owner, Contributor or User Access Administrator, and to whom.

## 2. Elevation of access to manage all subscriptions
```kql
AzureActivity
| where TimeGenerated > ago(30d)
| where OperationNameValue =~ "MICROSOFT.AUTHORIZATION/ELEVATEACCESS/ACTION"
| project TimeGenerated, Caller, CallerIpAddress, ActivityStatusValue
```
This operation is rare and high-impact.

## 3. Security controls disabled or deleted
```kql
AzureActivity
| where TimeGenerated > ago(7d)
| where OperationNameValue has_any ("MICROSOFT.SECURITY/", "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE", "MICROSOFT.OPERATIONALINSIGHTS/WORKSPACES/DELETE", "MICROSOFT.NETWORK/NETWORKWATCHERS", "MICROSOFT.NETWORK/AZUREFIREWALLS/DELETE", "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/DELETE")
| where OperationNameValue has_any ("DELETE", "DISABLE") or OperationNameValue has "DIAGNOSTICSETTINGS"
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, ResourceGroup, ActivityStatusValue
```

## 4. Network security group rules opening sensitive ports to the internet
```kql
AzureActivity
| where TimeGenerated > ago(7d)
| where OperationNameValue =~ "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE" and ActivityStatusValue =~ "Success"
| extend Props = parse_json(tostring(parse_json(Properties).requestbody))
| extend Source = tostring(Props.properties.sourceAddressPrefix), Port = tostring(Props.properties.destinationPortRange), Access = tostring(Props.properties.access)
| where Access =~ "Allow" and Source in ("*", "0.0.0.0/0", "Internet") and Port in ("22", "3389", "445", "*", "1433", "3306")
| project TimeGenerated, Caller, CallerIpAddress, Source, Port, _ResourceId
```
The JSON path can differ across API versions, so check a sample event.

## 5. Mass creation of virtual machines (possible mining)
```kql
AzureActivity
| where TimeGenerated > ago(1d)
| where OperationNameValue =~ "MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE" and ActivityStatusValue =~ "Success"
| summarize VMs=dcount(_ResourceId), Regions=dcount(tostring(parse_json(Properties).location)) by Caller, CallerIpAddress, bin(TimeGenerated, 1h)
| where VMs >= 5
```

## 6. Key Vault: secrets and keys read in bulk
```kql
AzureDiagnostics
| where TimeGenerated > ago(1d)
| where ResourceProvider == "MICROSOFT.KEYVAULT" and OperationName in ("SecretGet", "SecretList", "KeyGet", "CertificateGet")
| summarize Reads=count(), Items=dcount(requestUri_s) by CallerIPAddress, identity_claim_appid_g, Resource
| where Reads > 50 or Items > 20
| order by Reads desc
```
Check the Key Vault diagnostic settings are enabled before relying on this.

## 7. Storage account public access and key listing
```kql
AzureActivity
| where TimeGenerated > ago(14d)
| where OperationNameValue in~ ("MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION", "MICROSOFT.STORAGE/STORAGEACCOUNTS/REGENERATEKEY/ACTION")
| project TimeGenerated, Caller, CallerIpAddress, _ResourceId, ActivityStatusValue
```
Listing account keys gives full data-plane access, so unexpected callers matter.

## 8. Operations from a caller seen for the first time
```kql
let known = AzureActivity
    | where TimeGenerated between (ago(30d) .. ago(1d))
    | summarize by Caller, CallerIpAddress;
AzureActivity
| where TimeGenerated > ago(1d) and ActivityStatusValue =~ "Success"
| where OperationNameValue has_any ("WRITE", "DELETE", "ACTION")
| join kind=leftanti known on Caller, CallerIpAddress
| summarize Ops=count(), Examples=make_set(OperationNameValue, 5) by Caller, CallerIpAddress
```

## False positives and tuning
Automation, CI/CD pipelines, Infrastructure-as-Code deployments and administrators working from new networks. Compare with change tickets, and exclude known pipeline identities.

## Next steps
For a suspicious caller, review their Entra sign-ins ([entra-signin-hunting.md](entra-signin-hunting.md)) and everything else they changed in the same window.
