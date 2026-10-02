# Entra ID sign-in hunting: Microsoft Sentinel (KQL)

## Goal
Find password spray, brute force, MFA fatigue, suspicious sign-ins, legacy authentication and token abuse in Entra ID (Azure AD) sign-in logs.

## Data needed
`SigninLogs` (and `AADNonInteractiveUserSignInLogs` for token and background sign-ins) via the Entra ID data connector. Common columns: `UserPrincipalName`, `IPAddress`, `ResultType`, `ResultDescription`, `AppDisplayName`, `ClientAppUsed`, `Location`, `DeviceDetail`, `ConditionalAccessStatus`, `RiskLevelDuringSignIn`.

## ATT&CK
T1110.003 Password Spraying · T1621 MFA Request Generation · T1078.004 Cloud Accounts · T1550.001 Application Access Token · T1556 Modify Authentication Process

> Result codes: `0` success, `50126` bad password, `50053` locked out, `50057` disabled, `50074`/`50076`/`500121` MFA required or failed, `50158` external challenge. Check Microsoft's current error-code list for your case.

## 1. Password spray: one IP, many accounts, few attempts each
```kql
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == "50126"
| summarize Attempts=count(), Accounts=dcount(UserPrincipalName), SampleUsers=make_set(UserPrincipalName, 5) by IPAddress, bin(TimeGenerated, 15m)
| where Accounts >= 10
| order by Accounts desc
```

## 2. Spray followed by a success from the same IP
```kql
let failed = SigninLogs
    | where TimeGenerated > ago(24h) and ResultType == "50126"
    | summarize Fails=count(), Users=dcount(UserPrincipalName) by IPAddress
    | where Users >= 10;
SigninLogs
| where TimeGenerated > ago(24h) and ResultType == 0
| join kind=inner failed on IPAddress
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, Location, Fails, Users
```
A success from an address that just failed against many accounts is high priority.

## 3. MFA fatigue: repeated MFA prompts then approval
```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType in ("500121", "50074", "50076") or ResultType == 0
| summarize Denied=countif(ResultType in ("500121","50074","50076")), Success=countif(ResultType == 0), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by UserPrincipalName, IPAddress
| where Denied >= 5 and Success >= 1
```
Adjust result codes to match your tenant. Many prompts followed by a success is the pattern.

## 4. Legacy authentication (bypasses MFA)
```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where ClientAppUsed in ("IMAP4","POP3","SMTP","Exchange ActiveSync","Other clients","Authenticated SMTP","MAPI Over HTTP")
| summarize Count=count(), Successes=countif(ResultType == 0), IPs=dcount(IPAddress) by UserPrincipalName, ClientAppUsed
| order by Successes desc
```

## 5. Impossible or very fast travel
```kql
SigninLogs
| where TimeGenerated > ago(24h) and ResultType == 0
| extend Country = tostring(LocationDetails.countryOrRegion)
| where isnotempty(Country)
| sort by UserPrincipalName asc, TimeGenerated asc
| extend PrevCountry = prev(Country), PrevTime = prev(TimeGenerated), PrevUser = prev(UserPrincipalName)
| where UserPrincipalName == PrevUser and Country != PrevCountry
| extend MinutesBetween = datetime_diff('minute', TimeGenerated, PrevTime)
| where MinutesBetween < 120
| project UserPrincipalName, PrevCountry, Country, MinutesBetween, IPAddress, AppDisplayName
```
VPNs and mobile roaming cause false positives, so exclude your known egress addresses.

## 6. New country or new device for a user
```kql
let baseline = SigninLogs
    | where TimeGenerated between (ago(30d) .. ago(1d)) and ResultType == 0
    | extend Country = tostring(LocationDetails.countryOrRegion)
    | summarize KnownCountries=make_set(Country) by UserPrincipalName;
SigninLogs
| where TimeGenerated > ago(1d) and ResultType == 0
| extend Country = tostring(LocationDetails.countryOrRegion)
| join kind=inner baseline on UserPrincipalName
| where not(set_has_element(KnownCountries, Country))
| project TimeGenerated, UserPrincipalName, Country, IPAddress, AppDisplayName, KnownCountries
```

## 7. Sign-ins that Conditional Access did not apply
```kql
SigninLogs
| where TimeGenerated > ago(7d) and ResultType == 0
| where ConditionalAccessStatus in ("notApplied", "failure")
| summarize Count=count(), Apps=make_set(AppDisplayName, 5) by UserPrincipalName, IPAddress
| order by Count desc
```

## 8. Risky sign-ins that succeeded
```kql
SigninLogs
| where TimeGenerated > ago(7d) and ResultType == 0
| where RiskLevelDuringSignIn in ("medium","high") or RiskState in ("atRisk","confirmedCompromised")
| project TimeGenerated, UserPrincipalName, IPAddress, RiskLevelDuringSignIn, RiskEventTypes_V2, AppDisplayName
```

## 9. Non-interactive sign-ins from a new address (possible stolen token)
```kql
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(1d) and ResultType == 0
| summarize Apps=make_set(AppDisplayName, 5), Count=count() by UserPrincipalName, IPAddress
| join kind=leftanti (
    SigninLogs | where TimeGenerated between (ago(30d) .. ago(1d)) and ResultType == 0
    | summarize by UserPrincipalName, IPAddress) on UserPrincipalName, IPAddress
```
An address seen only in token-based sign-ins and never interactively can indicate a replayed token. Mobile and roaming users also cause noise.

## False positives and tuning
Shared egress addresses, VPNs, mobile carriers, service accounts and automation. Maintain a named-locations list and exclude trusted ranges.

## Next steps
For a suspected compromise: revoke sessions, reset credentials, review the account's mailbox rules and OAuth grants ([m365-mailbox-and-app-abuse.md](m365-mailbox-and-app-abuse.md)).
