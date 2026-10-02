# Mailbox, OAuth and directory abuse: Microsoft Sentinel (KQL)

## Goal
Find attacker persistence and data access after an account compromise: inbox rules, mail forwarding, risky OAuth consent, new credentials on applications and privileged role changes.

## Data needed
`OfficeActivity` (Exchange, SharePoint, OneDrive via the Microsoft 365 connector), `AuditLogs` (Entra ID audit), `CloudAppEvents` if you use Defender for Cloud Apps. Column names differ slightly between connectors, so check your schema.

## ATT&CK
T1114.003 Email Forwarding Rule · T1137 Office Application Startup · T1098.001 Additional Cloud Credentials · T1098.003 Additional Cloud Roles · T1528 Steal Application Access Token · T1530 Data from Cloud Storage

## 1. Suspicious inbox rules (delete, hide, forward)
```kql
OfficeActivity
| where TimeGenerated > ago(7d)
| where Operation in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
| extend Params = tostring(Parameters)
| where Params has_any ("DeleteMessage", "MoveToFolder", "ForwardTo", "RedirectTo", "ForwardAsAttachmentTo", "MarkAsRead")
| project TimeGenerated, UserId, ClientIP, Operation, Params
```
Rules that move messages to RSS, Archive or Deleted Items and mark them read are common after account takeover.

## 2. Rules triggered by security or finance keywords
```kql
OfficeActivity
| where TimeGenerated > ago(7d) and Operation in ("New-InboxRule", "Set-InboxRule")
| where tostring(Parameters) has_any ("invoice", "payment", "wire", "password", "security", "phish", "alert")
| project TimeGenerated, UserId, ClientIP, Parameters
```

## 3. Mailbox-level forwarding and delegate access
```kql
OfficeActivity
| where TimeGenerated > ago(14d)
| where Operation in ("Set-Mailbox", "Add-MailboxPermission", "Add-RecipientPermission", "Set-TransportRule", "New-TransportRule")
| where tostring(Parameters) has_any ("ForwardingSmtpAddress", "ForwardingAddress", "DeliverToMailboxAndForward", "FullAccess", "SendAs", "RedirectMessageTo", "BlindCopyTo")
| project TimeGenerated, UserId, ClientIP, Operation, Parameters
```

## 4. Mass file download or sharing in SharePoint and OneDrive
```kql
OfficeActivity
| where TimeGenerated > ago(1d)
| where Operation in ("FileDownloaded", "FileSyncDownloadedFull", "FileCopied")
| summarize Files=dcount(OfficeObjectId), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by UserId, ClientIP
| where Files > 200
| order by Files desc
```
Set the threshold from your baseline. Sync clients create large legitimate volumes.

## 5. Anonymous or external sharing links created in bulk
```kql
OfficeActivity
| where TimeGenerated > ago(1d)
| where Operation in ("AnonymousLinkCreated", "SharingInvitationCreated", "SecureLinkCreated")
| summarize Links=count(), Samples=make_set(OfficeObjectId, 5) by UserId, ClientIP
| where Links > 20
```

## 6. New OAuth application consent
```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName in ("Consent to application", "Add delegated permission grant", "Add app role assignment to service principal")
| extend Actor = tostring(InitiatedBy.user.userPrincipalName), App = tostring(TargetResources[0].displayName)
| project TimeGenerated, OperationName, Actor, App, Result, AdditionalDetails
```
Review the permissions granted. Broad mail, file or directory scopes granted to unfamiliar apps are the pattern of consent phishing.

## 7. Credentials added to an application or service principal
```kql
AuditLogs
| where TimeGenerated > ago(14d)
| where OperationName in ("Add service principal credentials", "Update application – Certificates and secrets management", "Add service principal", "Update application")
| extend Actor = coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName)), Target = tostring(TargetResources[0].displayName)
| project TimeGenerated, OperationName, Actor, Target, Result
```

## 8. Privileged role assignments
```kql
AuditLogs
| where TimeGenerated > ago(14d)
| where OperationName has_any ("Add member to role", "Add eligible member to role", "Add member to role in PIM completed")
| extend Actor = tostring(InitiatedBy.user.userPrincipalName), Target = tostring(TargetResources[0].userPrincipalName), Role = tostring(TargetResources[0].modifiedProperties[1].newValue)
| where Role has_any ("Global Administrator", "Privileged Role Administrator", "Exchange Administrator", "Application Administrator", "Cloud Application Administrator")
| project TimeGenerated, Actor, Target, Role
```
The `modifiedProperties` index can vary by event, so verify the role field against sample records.

## 9. Conditional Access, MFA or authentication method changes
```kql
AuditLogs
| where TimeGenerated > ago(14d)
| where OperationName has_any ("Update conditional access policy", "Delete conditional access policy", "User registered security info", "User deleted security info", "Admin registered security info")
| extend Actor = tostring(InitiatedBy.user.userPrincipalName), Target = tostring(TargetResources[0].userPrincipalName)
| project TimeGenerated, OperationName, Actor, Target, Result
```
A new authentication method added soon after a risky sign-in is a common attacker move.

## False positives and tuning
IT and helpdesk work, migrations, legitimate integrations and change windows. Correlate with tickets and approved change records.

## Next steps
Remove malicious rules and consents, revoke sessions and refresh tokens, and review mail sent from the account. Check the first sign-in that preceded the changes ([entra-signin-hunting.md](entra-signin-hunting.md)).
