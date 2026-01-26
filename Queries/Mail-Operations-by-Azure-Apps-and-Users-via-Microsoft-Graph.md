# Mail Operations by Azure Apps and Users via Microsoft Graph

## Intro

Some common methods for Threat Actors to establish covert persistance on Azure, is to create Logic Apps and/or Azure Apps that allow them to access user emails. If the initial access is missed, auditing your environment is a good way to identify suspicious activity.

## Expected outcomes and suggested actions

In a business environment it is common to have applications that require access to read user emails, this might be an anti-phishing service; a ticketing system; or a collaboration tool. Simply verify that the IP addresses that are used to access the mailboxes, align with the IP addresses shared by the vendor, and that the mailboxes that are accessed are within scope.

It is possible that you identify logic apps created by users, those will appear as users performing graph actions with a User Agent similar to _"azure-logic-apps/1.0"_ . Verify that this activity is permitted by the company IT policy and there is a legitimate reason for this application.

For any other application identified, proceed with additional investigation.

The volume of operations performed; the IP addresses; and uncommon user agents (eg curl, python) are good starting points to identify suspicious applications.


## Additional Info

During testing I noticed that a lot of legitimate user activity generates Graph requests, and filtering out by checking the user agent was an easy way. User Agents are not an optimal way to filter activity since they can be easily manipulated. The user agent _TeamsMiddleTier/1.0a$*+_ is also expected, since it is a known useragent for Teams backend operations.

Depending on your threat hunting appetite, you might want to add to search for the action _"/mailFolders"_ as well. This will display lookups that are made for specific folders, but keep in mind that results will increase drastically.

## Kusto Query

``` 
let timeframe=ago(90d);
MicrosoftGraphActivityLogs
| where TimeGenerated > timeframe
| where isempty(DeviceId)
| extend Action=trim_start("https://graph.microsoft.com/",RequestUri)
| extend Action=trim_start("/",tostring(split(Action,"?")[0]))
| extend Action=replace_string(Action,"//","/")
| where ResponseStatusCode == 200
| where Action has_any ("/messages/","/MailFolders/")
| extend Resource=iff(tostring(split(tolower(tostring(split(Action,"/")[1])),"(")[0]) matches regex "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",tostring(split(tolower(tostring(split(Action,"/")[2])),"(")[0]),tostring(split(tolower(tostring(split(Action,"/")[1])),"(")[0]))
| where Resource =~ "users"
| extend AffectedMailbox=tostring(split(Action,"/")[2])
| extend UserId_or_ServicePrincipalId=iff(isempty(ServicePrincipalId),UserId,ServicePrincipalId)
| join kind=leftouter (AADServicePrincipalSignInLogs
    | where TimeGenerated > timeframe
    | distinct ServicePrincipalName, AppId,  ServicePrincipalId) on $left.UserId_or_ServicePrincipalId==$right.ServicePrincipalId
| join kind=leftouter (IdentityInfo
    | where TimeGenerated > timeframe
    | project-rename AffectedMailboxUPN=AccountUPN
    | distinct AccountObjectId, AffectedMailboxUPN) on $left.AffectedMailbox==$right.AccountObjectId
| join kind=leftouter (IdentityInfo
    | where TimeGenerated > timeframe
    | distinct AccountObjectId, AccountUPN) on $left.UserId_or_ServicePrincipalId==$right.AccountObjectId
| extend AffectedMailbox=iff(tolower(AccountObjectId)==tolower(AffectedMailbox),tolower(AffectedMailboxUPN),tolower(AffectedMailbox))
| join kind=leftouter (AADNonInteractiveUserSignInLogs
    | where TimeGenerated > timeframe
    | distinct AppDisplayName, AppId) on AppId
| project-rename  ActionPerformedBy=AccountUPN
| where AffectedMailbox != ActionPerformedBy
| extend ActionPerformedBy=iff(isempty(ServicePrincipalId),strcat("🧑‍💼 User: ",tolower(ActionPerformedBy)," via the app: ",AppDisplayName),strcat("🖥️ AzureApp: ",ServicePrincipalName))
| project-reorder TimeGenerated, Resource, Action, AffectedMailbox,UserId_or_ServicePrincipalId,ActionPerformedBy, RequestUri, IPAddress, Location
| where UserAgent !startswith "TeamsMiddleTier" and UserAgent !startswith "Microsoft Office"
| summarize OperationsPerformed=count(), make_set(IPAddress), make_set(UserAgent), NumberOfMailboxes=dcount(AffectedMailbox),make_set(AffectedMailbox,50), min(TimeGenerated), max(TimeGenerated) by ActionPerformedBy, UserId_or_ServicePrincipalId
```

## Mitre Att&ck Techniques

- Persistence -  [T1671 - Cloud Application Integration](https://attack.mitre.org/techniques/T1671/)