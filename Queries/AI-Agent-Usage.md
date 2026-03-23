# AI Agent Usage

## Intro
This query can be used to identify users accessing various AI agents.


## Expected outcomes and suggested actions
Depending on your organization policies, it is possible that certain AI agents are not permitted to be used by certain users in fear of data leaking to those models. Depending on your organization policy, it might be worth blocking access to certain domains.


## Additional Info



## Kusto Query

``` 
let aiagents = externaldata(site: dynamic)
   [h"https://raw.githubusercontent.com/0x-cde/ai_agents_list/refs/heads/main/List.csv"] with(format='csv')
;
DeviceNetworkEvents
| where TimeGenerated > ago(90d)
| where ActionType =~ "connectionsuccess"
| extend RemoteUrl=tolower(replace_string(tostring(split(replace_regex(RemoteUrl,@"http(s)?://",""),"/")[0]),"www.",""))
| where RemoteUrl in (aiagents)
| project-reorder TimeGenerated, DeviceName, InitiatingProcessAccountName, InitiatingProcessAccountUpn, RemoteUrl, InitiatingProcessFileName,InitiatingProcessCommandLine
| summarize by DeviceName, InitiatingProcessAccountUpn,InitiatingProcessAccountDomain, InitiatingProcessAccountName, RemoteUrl
| where RemoteUrl !="salesforce.com"
```
