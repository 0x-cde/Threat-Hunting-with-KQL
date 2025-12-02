# Suspicious Curl Activity

## Intro

Threat Actors commonly utilize curl to fetch executable code from external repositories; and to export info to cloud storage or dump sites. This hunt allows you to identify suspicious curl executions that fit these parameters.

## Expected outcomes and suggested actions

It is possible that specific developers might use similar action to test api calls, but still results should be verified with the users/departments.


## Additional Info

For this Hunt the website https://lots-project.com/ by [mrd0x](https://github.com/mrd0x) is used to get a list of known cloud storage provider urls. 

## Kusto Query

``` 
let ExfiltrationSites = externaldata(results: dynamic)
   [h'https://lots-project.com/'] with(format='raw')
| project parse_json(results)
| mv-expand kind=array results
| extend results=tostring(split(results,'<table id="main-table">')[1])
| extend Site_info= split(results,'<a class="link" href=')
| project Site_info
| mv-expand Site_info
| where Site_info contains "<div>Exfiltration</div>"
| extend Website=tostring(split(tostring(split(Site_info,'">')[1]),'</a>')[0])
| project Website
| extend Website=tostring(trim(@'\*',Website))
| extend Website=tostring(trim(@'www\.',Website))
;
DeviceProcessEvents
| where TimeGenerated > ago(90d)
| where FileName has "curl"
| where ProcessCommandLine matches regex @"\b(?:https?://(?:\d{1,3}\.){3}\d{1,3}\b)" or (ProcessCommandLine has_any (ExfiltrationSites) and ProcessCommandLine !has "-o ")
| extend RemoteIP=tostring(split(extract(@"\b(?:https?://(?:\d{1,3}\.){3}\d{1,3}\b)",0,ProcessCommandLine),"//")[1])
| where (ipv4_is_in_any_range(RemoteIP,"0.0.0.0/8","100.64.0.0/10","127.0.0.0/8","169.254.0.0/16","192.0.0.0/24","192.0.2.0/24","192.88.99.0/24","198.18.0.0/15","198.51.100.0/24","203.0.113.0/24","224.0.0.0/4","233.252.0.0/24","240.0.0.0/4")==false and ipv4_is_private(RemoteIP)==false) or isempty(RemoteIP)
| project-reorder TimeGenerated, AccountDomain,AccountName, RemoteIP, ProcessCommandLine, FileName, InitiatingProcessCommandLine
```

## Mitre Att&ck Techniques

- Exfiltration - [T1041 - Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)
- Defence Evasion - [T1202 - Indirect Command Execution](https://attack.mitre.org/techniques/T1202/)
- Exfiltration - [T1537 - CTransfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/)
- Resource Development - [T1608 - Stage Capabilities](https://attack.mitre.org/techniques/T1608/)