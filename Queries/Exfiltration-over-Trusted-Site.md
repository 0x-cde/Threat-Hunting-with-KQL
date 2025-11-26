# Exfiltration over Trusted Site

## Intro

In a lot organizations there is a list of approved cloud storage providers. In a perfect environment your servers should only access very specific cloud storage services and your users would only use the storage provider that the company has selected.

For this Hunt I utilize the knowledge provided on https://lots-project.com/ by [mrd0x](https://github.com/mrd0x). The following query will help audit your environment for trafic to known Cloud Storage Services. 

## Expected outcomes and Suggested actions

Your servers should only communicate with a handful of known repos/blobs/buckets, investigate any that is not expected.

If a user workstation is making requests to any non-company-approved cloud storage, then that could be an indication of Shadow-IT or even that the user is exfiltrating company intelectual property or confidential information.

## Additional Info

The query is by default set to check only for Servers. If you want to check for workstations as well you can omit creating the _Servers_ table and comment out the respective line on the last part of the query.

In order to filter out expected cloud storage providers for your organization, you will have to comment out or edit the appropriate lines.

Since the query is parsing raw html, it is possible that if the external source changes the formating then this query might not work.

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
// Comment out the following line if you want to audit the blob storages as well
| where Website !endswith '.blob.core.windows.net'
// Remove comments from the following lines or customize them in order to exclude cloud storage providers legitimate for your organization
| where Website !~ "graph.microsoft.com"
// | where Website !~ ".amazonaws.com"
// | where Website !~ ".linodeobjects.com"
// | where Website !~ ".oraclecloud.com"
// | where Website !~ ".web.core.windows.net"
// | where Website !~ "drive.google.com"
// | where Website !~ "dropbox.com"
// | where Website !~ "icloud.com"
// | where Website !~ "storage.googleapis.com"
// | where Website !~ ".wasabisys.com"
;
let Servers = DeviceInfo
| where TimeGenerated > ago(14d)
| where DeviceType =~ "Server"
| distinct DeviceName
;
DeviceNetworkEvents
| where TimeGenerated > ago(14d)
| where DeviceName in (Servers)
| where RemoteUrl has_any (ExfiltrationSites)
| summarize min(TimeGenerated), count() by DeviceName, RemoteUrl, InitiatingProcessFileName, InitiatingProcessVersionInfoInternalFileName, InitiatingProcessVersionInfoOriginalFileName, InitiatingProcessCommandLine
```

## Mitre Att&ck Techniques

- Exfiltration - [T1537 - Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/)
- Exfiltration - [T1567 - Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/)
