# Port Forwarding to localhost

## Intro
A covert way for threat actors to contact their C2 and exfiltration channels is for them to create a port forwarding rule that redirects traffic from localhost to the threat actors infrastructure. That way they can hide traffic from the eyes of analysts and security products.


## Expected outcomes and suggested actions

The following query will help you identify and investigate cases where port forwarding rules to localhost are created. 

If the query returns an event, you should first investigate the process tree of the application that created the port forwarding rule. It is recommended that you verify with the user performing the actions for what the use case was for creating such a rule.

Then, check the reputation of the website/IP address where the traffic is forwarded. 

Finally, check for other applications that utilize the forwarding rule and point their traffic to any of the localhost IP addresses.


## Additional Info

Although the query is set for checking forwarding rules that point to external webpages and ip addresses, it can be modified to check for port forwarding rules that point to other local addresses. To do so change the *"where ipv4_is_private(forwardedIP)==false"* value to true. In the same line we also have the filter *"or isempty(forwardedIP)"* which is used in order to include rules that point to websites and naturally those attempts would not identify an IP address to be extracted in the previous lines.

## Kusto Query

``` 
DeviceProcessEvents
| where TimeGenerated > ago(90d)
| where FileName =~ "netsh.exe"
| where ProcessCommandLine has_all ("interface","add")
| extend IPs=extract_all(@"\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",ProcessCommandLine)
| extend forwardedIP=strcat_array(IPs[1],".")
| extend forwardingIP=strcat_array(IPs[0],".")
| where forwardingIP startswith "127." or forwardingIP == "0.0.0.0"
| where ipv4_is_private(forwardedIP)==false or isempty(forwardedIP)
| project-reorder TimeGenerated, ProcessCommandLine,forwardingIP, forwardedIP, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
```

## Mitre Att&ck Techniques

- Execution - [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- Defense Evasion - [Impair Defenses: Disable or Modify Network Device Firewall](https://attack.mitre.org/techniques/T1562/013/)
- Defense Evasion - [Masquerading: Match Legitimate Resource Name or Location](https://attack.mitre.org/techniques/T1036/005/)
- Defense Evasion - [Network Boundary Bridging](https://attack.mitre.org/techniques/T1599/)


