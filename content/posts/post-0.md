---
title: "Detecting network reconnaissance by correlating azure firewall and application gateway logs"
date: 2025-11-15T00:00:00Z
description: "Detecting reconnaissance and network scanning activity in Microsoft Sentinel by correlating Azure Firewall and Application Gateway logs using KQL and log correlation techniques."
categories: ["Cloud Security", "Network Hunting"]
tags: ["Azure Sentinel", "KQL", "Azure Firewall", "Application Gateway", "Network Scanning", "Log Correlation", "Reconnaissance Detection", "Discovery Tactic"]
author: "ThreatBuster"
showToc: true
TocOpen: false
draft: false
layout: "post"
---


## Introduction

Identifying potential network scanning activities often requires correlating events across multiple components of a network infrastructure. Such activities are commonly associated with early-stage reconnaissance, where attackers probe exposed services to discover potential vulnerabilities.

The process begins by identifying all IP addresses that attempt to access the Azure firewall **AZFWNetworkRule**. These IP addresses are then cross-referenced with **Application Gateway** logs.

Since logs from these two sources are not directly related, the presence of the same IP address in both logs may suggest potential network scanning activity. This type of behavior typically indicates that an attacker is conducting reconnaissance to find vulnerabilities in exposed systems. By combining these data sources, such behavior patterns can be detected and analyzed.

## Hypothesis

In this scenario, the hypothesis is that a potential attacker is conducting active reconnaissance with the goal of identifying vulnerabilities in exposed systems. The repeated and persistent activity over multiple days suggests a pattern consistent with network scanning or even exploitation of web vulnerabilities.

An attacker typically starts by scanning systems to identify open ports and services. If this scanning activity is ongoing and spreads across multiple days, it indicates a sustained attempt to map out the network and potentially exploit any weaknesses. This kind of reconnaissance is often the first step in more complex attacks.

By analyzing the logs for IP addresses that are consistently trying to access certain resources, especially over extended periods, we can identify suspicious behavior and correlate it with known attack patterns. This helps determine if the activity is merely benign (like automated monitoring or legitimate traffic) or if it is, in fact, part of a larger attempt to breach the network.

## Data sources

{{< warning_badge >}} Table names and schemas are environment-dependent (e.g., Microsoft Defender for Endpoint). Ensure you map these hunting activities to your specific workspace configuration.{{< /warning_badge >}}

**AZFWNetworkRule**: These logs contain information about network traffic filtered by the Azure Firewall. Specifically, they track events such as TCP, UDP, and ICMP traffic that is either allowed or denied based on configured firewall rules.

**ApplicationGatewayAccessLog**: These logs capture details about HTTP/HTTPS traffic passing through the Azure Application Gateway. They contain key data points such as source IP addresses, requested URLs, HTTP status codes, and response times.

## Investigation

To conduct this type of threat hunting analysis, the process starts by extracting logs from two key sources:

1.  The Azure firewall (**`AZFWNetworkRule`**)
2.  The application gateway logs (**`ApplicationGatewayAccessLog`**)

The analysis focuses on events from the past 30 days or more to identify any patterns of suspicious activity.

Since the main concern is public IP addresses attempting unauthorized access, the logs are filtered to **exclude private IPs**, ensuring that only public IPs are considered for further analysis.

Next, IP addresses that repeatedly attempt to connect to the firewall are extracted. For each detected IP, the filter looks for those with **more than two attempts per day**.

To detect persistent scanning behavior, the duration of activity is also analyzed. Specifically, the total number of distinct days on which an IP has been active is examined. The goal is to identify IPs that have attempted access on **at least six different days**.

Once suspicious IPs are identified in the firewall logs, they are cross-referenced with the application gateway logs to check if these IPs made **HTTP/HTTPS requests**. This step helps determine whether the scanning activity is targeting specific web applications or services.

{{< tip_badge >}} During an analysis, research can lead to other insights. For example, the results may identify potential exposed websites through the analysis of HTTP 200 responses. The URLs found should be examined to determine whether they belong to development environments. {{< /tip_badge >}}

### Query

The following query or an adaptation of it can be used to perform the analysis on Azure Sentinel environment

```kusto
let data  = AzureDiagnostics
| where TimeGenerated > ago(30d)
| where not(ipv4_is_private(SourceIP)) 
| where Category == "AZFWNetworkRule"
| summarize daily_count = count() by SourceIP, bin(TimeGenerated, 1d)
| where daily_count > 2
| summarize total_days = dcount(bin(TimeGenerated, 1d)), total_attempts = sum(daily_count) by SourceIP
| where total_days >= 6
| sort by total_attempts desc;
data
| join kind=inner (
    AzureDiagnostics
    | where TimeGenerated > ago(30d)
    | where Category == "ApplicationGatewayAccessLog"
    ) on $left.SourceIP == $right.clientIP_s
| sort by total_attempts desc
| project TimeGenerated, SourceIP, total_days, total_attempts, originalHost_s, httpStatus_d
| summarize count() by SourceIP, total_days, total_attempts, originalHost_s, httpStatus_d
| distinct SourceIP

```
{{< details "Step-by-step explaination" >}}

1.  **Filtering AZFWNetworkRule Logs**:  
    The query begins by filtering logs from the `AZFWNetworkRule` category for the last 30 days. It excludes private IPs by using the `ipv4_is_private(SourceIP)` function.
    
2.  **Counting Attempts per Day**:  
    The `summarize` function calculates how many times each IP attempted to connect to the firewall on a daily basis, using the `bin(TimeGenerated, 1d)` to group logs by day. We then filter for IPs that attempted to connect more than twice per day.
    
3.  **Calculating Total Days and Total Attempts**:  
    Further process the data by calculating the total number of distinct days (`dcount(bin(TimeGenerated, 1d))`) and the total number of attempts (`sum(daily_count)`) for each IP address. Filter out IPs that have attempted connections on at least six distinct days.
    
4.  **Joining with Application Gateway Logs**:  
    The filtered IPs are then matched with `ApplicationGatewayAccessLog` entries to identify any HTTP/HTTPS requests originating from the same sources. This step helps reveal whether IPs that scan the firewall are also interacting with web services.
    
5.  **Summarizing and Projecting Final Results**:  
    Finally, the query summarizes the results by counting the total number of attempts, the total days of activity, and the HTTP status codes returned by the Application Gateway. The `distinct SourceIP` function ensures that only unique suspicious IP addresses are displayed.

{{< /details  >}}

## Mitigations and recommendations

Based on the findings of the threat hunting analysis, the following actions are recommended to mitigate the risk of a potential attack:

1.  **Block identified malicious IPs**:  
    Identified IP addresses, if not associated with lawful activities, may be blocked in order to prevent further attempts to exploit vulnerabilities.
    
2.  **Harden firewall and application gateway configurations**:  
    Review and strengthen the firewall and application gateway rules to ensure they follow best security practices. Restrict public access only to necessary services and IP addresses, and ensure that only trusted sources are allowed to interact with sensitive applications and systems.
    
3.  **Increase monitoring and alerting**:  
    Enhance the monitoring capabilities by setting up alerts for any unusual or repeated access attempts to critical infrastructure. This will help detect any future reconnaissance activities promptly and allow for a swift response before they escalate into a full-blown attack.
    
4.  **Conduct vulnerability assessments**:  
    Perform vulnerability assessments on the exposed services identified during the analysis, especially those that might be running with default or weak configurations. This will help ensure that any potential attack vectors are mitigated before they can be exploited.
    
5.  **Implement rate limiting and access controls**:  
    Consider implementing rate limiting on sensitive endpoints and stronger access controls to minimize the impact of brute-force attempts or unauthorized access. Limiting the number of requests from an IP address or implementing IP whitelisting can help prevent such attacks from succeeding.

## Conclusion

The analysis provides a structured approach to identifying and mitigating potential network reconnaissance activities by analyzing multiple sources of network traffic logs and focusing on repeated patterns. The ability to cross-reference data from different sources allows security teams to quickly identify suspicious behavior, even if the logs themselves do not show any direct correlations. By identifying patterns of repeated activity, a threat hunter can identify attackers who may be trying to find weaknesses over an extended period of time, providing an essential tool for preventive defense measures.
    
----------

**Proactive threat hunting and continuous monitoring are key to maintaining a secure and resilient network infrastructure.**
> This blog provides a simplified overview of threat research processes. As the cybersecurity landscape evolves, these methodologies are also subject to change. I will strive to keep this resource up to date. [**Your feedback is valuable**](/contact), if you have any suggestions or opinions to share, please contact me so that I can improve this guide.
