---
title: "XWorm RAT in the Wild: Phishing Delivery, ClickFix abuse and KQL hunting"
date: 2025-12-15T10:00:00Z
description: "Technical analysis of XWorm RAT campaigns delivered via phishing, Prometheus TDS and ClickFix techniques, with practical KQL hunting queries for Microsoft Defender and Sentinel."
categories: ["Malware Analysis", "Endpoint Hunting"]
tags: ["XWorm RAT", "Phishing Analysis", "Social Engineering", "ClickFix", "PowerShell Hunting", "Microsoft Defender", "Command and Control (C2)", "JavaScript Malware"]
author: "ThreatBuster"
draft: false
showToc: true
TocOpen: false 
layout: "post"
cover:
    image: "" 
    alt: "XWorm RAT Threat Hunting analysis"
    relative: false
---

## Introduction

The following article outlines the methodology for investigating and mitigating large-scale phishing campaigns distributing the **Xworm** remote access trojan (RAT). The activity is based on recent detections of sophisticated attacks leveraging social engineering techniques, including the **Prometheus traffic direction system (TDS)** and the **clickfix method** to deploy malware.

The objective of this threat hunting effort is to **analyze and identify indicators of compromise to assess the impact on the target environment**. The investigation follows a systematic and structured approach aligned with the **MITRE ATT&CK framework**, allowing for the identification of adversarial tactics, techniques, and procedures (TTPs) observed in phishing attacks.

## Hypothesis

In this scenario, the hypothesis is that a an attacker leveraged a series of phishing campaigns to deceive the victim into executing a malicious JavaScript file. Upon execution, this file initiated the download and execution of the remote access trojan Xworm, leading to the compromise and infection of the victim's device. Through this technique, the attacker gained unauthorized access to the system, potentially enabling further malicious activities such as data exfiltration, system manipulation, or preparation for additional attacks like ransomware.

## Data sources

To conduct a thorough investigation, the following data sources can be used. 

{{< warning_badge >}} Table names and schemas are environment-dependent (e.g., Microsoft Defender for Endpoint). Ensure you map these hunting activities to your specific workspace configuration.{{< /warning_badge >}}

To conduct a thorough investigation, focus on the following telemetry:

* **DeviceNetworkEvents**: To detect C2 communications and anomalous outbound traffic.
* **DeviceFileEvents**: To capture file operations such as the creation of `.js`, `.exe`, or `.zip` files.
* **DeviceProcessEvents**: To monitor suspicious process executions (e.g., `mshta.exe`, `powershell.exe`).
* **UrlClickEvents**: To analyze clicks on phishing-related URLs.
* **EmailEvents**: To inspect email metadata, suspicious subjects, and malicious attachments.


## Artifact extraction

Threat research activities can begin with in-depth analysis and extraction of key elements identified in two large-scale phishing campaigns that distributed the Xworm remote access Trojan.

{{< tip_badge >}}  It is recommended to correlate these findings with open-source Threat Intelligence to obtain the most recent campaigns, hashes and C2 domains.{{< /tip_badge >}} 

### First Campaign

- Used URLs managed by the **Prometheus traffic direction system**, hosted on compromised websites and distributed via email.
    
- Phishing emails used enticing subject lines such as **‘Temporary Location’** and **‘Programme Manager’**.
    
- The embedded URL redirected victims to a **CAPTCHA-protected phishing page** (Figure 1), designed to build trust.
    
- Completing the CAPTCHA revealed a **‘Download’ button**, which delivered a zipped JavaScript (.js) file.
    
- Executing the JavaScript launched **PowerShell commands** that installed **Xworm RAT**.


{{< figure src="/post1/image01.png" title="Phishing Page" caption="CAPTCHA-protected phishing page used in the first campaign" alt="CAPTCHA Phishing Page" align="center" >}}

### Second Campaign

- Used **ClickFix**, a social engineering tactic exploiting the **‘do-it-yourself’ mentality**.
    
- Variants Detected:
    
    - **HTML Attachments:** Emails with subjects like **“send you some money”** contained **malicious HTML attachments** (e.g., `INVOICE0086283927.html`). These displayed ClickFix instructions, prompting users to paste a command into the Windows Run dialogue box, executing an HTA script that installed Xworm.
        
    - **Embedded URLs:** Emails with subjects like **‘Worldwide delivery’** contained **fraudulent hyperlinks** (e.g., `Invoice/69735AAQQ`). Clicking led to a malicious Word document urging users to **‘Install extension’** (Figure 2), triggering ClickFix instructions and malware installation.

{{< figure src="/post1/image02.png" title="ClickFix Prompt" caption="Example of ClickFix social engineering tactic" alt="ClickFix Prompt" align="center" >}}

### MITRE ATT&CK Mapping

These phishing campaigns can be mapped to multiple MITRE ATT&CK techniques. Below are some of the main ones identified:

- **Initial Access:** Phishing emails as the entry point.
    
- **Execution:** Malicious JavaScript, PowerShell commands, and social engineering tactics.
    
- **Defense Evasion:** Obfuscation and anti-detection techiniques
    
- **Command and Control:** Xworm establishing persistent C2 communication.

{{< figure src="/post1/mitremapping.png" title="MITRE ATT&CK Mapping" alt="MITRE Mapping" align="center" >}}

## Investigation

The threat hunting process is divided into stages, each of which requires an in-depth analysis to detect possible malicious behaviors or compromised hosts. Given that the initial access occurs via phishing, the investigation begins by targeting phishing campaigns and their associated artifacts. This involves executing queries across email events, endpoint activities, and network logs to identify indicators of compromise IoCs and behavioral patterns consistent with the tactics used in this attack.

**The primary focus is on identifying phishing emails that align with the observed techniques**. Emails with subjects such as "Fixed Term Position", "Program Manager", "send you some money", and "Worldwide Delivery" will undergo thorough analysis. Further scrutiny will target emails containing attachments with “.html” and “.js” extensions, as these formats were exploited in the attack chain. Additional research will examine references to Prometheus TDS and the ClickFix technique to uncover related activity. These efforts aim to map out the campaign's breadth and identify potential entry points.

**The second phase of the investigation focuses on execution**. In this phase, the focus is on detecting malicious PowerShell commands, JavaScript files and files downloaded from phishing campaigns. The analysis will look for PowerShell commands that use suspicious functions as well as encoded or obfuscated scripts. Execution attempts involving tools such as “mshta.exe” and “wscript.exe” will also be analyzed, given their frequent misuse to launch malicious payloads.

**Since the attacker employs techniques for defense evasion**, such as URL redirects and obfuscated scripts, these events will also be closely tracked. By focusing on these elements, the investigation can reveal attempts to bypass security measures and obscure the malicious activity.

**The final phase concerns the detection of command and control communications.** The focus is on monitoring unusual outgoing traffic initiated by potentially malicious scripts. This includes identifying connections to unknown IP addresses or domains and detecting the use of non-standard ports or protocols, such as unconventional HTTP/S traffic.

**It is important to tie this analysis to malicious artifacts identified in earlier stages**, as attempting to investigate all unknown IP communications could prove overly time-consuming and extend beyond the scope of the current investigation. By narrowing the focus, the threat hunting process ensures precision and efficiency in identifying and mitigating the threat.

### Stage 1: Initial Access

The investigation begins with an analysis of the initial access phase, during which the attacker attempts to infiltrate the environment. The first step in this phase involves searching for IoCs identified, which have been observed in phishing campaigns:

- `https[:]//mideashop[.]es/translucid/egotistical/ovule/?`
    
- `https[:]//abuc[.]cm/planning/contagious/?`
    
- `https[:]//ilosalamos[.]cl/hamster/gelatinous/?`
    
- `https[:]//adecco[.]com.working-with-adecco.findajob.profit-potential.top/adecco/ade.php?`
    
- `http[:]//185.147.124[.]40/Capcha.html`
    

#### **KQL Query - Search for Identified URLs in Logs**
 
```kql 
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl in (
    "https://mideashop.es/translucid/egotistical/ovule/?",
    "https://abuc.cm/planning/contagious/?",
    "https://ilosalamos.cl/hamster/gelatinous/?",
    "https://adecco.com.working-with-adecco.findajob.profit-potential.top/adecco/ade.php?",
    "http://185.147.124.40/Capcha.html"
)
```

From the set of results obtained, if any, the threat hunting process must continue to analyze the results.

#### Email Analysis

A subsequent search can be conducted to identify suspicious e-mails from the past 30 days by filtering messages containing keywords derived from the identified URLs. Examples of keywords: 'adecco', 'mideashop', 'abuc', 'contagious', 'capcha' and others.

####  **KQL Query - Search for Suspicious Emails**

```
EmailEvents
| where Timestamp > ago(30d)
| where Subject contains "Fixed" or Subject contains "Programme Manager"
   or Subject contains "money" or Subject contains "Worldwide Delivery"
   or SenderFromAddress contains "adecco" or SenderFromAddress contains "mideashop"
```

From the set of results obtained, if any, the threat hunting process must continue to analyze the results.

---

### Stage 2-3: Execution and Defense Evasion

The second stage involves the execution of malicious payloads, including JavaScript, HTML files, and other types of malicious content.

The following payloads and downloaded files are related to the campaign:

- `https[:]//gwsmltd[.]com/bg/PM-DETAILS-STQRT5RX-102024.zip?`
    
- `http[:]//85.209.11[.]15/q/9.png`
    
- `http[:]//85.209.11[.]15/q/45.png`
    

Additionally, the following malicious hashes were extracted from the downloaded file:

- `B09539cbda49c4c870bba07756eac1c7688e61efb8ea6e9bc2eac6eb53a7df7d 9.png`
    
- `D08928d078d1b2ded79a527727839a0b302088e9934327a93d977e8a830af436 45.png`
    

#### **KQL Query - Search for Downloaded Malicious Files**

```
DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA256 in (
    "B09539cbda49c4c870bba07756eac1c7688e61efb8ea6e9bc2eac6eb53a7df7d",
    "D08928d078d1b2ded79a527727839a0b302088e9934327a93d977e8a830af436"
)
```

From the set of results obtained, if any, the threat hunting process must continue to analyze the results.

A search can be also performed for all URLs contacted in the last 30 days containing filenames matching patterns seen in the malicious campaign (e.g., `9.png`, `25.png`).

#### **KQL Query - Search for Malicious URL Requests**

```
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl endswith ".png"
```

From the set of results obtained, if any, the threat hunting process must continue to analyze the results.

An additional query can be executed to detect instances of `mshta.exe` potentially used to execute HTA scripts or download HTML pages linked to the malicious payload.

#### **KQL Query - Detect mshta.exe Execution**

```
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName == "mshta.exe"
```

From the set of results obtained, if any, the threat hunting process must continue to analyze the results.

---

### Stage 4: Command and Control (C2)

The final phase of the investigation focuses on detecting communications with command and control (C2) infrastructure and monitoring for unusual outbound traffic.

The following IP addresses are associated with the **Xworm** C2 infrastructure:

- `http[:]185.147.124[.]40`
    
- `http[:]85.209.11[.]15`
    

#### **KQL Query - Detect C2 Communications**

```
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in ("185.147.124.40", "85.209.11.15")
```

From the set of results obtained, if any, the threat hunting process must continue to analyze the results.

## Conclusion

The article enables you to identify systems potentially compromised by XWorm malware using threat intelligence bulletins from sources such as cyber threat intelligence reports, websites, and other resources to effectively assess the analysis environment. The goal is to establish a systematic approach that ensures no potential threats are overlooked, highlighting every aspect of a cyber campaign. In addition, it is important to note the use of the MITRE ATT&CK framework, an essential resource that provides a great deal of information on attackers' tactics, techniques, and procedures (TTPs), allowing for refinement of research activities. 

----------

**Proactive threat hunting and continuous monitoring are key to maintaining a secure and resilient network infrastructure.**
> This blog provides a simplified overview of threat research processes. As the cybersecurity landscape evolves, these methodologies are also subject to change. I will strive to keep this resource up to date. [**Your feedback is valuable**](/contact), if you have any suggestions or opinions to share, please contact me so that I can improve this guide.
