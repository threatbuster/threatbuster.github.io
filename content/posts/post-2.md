---
title: "Malicious Browser Extensions Targeting AI Tools"
date: 2026-01-15T12:00:00Z
description: "Analysis of malicious Chrome extensions abusing AI tools to steal user data and AI conversations, including detection techniques and KQL hunting queries using Microsoft Defender telemetry."
categories: ["Endpoint Security", "Threat Intelligence"]
tags: ["Browser Security", "Chrome Extensions", "AI Safety", "Data Exfiltration", "Supply Chain Attack", "Microsoft Defender", "Persistence Techniques", "Credential Theft"]
author: "ThreatBuster"
showToc: true
draft: false
TocOpen: false
layout: "post"
---

## Introduction

Several **malicious extensions** have been observed distributed through official browser extension stores, posing as AI assistants and productivity tools. Thanks to the elevated privileges granted to browser extensions, attackers were able to establish persistent access, monitor browsing activity, and exfiltrate sensitive data with minimal visibility to end users.

The goal of this threat research activity is to identify compromised endpoints, validate the persistence of extensions, and detect command and control (C2) communications. In the example, Microsoft Defender for Endpoint telemetry will be used, but **the logic will be the same on other platforms**.

## Hypothesis

Some users unknowingly installed malicious browser extensions disguised as legitimate artificial intelligence or productivity tools. Once installed, these extensions established persistence and, by requesting additional permissions, began collecting information about user activity and interactions with AI platforms, periodically transmitting the collected data to infrastructure controlled by the attackers. This behavior led to silent data exfiltration and prolonged exposure, with no obvious signs of compromise for the user.

## Data sources

To conduct a thorough investigation, the following data sources can be used. 

{{< warning_badge >}} Table names and schemas are environment-dependent (Microsoft Defender for Endpoint). Ensure you map these hunting activities to your specific workspace configuration. {{< /warning_badge >}}

Primary telemetry sources:

- **DeviceNetworkEvents**  
  Used to detect outbound connections toward suspicious domains.

- **DeviceFileEvents**  
  Used to identify extension-related file creation or modification.

- **DeviceEvents**  
  Used to validate security actions and detections.


## Artifact extraction

The following malicious extensions were identified based on online articles:

| Extension Name | Extension ID |
|---------------|--------------|
| Chat GPT for Chrome with GPT-5, Claude Sonnet & DeepSeek AI | fnmihdojmnkclgjpcoonokmkhjpjechg |
| AI Sidebar with Deepseek, ChatGPT, Claude, and more | inhcgfpbfdjbjogdfjbclgolkmhnooop |

These extensions were observed collecting AI interaction content and session metadata.

### MITRE ATT&CK Mapping

These phishing campaigns can be mapped to multiple MITRE ATT&CK techniques. Below are some of the main ones identified:

- **T1189 – Drive-by Compromise**:  Users are lured into installing malicious browser extensions directly from official browser extension stores. The installation occurs through a trusted delivery channel, without exploiting browser vulnerabilities, making the compromise difficult to detect.

- **T1195.002 – Supply Chain Compromise: Compromise Software Supply Chain**: Threat actors abuse the browser extension ecosystem by publishing trojanized extensions through legitimate stores, effectively compromising the software supply chain and bypassing traditional trust assumptions.

- **T1204.002 – User Execution: Malicious File**: The attack relies on explicit user interaction. Users voluntarily install the malicious extensions, believing them to be legitimate AI assistants or productivity tools.

- **T1176.001 - Browser Extensions**: Core persistence and execution mechanism. These extensions (e.g., "Chat GPT for Chrome" with ID fnmihdojmnkclgjpcoonokmkhjpjechg) install via official stores, load on browser startup, and use elevated privileges to monitor AI interactions without user awareness.

- **T1036 – Masquerading**: Malicious extensions impersonate legitimate AI tools by using deceptive names, icons, and descriptions, reducing user suspicion and increasing installation success.

- **T1056.008 – Input Capture: Web Forms**: Extensions intercept user input and content submitted to web-based AI platforms, allowing the collection of prompts, responses, and interaction context.

- **T1119 – Automated Collection**: Data harvesting is performed continuously and automatically, without requiring further user interaction, enabling large-scale collection of sensitive information.

- **T1555 - Credentials from Password Stores**: Extensions are able to steal cookies, session tokens, and stored credentials via browser APIs (e.g., chrome.cookies)

- **T1217 - Browser Information Discovery**: Extensions can enumerate browsing history, bookmarks, and AI usage patterns for targeted data collection.

- **T1071.001 – Application Layer Protocol: Web Protocols**: Command-and-control communications and data exfiltration occur over HTTP/HTTPS, blending malicious traffic with legitimate browser activity.

- **T1041 - Exfiltration Over C2 Channel**: Collected data (AI chats, metadata) is automatically sent over the same HTTP/HTTPS channels to C2 domains (e.g., chataigpt[.]pro, deepseek[.]ai), blending with normal traffic.


{{< figure src="/post2/mitremapping.png" link="/post2/mitremapping.png" title="MITRE ATT&CK Mapping" alt="MITRE Mapping" align="center" >}}


## Investigation

The hunting activity can be conducted in multiple phases:

1. Identification of endpoints that interact with known malicious extension IDs.
2. Confirmation of the presence of the malicious extension 
3. Network traffic analysis toward known C2 infrastructure  
4. Correlation of blocked and successful outbound connections  

### Stage 1 – Identification of malicious extensions

This stage focuses on detecting potentially malicious browser extensions that may have been installed on endpoint systems. The goal is to identify any indications of compromise based on known malicious extension IDs and related file activities.

#### KQL – Detect malicious extension IDs

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any (
    "fnmihdojmnkclgjpcoonokmkhjpjechg",
    "inhcgfpbfdjbjogdfjbclgolkmhnooop"
)
```

Any devices returned by this query should be flagged for further investigation. 

Recommended next steps include verifying that the suspicious extensions are still installed or have been removed as a result of any corrective actions or user actions. To identify systems that may still host or have recently interacted with the malicious extensions, analyze file operations:

#### KQL – Extension-related file activity

```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has_any (
    "fnmihdojmnkclgjpcoonokmkhjpjechg",
    "inhcgfpbfdjbjogdfjbclgolkmhnooop"
)
```


### Stage 2 – Command and Control detection

Malicious browser extensions communicate with attacker-controlled servers for data exfiltration. The following domains have been identified as part of the suspected C2 infrastructure:

- chataigpt[.]pro
- chatgptsidebar[.]pro
- deepaichats[.]com
- chatsaigpt[.]com
- deepseek[.]ai
- chatgptbuddy[.]com

Use the following query to detect any network events indicating connection attempts from endpoints to the listed domains:

#### KQL – Detect outbound connections to C2 domains

```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any (
    "chataigpt.pro",
    "chatgptsidebar.pro",
    "deepaichats.com",
    "chatsaigpt.com",
    "deepseek.ai",
    "chatgptbuddy.com"
)
```

Endpoints that establish outgoing connections to these domains should be prioritized for investigation and containment.


## Mitigations and recommendations

1. Perform a full antivirus scan on all endpoints identified during the detection phases, ensuring that the latest signatures detecting the malicious extensions are already deployed.
2. If needed, provide users with step‑by‑step instructions to manually remove the malicious extensions from their browsers:
   - Chat GPT for Chrome with GPT-5, Claude Sonnet & DeepSeek AI
   - AI Sidebar with Deepseek, ChatGPT, Claude, and more
4. Enforce browser extension control policies:
   - Allowlist approved extensions
   - Restrict installation from unmanaged publishers
5. Conduct user awareness training focused on browser extensions

## Conclusion

Malicious browser extensions are an especially insidious and effective vector of persistence, particularly when they are distributed through official stores and perceived as trustworthy. Through the use of security telemetry and the correlation of indicators of compromise shared by the research community (**knowledge sharing**), it is possible to proactively identify and mitigate this threat, limiting the risk of prolonged data exposure and compromise of user privacy.


## References

1. OX Security, “Malicious Chrome Extensions Steal ChatGPT & DeepSeek Conversations”, https://www.ox.security/blog/malicious-chrome-extensions-steal-chatgpt-deepseek-conversations/  
2. Dataprise Defense Digest, “Malicious AI Chrome Extensions and Data Exfiltration”, https://www.dataprise.com/resources/defense-digest/malicious-ai-chrome-extensions-data-exfiltration/

----------

**Proactive threat hunting and continuous monitoring are key to maintaining a secure and resilient network infrastructure.**
> This blog provides a simplified overview of threat research processes. As the cybersecurity landscape evolves, these methodologies are also subject to change. I will strive to keep this resource up to date. [**Your feedback is valuable**](/contact), if you have any suggestions or opinions to share, please contact me so that I can improve this guide.