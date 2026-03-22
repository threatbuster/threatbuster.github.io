---
title: "Abusing public repositories for malware distribution"
date: 2026-03-20T12:00:00Z
description: "Identification of malicious campaigns that exploit GitHub repositories to spread malicious code disguised as software utility within the environment "
categories: ["Endpoint Security", "Threat Intelligence", "Security Automation"]
tags: ["Malvertising", "GitHub Abuse", "Ingress Tool Transfer", "Social Engineering", "Malware Distribution", "Cloud Abuse", "Python Tool", "SOAR"]
author: "ThreatBuster"
showToc: true
draft: false
TocOpen: false
layout: "post"
---

## Introduction

Large-scale campaigns, which target a massive number of worldwide devices, often distribute malware through **newly created websites that masquerade itself as legitimate software utilities**. These sites frequently redirect users to payloads hosted on platforms such as GitHub, or present those same GitHub repositories as legitimate software that unsuspecting users might download and run.

Modern threat actors **exploit highly trusted public infrastructure** to rapidly upload and distribute malicious software before it can be detected and removed. This approach allows them to bypass traditional network security controls, **taking advantage on the trust that users naturally place in these services**. Consequently, both the initial download and the subsequent distribution of the payload often evade domain reputation filters and other defences, allowing malicious elements to be introduced into the environment without triggering immediate alerts.

The goal of this threat hunting activity is to identify both repositories that have already been deactivated but may have introduced malicious software when they were active, and newly created malicious repositories that have not yet been classified or reported.

**NOTE:** The article focuses on GitHub repositories, but the concepts can be applied to other websites as well.

## Hypothesis

A user within the environment was exposed to a misleading campaign or search results while searching for legitimate software, which led him to access a **malicious repository**. The repository likely hosted seemingly harmless software which, once downloaded and executed, resulted in the installation of a malicious payload within the environment.

## Data sources

{{< warning_badge >}} Any data source that allows the extraction of URLs pointing to repositories can be used. In the case of Microsoft Defender, this refers specifically to referral URLs leading to the public repositories from which the software is downloaded.{{< /warning_badge >}}

Telemetry source:

- **DeviceFileEvents**: used to identify the creation of files on the system, such as ZIP archives, installers, executable files and other content downloaded from unverified or unknown URLs.

## Investigation

The principle behind this type of analysis is straightforward and can be implemented within SOAR platforms or as a standalone solution. 

The workflow can be broken down into three main stages:

1. **Identification and extraction:** The researcher must identify and extract all download links from the identified repositories, along with their source/referral URL.

2. **Enrichment:** URLs must be enriched with additional attributes and useful information in order to be prioritised.

3. **Analysis and prioritisation**:  evaluate the enriched data to identify and focus on the most suspicious entries.


### Stage 1 – GitHub URL discovery and extraction from telemetry

By using pre-defined queries, such as the one below, URLs of interest can be extracted from Microsoft Defender telemetry.

#### KQL – GitHub payload download

```kql
DeviceFileEvents
| where FileOriginReferrerUrl has "github" or FileOriginUrl has "github"
| where TimeGenerated > ago(30d)
| project TimeGenerated, DeviceName, FileName, FileOriginUrl, FileOriginReferrerUrl
| summarize
    Occurrences = count(),
    FileNames = make_set(FileName),
    FileOriginUrls = make_set(FileOriginUrl)
    by FileOriginReferrerUrl
| extend FileNames_count = array_length(FileNames)
| order by FileNames_count desc
```

{{< warning_badge >}} The result table contains 6 real-world malicious URLs identified this month. {{< /warning_badge >}}


{{< figure src="/post3/extracted_url.png" link="/post3/extracted_url.png" title="GitHub URL extraction from Microsoft Defender telemetry (KQL results)" alt="Table showing GitHub-related URLs extracted from Microsoft Defender DeviceFileEvents using a KQL query, including referrer URLs and file download activity" align="center" >}}

URLs can be extracted using a custom logic. From the query shown above, it is possible to identify the '**FileOriginReferrerUrl**' field, which can prove particularly useful, as well as the '**FileOriginUrl**' field. 

It is important to note that 'FileOriginUrl' often contains multiple direct download links related to the same GitHub repository. These URLs typically refer to the same resource through different delivery endpoints and should therefore be normalized and deduplicated during processing. Once cleaned and consolidated, the resulting set of URLs can be used for further investigation.

### Stage 2 – URL enrichment and contextual risk profiling

The process of extracting URLs usually generates a large number of results. It is therefore necessary to **establish a methodology for prioritising suspicious URLs**.

To make the dataset more manageable, results can be enriched using a simple script (link at the end of the paragraph), in which each URL can be tagged with additional attributes that make it easier to classify them according to specific characteristics. In the script developed, the URLs are classified by correlating basic attributes relating to the URL itself or to the GitHub portal.

- **url**</br>
    Description: The original URL being analyzed.

- **status_code**</br> 
    Description: HTTP response status code returned by the server.</br>
    Why: Non-200 responses (e.g., 403, 404, 500) may indicate inactive, restricted, or misconfigured infrastructure often associated with malicious or short-lived campaigns

- **ssl_issuer**</br>
    Description: The Certificate Authority (CA) that issued the SSL/TLS certificate.</br>
    Why: Suspicious or uncommon issuers, or self-signed certificates, are often used in malicious infrastructure.

- **ssl_fingerprint**</br>
    Description: A unique hash (SHA-256) of the SSL certificate.</br>
    Why: Enables correlation across multiple domains using the same certificate. Reused fingerprints across unrelated domains can indicate attacker infrastructure reuse.

- **ssl_valid_from**</br>
    Description: The start date of the certificate validity period.</br>
    Why: Very recent certificates are often associated with newly created malicious domains used in phishing or malware campaigns.

- **age_certificate**</br>
    Description: The age of the SSL certificate in days.

GitHub-related fields:

- **github_stars**</br>
    Description: Number of stars (popularity indicator) of the repository.</br>
    Why: Legitimate repositories tend to have community engagement. Very low or zero stars may indicate newly created or fake repositories.

- **github_forks**</br>
    Description: Number of times the repository has been forked.</br>
    Why: Forks indicate community usage and trust. A lack of forks may suggest the repository is not widely used or trusted.

- **github_age_days**</br>
    Description: Age of the repository in days since creation.</br>
    Why: Recently created repositories are often used in malware distribution or phishing campaigns before being taken down.

- **github_has_issues**</br>
    Description: Whether the repository has issues enabled.</br>
    Why: Legitimate projects typically use issue tracking. Disabled issues may indicate lack of transparency or a disposable repository.

- **github_has_wiki**</br>
    Description: Whether the repository includes a wiki.</br>
    Why: Wikis are often present in mature, legitimate projects. Absence may indicate low effort or malicious intent.

- **github_description**</br>
    Description: Textual description of the repository provided by the owner.</br>
    Why: Missing, vague, or misleading descriptions can be a red flag.


{{< figure src="/post3/extracted_url_refined.png" link="/post3/extracted_url_refined.png" title="Refined and prioritized GitHub URLs for threat hunting analysis" alt="Processed dataset of GitHub URLs filtered and normalized to highlight suspicious repositories based on risk indicators such as activity and age" align="center" >}}

{{< warning_badge >}} The script provided is a simplified utility designed to help prioritise the analysis of potentially malicious GitHub repositories and URLs that redirect to suspicious content. This type of analysis can also be integrated into automated workflows and managed via SOAR platforms. {{< /warning_badge >}}

> 🛠️ You can find the script here: [**url-repo-enrichment-toolkit**](https://github.com/threatbuster/url-repo-enrichment-toolkit)

### Stage 3 – Risk-based prioritization

The extracted features enable the **combination of multiple weak signals into actionable intelligence** and allow prioritization of URLs for further investigation. Once the list has been refined, the next step is to analyze it and isolate the most suspicious entries.

The dataset can be sorted and refined by removing less suspicious entries using **context-driven parameters**. For example, URLs can be prioritized based on red flags such as:

- Newly created domains or repositories
- Expired or inactive URLs
- Unusual patterns or inconsistencies

From there, the investigation becomes more exploratory and **is up to you**!

Newly created repositories, or those that are already inactive or have been removed, are often more likely to have hosted malicious content. Furthermore, URLs or repositories that have already been removed should be analysed and correlated with the behaviour detected by the **telemetry data available in your environment**.



##  Mitigations and recommendations

1. **Block or restrict access to repositories**  
   Maintain and regularly update a dynamic list of repositories and URLs identified as malicious or suspicious. If possible, implement **conditional access policies** that restrict downloads from newly created or low-reputation repositories, thereby reducing exposure to short-lived malicious infrastructure.

2. **Implement reputation-aware filtering**  
   Move beyond simple domain reputation and introduce controls that evaluate contextual indicators. Define **custom risk thresholds** to automatically flag or block suspicious downloads.

3. **User awareness and training**  
   Raise awareness among users about the issue of 'abuse of trusted platforms'. Emphasise that platforms such as GitHub are not inherently secure.  

4. **SOAR – Automate enrichment and scoring**  
   Integrate automated enrichment into your detection pipeline using a SOAR platform. A typical enrichment workflow may include:  
   - Extract URL/repository from telemetry / emails and so on. 
   - Use external sources or internal 
   - Retrieve metadata (age, stars, forks, description)  
   - Calculate a risk score based on predefined heuristics  

   This approach significantly reduces manual triage and enables faster response times.


## Conclusion

The analysis demonstrates how trusted platforms can be effectively abused to distribute malicious payloads while bypassing traditional security controls. By leveraging public repositories, threat actors exploit implicit trust, making detection significantly more challenging.

Through structured threat hunting and correlation of weak signals it is possible to uncover suspicious activity that would otherwise remain undetected. The key takeaway is that contextual and behavioral analysis must complement reputation-based controls. Organizations that rely solely on domain trust are inherently exposed to this type of attack vector.   
 
----------

**Proactive threat hunting and continuous monitoring are key to maintaining a secure and resilient network infrastructure.**
> This blog provides a simplified overview of threat research processes. As the cybersecurity landscape evolves, these methodologies are also subject to change. I will strive to keep this resource up to date. [**Your feedback is valuable**](/contact), if you have any suggestions or opinions to share, please contact me so that I can improve this guide.