# SOC Analyst — Triage Case Repository

**Analyst:** SOC-201 | Jophiel Arevalo Enriquez  
**Platform:** MyDFIR SOC Simulator (mahcyberdefense.com)  
**Environment:** Microsoft XDR / Sentinel / Splunk  
**Period:** May–July 2026  

---

## Overview

This repository documents ten real triage cases worked through the MyDFIR SOC Simulator. Each case includes the original alert, raw alert data, investigation queries, findings, and a structured report following the 5W1H format.

---

## Case Index

| # | Case | Severity | Verdict | Platform |
|---|---|---|---|---|
| 01 | [Anonymous IP — SOC-174 (Tor)](https://github.com/JophielArevalo1998/SOC-Portfolio/blob/main/Triage%20Investigations%20Sentinel-Splunk/Case%2001%20anonymous%20ip%20soc%20174.md) | Low | True Positive | Microsoft XDR |
| 02 | [ValleyRAT Multi-Stage Compromise — KCD-Web](https://github.com/JophielArevalo/SOC-Portfolio/blob/main/Triage%20Investigations%20Sentinel-Splunk/Case%2002%20valleyrat%20kcd%20web.md) | Medium → Critical | True Positive — Active Intrusion | Splunk |
| 03 | [Credential Stuffing — MTS-ContractorPC1 (Incident 2120)](https://github.com/JophielArevalo/SOC-Portfolio/blob/main/Triage%20Investigations%20Sentinel-Splunk/Case%2003%20credential%20stuffing%20mts%202120.md) | Low | True Positive — Unsuccessful | Sentinel |
| 04 | [Credential Stuffing — MTS-ContractorPC1 (Incident 2121)](github.com/JophielArevalo/SOC-Portfolio/blob/main/Triage%20Investigations%20Sentinel-Splunk/Case%2004%20credential%) | Low | True Positive — Unsuccessful | Sentinel |
| 05 | [CRA Phishing Email — SPF/DKIM Fail](https://github.com/JophielArevalo/SOC-Portfolio/blob/main/Triage%20Investigations%20Sentinel-Splunk/Case%2005%20cra%20phishing%20email.md) | Low | True Positive — No User Interaction | Defender |
| 06 | [Unauthorized WordPress Admin Access](https://github.com/JophielArevalo/SOC-Portfolio/blob/main/Triage%20Investigations%20Sentinel-Splunk/Case%2006%20wordpress%20admin%20login.md) | High | True Positive — Active Compromise | Sentinel |
| 07 | [RDP Login — KCD-Web (Benign)](https://github.com/JophielArevalo/SOC-Portfolio/blob/main/Triage%20Investigations%20Sentinel-Splunk/Case%2007%20kcd%20rdp%20login%20benign.md) | Medium | True Positive — Benign | Splunk |
| 08 | [Anonymous IP — SOC-186 (Log Retention Expired)](https://github.com/JophielArevalo/SOC-Portfolio/blob/main/Triage%20Investigations%20Sentinel-Splunk/Case%2008%20anonymous%20ip%20soc%20186.md) | Medium | True Positive — Limited Evidence | Microsoft XDR |
| 09 | [RDP Login — KCD Contractor (Benign)](https://github.com/JophielArevalo/SOC-Portfolio/blob/main/Triage%20Investigations%20Sentinel-Splunk/Case%2009%20kcd%20contractor%20rdp%20benign.md) | Medium | True Positive — Benign | Splunk |
| 10 | [SOC Account Compromise — UK Sign-in](https://github.com/JophielArevalo/SOC-Portfolio/blob/main/Triage%20Investigations%20Sentinel-Splunk/Case%2010%20soc%20account%20compromise%20uk.md) | Medium → Critical | True Positive — Active Compromise | Microsoft XDR |

---

## Skills Demonstrated

- Alert triage across Microsoft XDR, Sentinel, and Splunk
- KQL (Kusto Query Language) for Defender Advanced Hunting
- Splunk SPL for endpoint and identity investigation
- OSINT — VirusTotal, AbuseIPDB, Shodan
- Malware identification (ValleyRAT / Silver Fox APT)
- Email forensics — SPF, DKIM, DMARC analysis
- Web log analysis — Apache access log parsing via KQL regex
- IOC defanging and report writing
- MITRE ATT&CK technique mapping
- Impossible travel and identity-based detection investigation
