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
| 01 | [Anonymous IP — SOC-174 (Tor)](https://github.com/JophielArevalo1998/SOC-Portfolio/blob/main/Triage%20Investigations/Case%2001%20%E2%80%94%20Anonymous%20IP%20Address.md) | Low | True Positive | Microsoft XDR |
| 02 | [ValleyRAT Multi-Stage Compromise — KCD-Web](https://github.com/JophielArevalo1998/SOC-Portfolio/blob/main/Triage%20Investigations/Case%2002%20%E2%80%94%20ValleyRAT%20Multi-Stage%20Compromise.md) | Medium → Critical | True Positive — Active Intrusion | Splunk |
| 03 | [Credential Stuffing — MTS-ContractorPC1 (Incident 2120)](https://github.com/JophielArevalo1998/SOC-Portfolio/blob/main/Triage%20Investigations/Case%2003%20%E2%80%94%20Credential%20Stuffing%20SMB%20Exposure.md) | Low | True Positive — Unsuccessful | Sentinel |
| 04 | [Credential Stuffing — MTS-ContractorPC1 (Incident 2121)](https://github.com/JophielArevalo1998/SOC-Portfolio/blob/main/Triage%20Investigations/Case%2004%20%E2%80%94%20Credential%20Stuffing%20SMB%20Exposure.md) | Low | True Positive — Unsuccessful | Sentinel |
| 05 | [CRA Phishing Email — SPF/DKIM Fail](https://github.com/JophielArevalo1998/SOC-Portfolio/blob/main/Triage%20Investigations/Case%2005%20%E2%80%94%20CRA%20Impersonation%20Phishing.md) | Low | True Positive — No User Interaction | Defender |
| 06 | [Unauthorized WordPress Admin Access](https://github.com/JophielArevalo1998/SOC-Portfolio/blob/main/Triage%20Investigations/Case%2006%20%E2%80%94%20Unauthorized%20WordPress%20Admin%20Access.md) | High | True Positive — Active Compromise | Sentinel |
| 07 | [RDP Login — KCD-Web (Benign)](https://github.com/JophielArevalo1998/SOC-Portfolio/blob/main/Triage%20Investigations/Case%2007%20%E2%80%94%20RDP%20Login%20to%20KCD-Web.md) | Medium | True Positive — Benign | Splunk |
| 08 | [Anonymous IP — SOC-186 (Log Retention Expired)](https://github.com/JophielArevalo1998/SOC-Portfolio/blob/main/Triage%20Investigations/Case%2008%20%E2%80%94%20Anonymous%20IP%20Address.md) | Medium | True Positive — Limited Evidence | Microsoft XDR |
| 09 | [RDP Login — KCD Contractor (Benign)](https://github.com/JophielArevalo1998/SOC-Portfolio/blob/main/Triage%20Investigations/Case%2009%20%E2%80%94%20RDP%20Login%20to%20KCD%20Workstation.md) | Medium | True Positive — Benign | Splunk |
| 10 | [SOC Account Compromise — UK Sign-in](https://github.com/JophielArevalo1998/SOC-Portfolio/blob/main/Triage%20Investigations/Case%2010%20%E2%80%94%20SOC%20Account%20Compromise.md) | Medium → Critical | True Positive — Active Compromise | Microsoft XDR |

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
