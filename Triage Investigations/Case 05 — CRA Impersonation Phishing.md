# Case 05 — CRA Impersonation Phishing (SPF/DKIM Fail)

**Incident:** 2123 | **Severity:** Low | **Verdict:** True Positive — No User Interaction  
**Date:** 2026-05-22 | **Platform:** Microsoft Sentinel / Defender (EmailEvents)

---

## Alert

**Title:** Email - Authentication SPF/DKIM Fail  
**Description:** Inbound email fails SPF and/or DKIM authentication — indicates spoofed sender  
**MITRE Tactic:** InitialAccess | **Technique:** T1566 (Phishing)  
**Detection Source:** Azure Sentinel scheduled rule  
**Activity:** 2026-05-22T18:34:11Z  

---

## Raw Alert (Key Fields)

```json
{
  "Analytic Rule Name": "Email - Authentication SPF/DKIM Fail",
  "IncidentId": "2123",
  "Search Query Results Overall Count": "1"
}
```

---

## Queries Used

**Find the email in EmailEvents:**
```kql
EmailEvents
| where TimeGenerated between (datetime(2026-05-22T17:00:00Z) .. datetime(2026-05-22T21:00:00Z))
| project Timestamp, SenderFromAddress, SenderIPv4, RecipientEmailAddress, Subject, AuthenticationDetails, DeliveryAction, LatestDeliveryAction, ThreatTypes, DetectionMethods
| order by Timestamp asc
```

**Extract the phishing URL:**
```kql
EmailUrlInfo
| where NetworkMessageId == "e2691498-e008-4289-997b-08deb830b609"
| project Url, UrlDomain, UrlLocation
```

**Check if recipient clicked the URL:**
```kql
UrlClickEvents
| where Timestamp between (datetime(2026-05-22T18:30:00Z) .. datetime(2026-05-22T23:59:00Z))
| where Url has "well3r213.es"
| project Timestamp, AccountUpn, Url, ActionType, IPAddress
| order by Timestamp asc
```

**Check if same sender targeted other recipients:**
```kql
EmailEvents
| where TimeGenerated between (datetime(2026-05-22T17:00:00Z) .. datetime(2026-05-22T21:00:00Z))
| where SenderFromAddress == "fujimoto@endure.jp"
| project Timestamp, RecipientEmailAddress, Subject, DeliveryAction, LatestDeliveryAction
```

---

## Findings

**IOCs:**
- Sender: `fujimoto[@]endure[.]jp`
- Sender IP: `153[.]127[.]234[.]4`
- Sender Domain: `endure[.]jp`
- Display Name Spoofed As: Canada Revenue Agency (CRA)
- Recipient: `info[@]mapletaxsolutions[.]ca`
- Subject: Important Document
- Phishing URL: `hxxps://well3r213[.]es/mm/Updatemail[.]htm`
- Domain: `well3r213[.]es`
- NetworkMessageId: `e2691498-e008-4289-997b-08deb830b609`
- Authentication: SPF=pass (for endure.jp only), DKIM=none, DMARC=bestguesspass
- Initial Delivery: Blocked → Quarantine
- Final Delivery: Released to Inbox (org-level auto-release policy)
- URL Clicks: 0

**Two emails sent — same sender, same recipient, 15 minutes apart:**
- 2026-05-22 18:19 UTC — Blocked, remained in quarantine
- 2026-05-22 18:34 UTC — Blocked, then auto-released to inbox (this alert)

---

## Investigation Summary

On 2026-05-22 at 18:34 UTC, a phishing email impersonating the Canada Revenue Agency (CRA) was delivered to `info[@]mapletaxsolutions[.]ca`. The sender `fujimoto[@]endure[.]jp` spoofed the display name to "Canada Revenue Agency (CRA)" while using a Japanese domain. The email contained a link to `hxxps://well3r213[.]es/mm/Updatemail[.]htm` — a credential harvesting page. Microsoft initially quarantined the email (High confidence Phish) but an org-level policy auto-released it to the inbox. A follow-up query confirmed no URL clicks occurred and no other recipients were targeted. This was one of two identical emails sent 15 minutes apart — only the second was auto-released.

**WHO:** Unknown threat actor; victim: `info[@]mapletaxsolutions[.]ca` (Canadian tax solutions firm)  
**WHAT:** CRA impersonation phishing email with credential harvesting link  
**WHEN:** 2026-05-22 18:19 UTC (first attempt) and 18:34 UTC (second, released to inbox) — activity ended, no clicks  
**WHERE:** Microsoft Exchange Online — inbound email to mapletaxsolutions.ca tenant  
**WHY:** Targeting a tax solutions company with a CRA impersonation is likely aimed at harvesting M365 or CRA portal credentials  
**HOW:** Spoofed display name sent from Japanese domain; bypassed DMARC due to weak policy; auto-release policy allowed delivery to inbox despite high-confidence phish detection  

---

## Recommendations

1. Review and tighten the org-level quarantine auto-release policy — high-confidence phish emails should never be auto-released.
2. Block sender domain `endure[.]jp` and IP `153[.]127[.]234[.]4` in the email gateway.
3. Block domain `well3r213[.]es` at the web proxy and email gateway.
4. Notify `info[@]mapletaxsolutions[.]ca` of the phishing attempt.
5. Enforce DMARC reject policy on the recipient domain to prevent display name spoofing.
