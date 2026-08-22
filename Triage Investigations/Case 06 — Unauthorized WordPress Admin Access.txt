

Case 06 wordpress admin login · MD
# Case 06 — Unauthorized WordPress Admin Access
 
**Incident:** 2127 | **Severity:** High | **Verdict:** True Positive — Active Compromise  
**Date:** 2026-05-23 | **Platform:** Microsoft Sentinel (Access_CL — Apache web logs)
 
---
 
## Alert
 
**Title:** Identity - Successful Admin WordPress Login  
**Description:** Successful POST to `/wp-admin/admin-ajax.php` from non-whitelisted IP  
**MITRE Tactic:** InitialAccess | **Technique:** T1078 (Valid Accounts)  
**Detection Source:** Azure Sentinel scheduled rule (Access_CL custom log)  
**Activity:** 2026-05-23T01:40:51Z – 2026-05-23T01:41:04Z  
**Whitelisted legitimate admin IP:** `70[.]31[.]87[.]94`  
 
---
 
## Raw Alert (Key Fields)
 
```json
{
  "Analytic Rule Name": "Identity - Successful Admin WordPress Login",
  "severity": "High",
  "Search Query Results Overall Count": "3",
  "Query": "Access_CL | ... | where client_ip !in ('70.31.87.94') | where status == '200' and method == 'POST' and url == '/wp-admin/admin-ajax.php'"
}
```
 
---
 
## Queries Used
 
**Find the triggering IP and full admin session:**
```kql
Access_CL
| extend raw = tostring(RawData)
| extend client_ip = extract(@"^(\S+)", 1, raw)
| extend method = extract(@"""(\S+)\s", 1, raw)
| extend url = extract(@"""(?:\S+)\s(\S+)\s", 1, raw)
| extend status = toint(extract(@""" \s*(\d{3})\s", 1, raw))
| where TimeGenerated between (datetime(2026-05-23T01:35:00Z) .. datetime(2026-05-23T01:50:00Z))
| where status == 200 and method == "POST" and url == "/wp-admin/admin-ajax.php"
| project TimeGenerated, client_ip, method, status, url, RawData
| order by TimeGenerated asc
```
 
**All WordPress admin/login activity grouped by IP:**
```kql
Access_CL
| extend raw = tostring(RawData)
| extend client_ip = extract(@"^(\S+)", 1, raw)
| extend method = extract(@"""(\S+)\s", 1, raw)
| extend url = extract(@"""(?:\S+)\s(\S+)\s", 1, raw)
| extend status = toint(extract(@""" \s*(\d{3})\s", 1, raw))
| where TimeGenerated between (datetime(2026-05-23T00:00:00Z) .. datetime(2026-05-23T03:00:00Z))
| where url has_any ("wp-login", "xmlrpc", "admin-ajax", "wp-admin")
| summarize count() by client_ip, url, status
| order by count_ desc
```
 
**Specific admin pages accessed by primary attacker:**
```kql
Access_CL
| extend raw = tostring(RawData)
| extend client_ip = extract(@"^(\S+)", 1, raw)
| extend method = extract(@"""(\S+)\s", 1, raw)
| extend url = extract(@"""(?:\S+)\s(\S+)\s", 1, raw)
| extend status = toint(extract(@""" \s*(\d{3})\s", 1, raw))
| where TimeGenerated between (datetime(2026-05-23T01:38:00Z) .. datetime(2026-05-23T01:45:00Z))
| where client_ip == "70.49.218.243"
| where url has "wp-admin"
| project TimeGenerated, method, status, url
| order by TimeGenerated asc
```
 
---
 
## Findings
 
**IOCs:**
- IP (primary): `70[.]49[.]218[.]243` — Bell Canada, Ottawa (0 AbuseIPDB reports — residential, deepest session)
- IP: `205[.]185[.]122[.]41` — FranTech Solutions, Las Vegas (313 reports, 100% abuse confidence)
- IP: `209[.]141[.]61[.]179` — FranTech Solutions, Las Vegas (200 reports, 100% abuse confidence)
- IP: `165[.]227[.]37[.]172` — DigitalOcean, Toronto (wp-cron abuse)
- IP: `78[.]153[.]140[.]251` — HOSTGLOBAL.PLUS LTD, London (2,759 reports, 100% abuse)
- IP: `78[.]153[.]140[.]156` — HOSTGLOBAL.PLUS LTD, London (2,976 reports, 100% abuse)
- WordPress site hosted at the investigated domain
**Primary attacker session (`70[.]49[.]218[.]243`) — 39 requests, 40 seconds:**
- Logged in via `wp-login.php` → redirected to `/wp-admin/`
- Loaded `plugin-install.min.js` — navigated to plugin install page
- Accessed `options-general.php` — WordPress general settings
- Accessed `admin.php?page=when-last-login-settings` — audited admin login times
- Accessed `users.php` — viewed full user list
- 3x POST to `admin-ajax.php` — performed admin actions
**wp-cron abuse by `165[.]227[.]37[.]172`:**
- Hit `/wp-cron.php?doing_cron` twice (01:29 and 02:34 UTC) — possible scheduled backdoor trigger
---
 
## Investigation Summary
 
On 2026-05-23 between 01:29–02:35 UTC, four external IPs successfully authenticated to the WordPress admin panel via `wp-login.php`. The primary attacker (`70[.]49[.]218[.]243`) conducted a 39-request admin session accessing plugin installation, general settings, login audit data, and the user list. Simultaneously, a DigitalOcean IP (`165[.]227[.]37[.]172`) triggered `wp-cron.php` twice — consistent with executing a scheduled task or backdoor planted during the admin session. Two additional high-abuse IPs (`78[.]153[.]140[.]251/156`) made POST requests to the homepage. Web logs do not confirm whether a plugin was installed or user created — WordPress database forensics are required to determine the full impact.
 
**WHO:** Multiple threat actors (at least 4 IPs); some on known malicious infrastructure (FranTech, HOSTGLOBAL.PLUS)  
**WHAT:** Unauthorized WordPress admin logins — settings accessed, user list viewed, plugin install page visited, wp-cron abused  
**WHEN:** 2026-05-23 01:29–02:35 UTC — activity window confirmed; persistence via wp-cron may be ongoing  
**WHERE:** WordPress admin panel — internet-facing web application  
**WHY:** Likely to establish persistent access via malicious plugin, backdoor user, or scheduled task  
**HOW:** Valid admin credentials used — source of credential leak unknown; no brute force detected preceding the logins  
 
---
 
## Recommendations
 
1. Reset all WordPress admin account passwords immediately.
2. Audit installed plugins — check for any added or modified after 2026-05-23 01:00 UTC.
3. Audit WordPress user accounts for new or modified admin users.
4. Review `options-general.php` settings for unauthorised changes.
5. Inspect `wp-cron.php` scheduled tasks for malicious entries.
6. Block all attacking IPs at the WAF.
7. Restrict `wp-login.php` and `wp-admin/` access to known IPs or require VPN.
8. Investigate how admin credentials were obtained.
 
