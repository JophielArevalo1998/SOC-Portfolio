# 🔔 Alert & Rule Configurations

> This file documents every alert and detection rule created during the lab, including the body template used for osTicket integration.

---

## Alert 1 — SSH Brute Force

**Location in Kibana:** Security → Rules → Detection Rules (or Discover → top-right → Alerts)

```yaml
Name: SSH Brute Force - SOC-Linux-Jop
Type: Threshold
Index: logs-system.auth-*
Query: >
  system.auth.ssh.event: "Failed"
  and agent.name: "SOC-Linux-Jop"
Threshold: 5
Group By:
  - source.ip
  - user.name
Time window: 5 minutes
Severity: Medium
Tags:
  - SSH
  - BruteForce
  - Linux
```

**osTicket webhook body (paste under Rule → Actions → Webhook):**
```json
{
  "alert": true,
  "autorespond": true,
  "source": "API",
  "name": "SOC Alert Bot",
  "email": "alerts@soc-lab.local",
  "subject": "SSH Brute Force Detected - {{rule.name}}",
  "message": "SSH Brute Force Alert fired at {{date}}\n\nRule: {{rule.name}}\nSeverity: {{rule.severity}}\n\nSource IP: {{context.sourceIp}}\nTarget User: {{context.user}}\nFailed Attempts: {{context.value}}\n\nInvestigate at: {{kibanaBaseUrl}}/app/security"
}
```

---

## Alert 2 — RDP Brute Force (Windows)

```yaml
Name: RDP Brute Force - SOC-WIN-JOP
Type: Threshold
Index: logs-windows.*
Query: >
  event.code: "4625"
  and agent.name: "SOC-WIN-JOP"
Threshold: 5
Group By:
  - source.ip
  - winlog.event_data.TargetUserName
Time window: 5 minutes
Severity: Medium
Tags:
  - RDP
  - BruteForce
  - Windows
```

---

## Detection Rule 1 — RDP Brute Force (Custom Query)

> More informative than the alert — provides full context in the Security → Alerts timeline.

```yaml
Name: RDP Brute Force Detection Rule
Type: Custom Query (Threshold variant)
Index: logs-windows.*
Query: >
  event.code: "4625"
  and agent.name: "SOC-WIN-JOP"
Threshold: 5
Group By:
  - source.ip
  - winlog.event_data.TargetUserName
Required Fields:
  - source.ip
  - winlog.event_data.TargetUserName
  - winlog.event_data.LogonType
  - @timestamp
Severity: Medium
Risk Score: 47
```

---

## Detection Rule 2 — Mythic Apollo C2 Implant

```yaml
Name: Mythic Apollo C2 - Process Creation by Hash
Type: Custom Query
Index:
  - logs-endpoint*
  - logs-windows.*
Query: >
  event.code: "1"
  and winlog.event_data.OriginalFileName: "Apollo.exe"
  and winlog.event_data.Hashes: *B922E4A7C639E697D4AA06196E4DDE56CAF49CC4837F253228237EF46A285F90*
Required Fields:
  - winlog.event_data.Hashes
  - winlog.event_data.OriginalFileName
  - winlog.event_data.Image
  - winlog.event_data.CommandLine
  - winlog.event_data.ParentImage
  - process.entity_id
Severity: Critical
Risk Score: 99
Tags:
  - C2
  - Mythic
  - Apollo
  - MalwareExecution
```

---

## osTicket API Test Payload

> Use this to test the webhook connector from Kibana before attaching it to real rules.
> Source: https://github.com/osTicket/osTicket/blob/develop/setup/doc/api/tickets.md

```json
{
  "alert": true,
  "autorespond": true,
  "source": "API",
  "name": "Test Alert",
  "email": "test@example.com",
  "phone": "",
  "subject": "Test Ticket from Elastic",
  "ip": "123.211.233.122",
  "message": "data:text/html,<b>This is a test ticket created via the Elastic webhook connector.</b><br><br>If you can see this ticket in osTicket, the integration is working correctly."
}
```

---

## Webhook Connector Configuration (Kibana)

```
Name:         osTicket-SOC-Webhook
Type:         Webhook
URL:          http://OSTICKET_PRIVATE_IP/osticket/upload/api/tickets.json
Method:       POST

Headers:
  Content-Type:   application/json
  X-API-Key:      YOUR_OSTICKET_API_KEY

Authentication: None (API key in header)
```

> **Note on IP:** Use the **private/internal IP** of the osTicket server (not public) since both machines are in the same VPC. This avoids unnecessary external routing and is more secure.
