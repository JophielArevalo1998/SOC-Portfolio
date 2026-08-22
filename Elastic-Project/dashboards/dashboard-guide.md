# 📊 Dashboard Setup Guide

> Step-by-step instructions to recreate all dashboards in Kibana from scratch.

---

## Dashboard 1 — SSH Brute Force Attack Map

**Goal:** Show a world map with countries color-coded by number of failed SSH attempts.

### Steps:

1. Go to **Kibana → Maps → Create new map**
2. Click **Add layer**
3. Select **Administrative boundaries → World Countries**
4. Under **Layer style → Term joins**, click **Add join**
5. Configure the join:
   - **Left field:** `ISO 3166-1 alpha-2 code`
   - **Right source:** your `logs-system.auth-*` index
   - **Right field:** `source.geo.country_iso_code`
   - **Metric:** Count of documents
   - **Filter:** `system.auth.ssh.event: "Failed" and agent.name: "SOC-Linux-Jop"`
6. Set **Layer style → Fill color → By value** → choose the count metric
7. Save as: **SSH Brute Force — Source Countries**

### Screenshot reference:
`screenshots/14-ssh-map-dashboard.png`

---

## Dashboard 2 — RDP Activity Dashboard

**Goal:** Full RDP monitoring dashboard with map, failed attempts table, and successful logons table.

### Panel 1 — Attacker Countries Map

1. Go to **Kibana → Maps → Create new map**
2. Add layer → World Countries → join on `source.geo.country_iso_code`
3. Filter: `event.code: "4625" and agent.name: "SOC-WIN-JOP"`
4. Save as a panel to add to the dashboard

### Panel 2 — Failed RDP Logons Table

1. **Analytics → Dashboards → Create visualization**
2. Select **Table** chart type
3. **Query:** `event.code: "4625" and agent.name: "SOC-WIN-JOP"`
4. **Rows (Bucket aggregations):**
   - `source.ip` — Top 10 values
   - `winlog.event_data.TargetUserName` — Top 10 values
5. **Metric:** Count
6. Panel title: **Failed RDP Logon Attempts**

### Panel 3 — Successful RDP Logons Table

1. Create another **Table** visualization
2. **Query:** `event.code: "4624" and agent.name: "SOC-WIN-JOP" and (winlog.event_data.LogonType: 10 or winlog.event_data.LogonType: 7)`
3. **Rows:**
   - `source.ip`
   - `winlog.event_data.TargetUserName`
   - `winlog.event_data.LogonType`
4. Panel title: **Successful RDP Sessions**

### Assemble the dashboard:

1. **Analytics → Dashboards → Create dashboard**
2. Add each panel via **Add panel → Existing visualization**
3. Drag panels to arrange them (map on top, tables below)
4. Save as: **RDP Activity Dashboard**

### Screenshot references:
- `screenshots/16-rdp-dashboard.png`
- `screenshots/17-rdp-map.png`
- `screenshots/18-rdp-tables.png`

---

## Dashboard 3 — Mythic C2 / Endpoint Activity Dashboard

**Goal:** Three panels covering process creation, network connections, and Defender disables — the key signals of a C2 compromise.

### Panel 1 — Suspicious Process Creation

- **Type:** Table
- **Query:** `event.code: "1" and event.provider: "Microsoft-Windows-Sysmon" and (powershell or cmd or rundll32)`
- **Fields to show:**
  - `winlog.event_data.Image` — process path
  - `winlog.event_data.CommandLine` — full command
  - `winlog.event_data.ParentImage` — parent process
  - `@timestamp`
- **Panel title:** Suspicious Process Execution (Sysmon ID:1)

### Panel 2 — Outbound Network Connections

- **Type:** Table
- **Query:** `event.code: "3" and event.provider: "Microsoft-Windows-Sysmon" and winlog.event_data.Initiated: "true"`
- **Fields to show:**
  - `winlog.event_data.Image` — which process made the connection
  - `winlog.event_data.DestinationIp`
  - `winlog.event_data.DestinationPort`
  - `@timestamp`
- **Panel title:** Outbound Network Connections (Sysmon ID:3)

### Panel 3 — Windows Defender Disabled

- **Type:** Table or Metric count
- **Query:** `event.code: "5001" and event.provider: "Microsoft-Windows-Windows Defender"`
- **Fields to show:**
  - `@timestamp`
  - `host.name`
  - `winlog.event_data.ProductName`
- **Panel title:** Defender Real-Time Protection Disabled (ID:5001)

### Save as: **Endpoint Threat Dashboard — C2 Activity**

### Screenshot reference:
`screenshots/29-c2-hunting.png`

---

## Tips for Building Kibana Visualizations

| Tip | Detail |
|-----|--------|
| **Use Lens** | Kibana's Lens editor is the easiest for tables and bar charts |
| **Use Maps** | For geographic visualizations — don't use Lens for maps |
| **Save before adding to dashboard** | Create each visualization, save it, then add to dashboard |
| **Time filter** | Always check the time filter in the top right — set to "Last 7 days" or your lab's activity period |
| **Refresh rate** | Set "Auto refresh: 10 seconds" when monitoring live attacks |
| **Index pattern** | Ensure the correct index pattern is selected for each visualization |
