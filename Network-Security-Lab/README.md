# Network Security Lab – DMZ, DNS, Email, Proxy, Firewall & VPN

A blue‑team engineering lab that implements and validates a **segmented network** with:
- Dual gateways (external/internal) with IP forwarding & NAT
- DMZ web server (HTTP/HTTPS)
- BIND9 DNS (authoritative + forwarders)
- Postfix/IMAP email path validation
- Squid proxy with ACLs (e.g., .au restriction)
- iptables firewall (default‑deny + stateful allows)
- OpenVPN connectivity with tun interface verification

---

## 🎯 Objectives
- Build a minimal yet realistic **defensive network**.
- Enforce **least privilege** at network boundaries (firewalling, ACLs).
- Validate end‑to‑end **service availability** and **policy enforcement**.
- Document configs so the design is auditable and reproducible.

---

## 📁 Folder Contents
- **report.pdf** — The full lab walkthrough with screenshots.
- **gateway-configs/** — Netplan/sysctl/iptables snippets for each gateway.
- **dns-setup.md** — BIND9 configuration (options, zones, reverse).
- **firewall-rules.txt** — Final iptables policy (annotated).
- **vpn-config.md** — OpenVPN server/client notes + verification steps.
- **summary.md** — (This file) Executive overview.

---

## 🔧 Services & Controls Implemented
- **Routing & NAT:** IP forwarding enabled; MASQUERADE on edge; default routes.
- **Web:** Apache index validation over HTTP/HTTPS.
- **DNS:** `named.conf.options`, zone files, reverse PTR; verified with `dig`.
- **Email:** Postfix to Thunderbird test (server→client and client→server).
- **Proxy:** Squid ACL to control destinations (e.g., `.au`) and internal sites.
- **Firewall:** Default‑deny; allow 80/443, 53/TCP+UDP, 1194/UDP, related/established.
- **VPN:** OpenVPN server; tun interface up; client ping across VPN.

---

## ✅ Validation & Evidence
- Browser access to DMZ index page (HTTP & HTTPS).
- `dig` results confirm A and PTR records.
- Mail path proof (server log & client mailbox).
- Proxy denies/permits as intended; error pages captured.
- iptables listing shows policies and counters.
- VPN `tun0` up with successful ping to peer.

---

## 🛠️ Tooling
Ubuntu Server/Desktop VMs, Apache, BIND9, Postfix/IMAP, Squid, iptables, OpenVPN, `dig`, `wget`, `nc`.
