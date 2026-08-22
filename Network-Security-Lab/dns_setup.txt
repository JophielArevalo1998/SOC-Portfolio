# DNS Setup (BIND9)

## 1) Packages
- Ensure `bind9` and `dnsutils` installed.

## 2) `named.conf.options`
- Set forwarders (e.g., 8.8.8.8 / 8.8.4.4) as needed.
- `dnssec-validation auto;`
- `listen-on { 192.168.1.1; 10.10.1.254; };`
- `listen-on-v6 { none; };`

## 3) `named.conf.local`
- Define authoritative zones, e.g.:
  - `zone "jophiel7015ict.com" { type master; file "/etc/bind/db.jophiel7015ict.com"; };`
  - `zone "1.168.192.in-addr.arpa" { type master; file "/etc/bind/db/192.168.1"; };`

## 4) Zone Files
- `db.jophiel7015ict.com`: NS + A records (ns1, www, host IPs)
- Reverse zone for PTRs (map host IP → FQDN)

## 5) Validate
- Reload BIND and run:
    - dig @192.168.1.1 www.jophiel7015ict.com A dig @192.168.1.1 -x 192.168.1.80 PTR
- - Confirm answers and TTLs.

## 6) Security Notes
- Restrict recursion to trusted subnets.
- Keep zones and options under version control (sanitized).
