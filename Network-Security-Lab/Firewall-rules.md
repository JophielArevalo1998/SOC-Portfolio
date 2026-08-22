# iptables Baseline – External Gateway (sanitized)
# Default policies
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]

# Allow loopback and established
-A INPUT  -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT
-A INPUT  -m state --state RELATED,ESTABLISHED -j ACCEPT
-A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

# DNS (TCP/UDP 53) as needed
-A FORWARD -p udp --dport 53  -j ACCEPT
-A FORWARD -p tcp --dport 53  -j ACCEPT

# Web (HTTP/HTTPS) for DMZ
-A FORWARD -p tcp --dport 80  -j ACCEPT
-A FORWARD -p tcp --dport 443 -j ACCEPT

# OpenVPN (UDP 1194)
-A FORWARD -p udp --dport 1194 -j ACCEPT
-A FORWARD -p udp --sport 1194 -j ACCEPT

COMMIT

*nat
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]

# NAT outbound via uplink (replace eth0 if needed)
-A POSTROUTING -o eth0 -j MASQUERADE

COMMIT
