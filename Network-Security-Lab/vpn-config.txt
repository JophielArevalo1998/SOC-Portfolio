# OpenVPN Notes (Server + Client Verification)

## Server Side
- OpenVPN server listening on `udp/1194`.
- `tun0` interface created on gateway.
- IP forwarding enabled in `/etc/sysctl.conf`:
    - net.ipv4.ip_forward=1
- NAT on upstream gateway to allow Internet egress.

## Client Side
- Client receives `tun` IP (e.g., 10.8.0.6); verify with:

ip a | grep tun0


- Test reachability:

ping 10.8.0.1

## Troubleshooting
- Check `iptables` for `RELATED,ESTABLISHED`.
- Validate server and client time (certs).
- Confirm routing (`ip route`) and DNS resolution.
