# Gateway Configs

This folder contains **sanitized** configuration snippets for:
- `external-gateway` (uplink + DMZ)
- `internal-gateway` (internal + DMZ)

## Included
- **netplan/** — Static addressing, routes, DNS.
- **sysctl/** — IP forwarding (IPv4), anti‑spoofing options.
- **iptables/** — NAT (MASQUERADE), default‑deny forwarding, explicit service allows.

> ⚠️ Secrets, real public IPs, and keys must be **redacted**.  
> Use placeholders like `X.X.X.X` or `your.public.ip`.
