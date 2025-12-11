# UFW Firewall Hardening Notes

## Overview
UFW (Uncomplicated Firewall) is being used to enforce a host-based firewall with a default-deny stance.  
Only SSH (22/tcp) is permitted for remote administration. All other inbound traffic is blocked.

## Configuration Steps Executed
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw enable
sudo ufw status verbose

## Current Firewall Status (Cleaned Summary)
- Status: active
- Logging: on (low)
- Default Policies:
  - Incoming: deny
  - Outgoing: allow
  - Routed: disabled

## Allowed Inbound Traffic
- 22/tcp (SSH) — for remote management  
  - Allowed from all sources (sandbox environment)

## Observed Duplicate Entries
The raw output showed duplicate entries for IPv4 and IPv6:
- "22/tcp" and "22/tcp (OpenSSH)"
- "22/tcp (v6)" and "22/tcp (OpenSSH (v6))"

These come from:
1. UFW auto-detecting the OpenSSH profile
2. Manual allowance using "ufw allow 22/tcp"

The duplicates pose no functional issue but will be removed for clarity.

## Cleanup Commands (Planned)
sudo ufw delete allow "OpenSSH"
sudo ufw allow 22/tcp comment "SSH access"

This will leave a single IPv4/IPv6 rule for SSH.

## Validation Commands
```
sudo ufw status verbose
sudo ss -tulnp | grep ssh
sudo tail -n 30 /var/log/ufw.log
```
## Notes / Rationale
- SSH is the only required ingress for management of the lab VM.
- All other ports remain blocked to reduce attack surface.
- IPv6 is permitted because the VM is running dual-stack networking.
- Logging is enabled to support log auditing, failed-login tracking, and future fail2ban integration.

## Next Steps
- Add fail2ban protection for SSH brute force attempts
- Add firewall rate-limiting:
  sudo ufw limit ssh
- Evaluate whether IPv6 should be disabled if not needed
