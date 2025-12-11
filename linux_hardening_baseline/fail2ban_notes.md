# Fail2ban Hardening Notes — SSH Protection

## Overview
Fail2ban is configured to protect SSH from brute-force attempts. The default Fail2ban configuration was replaced with a hardened jail.local to reduce retries, extend ban times, and integrate bans with UFW.

## Modified File
/etc/fail2ban/jail.local

## Configuration
[DEFAULT]
bantime = 12h
findtime = 10m
maxretry = 3
backend = systemd
banaction = ufw
banaction_allports = ufw

[sshd]
enabled = true
port    = ssh
logpath = /var/log/auth.log
maxretry = 3
bantime = 12h
findtime = 10m

## Rationale
- Reduced maxretry to 3 to limit brute-force attempts.
- bantime extended to 12 hours to slow persistent attackers.
- backend set to systemd for proper log parsing on Ubuntu 24.04.
- banaction set to UFW so bans integrate with host firewall.
- SSH jail explicitly enabled and monitored.

## Persistent Ban Configuration
Fail2ban no longer uses a separate `fail2ban-persistent` package. 
Persistent bans are enabled via local configuration:

/etc/fail2ban/fail2ban.local
[Definition]
persistentbans = true

jail.local:
dbpurgeage = 1d

Validated by triggering a ban, rebooting, and confirming the IP remained banned.

## Validation Commands
sudo fail2ban-client status
sudo fail2ban-client status sshd
sudo tail -n 50 /var/log/fail2ban.log

## Current Status (Initial)
- No failed SSH attempts yet
- No banned IPs yet
- Jail is active and monitoring

## Next Steps
- Trigger intentional failed logins to generate ban events
- Capture logs before/after ban
- Add ban/unban commands to notes:
  - sudo fail2ban-client set sshd banip <IP>
  - sudo fail2ban-client set sshd unbanip <IP>
- Add Fail2ban log excerpts to the portfolio
