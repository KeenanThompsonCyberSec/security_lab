# SSH Hardening Notes 

## Modified Files
- /etc/ssh/sshd_config
- /etc/issue.net (SSH banner)
- /etc/update-motd.d/99-custom (dynamic MOTD script)

## SSHd Configuration Changes
- Protocol 2 (default in modern OpenSSH)
- PubkeyAuthentication yes
- PasswordAuthentication no   (enabled only after confirming key-based login)
- PermitRootLogin no
- MaxAuthTries 3
- LoginGraceTime 5m
- AllowUsers Keenan
- Banner /etc/issue.net

## Banner (/etc/issue.net)
```
##############################################

#    🔵  CYBERSECURITY PRACTICE LAB  🔵     #

#    Unauthorized access is boring. Don’t.   #

#      All actions are logged & audited.     #

##############################################
```
## Dynamic MOTD Script (/etc/update-motd.d/99-custom)
```
#!/bin/bash

echo "-------------------------------------------"
echo "   Keenan’s Security Lab — $(hostname)"
echo "   Uptime: $(uptime -p)"
echo "   Active SSH Sessions: $(who | wc -l)"
echo "   Failed Logins Today:"
grep "Failed password" /var/log/auth.log | wc -l
echo "-------------------------------------------"

cat << 'EOF'
┌──────────────────────────────────────────-─┐

│   Keenan’s Cyber Defense Playground 🛡️     │

│   SSH events logged via auditd + journald. │

│   Unauthorized actions are automatically   │

│   flagged as “skill issue.”                │

└──────────────────────────────────────────-─┘

EOF
```
## Commands Executed
```
sudo nano /etc/ssh/sshd_config
sudo systemctl restart ssh.service
sudo systemctl status ssh.service
sudo nano /etc/issue.net
sudo nano /etc/update-motd
```
