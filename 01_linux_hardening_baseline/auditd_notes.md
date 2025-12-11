# Auditd Configuration & Monitoring Notes

## Overview
Auditd is configured as the host-level audit framework for monitoring critical
security events. This includes unauthorized access attempts, file integrity
violations, privilege escalation, suspicious command execution, SSH changes,
and attempts to modify audit logging itself.

Auditd provides the forensic and detection-grade telemetry that SIEM,
EDR, SOC, cloud security, and IAM engineering roles rely on.

This system uses custom audit rules designed to mimic production-grade
controls used in enterprise environments.

---

## Modified Files
- /etc/audit/rules.d/99-security.rules
- /etc/sudoers (`Defaults logfile="/var/log/sudo.log"`)

---

## Loaded Audit Rules

SSH configuration monitoring
-w /etc/ssh/sshd_config -p wa -k ssh_config

User & authentication database monitoring
-w /etc/passwd -p wa -k user_changes
-w /etc/group -p wa -k user_changes
-w /etc/shadow -p wa -k auth_changes
-w /etc/sudoers -p wa -k sudo_config

Sudo activity logging
-w /var/log/sudo.log -p wa -k sudo_activity

Integrity monitoring of critical binaries
-w /usr/bin/sudo -p wa -k binary_modification
-w /usr/bin/passwd -p wa -k binary_modification

Suspicious command execution
-w /usr/bin/wget -p x -k network_activity
-w /usr/bin/curl -p x -k network_activity
-w /usr/bin/nc -p x -k hacking_tools
-w /usr/bin/nmap -p x -k recon

Auditd configuration changes
-w /etc/audit/auditd.conf -p wa -k audit_config
-w /etc/audit/rules.d/ -p wa -k audit_rules

Process execution tracing (execve syscall)
-a always,exit -F arch=b64 -S execve -k process_exec

---

## Rationale for Rule Categories

### **SSH Configuration (`ssh_config`)**
Detects:
- unauthorized SSH hardening changes  
- backdoor insertion  
- weakening of ciphers/MACs  
- persistence via SSH keys  

### **User Database (`user_changes`, `auth_changes`)**
Detects:
- hidden user creation  
- privilege escalation  
- modification of login shells  
- shadow file tampering  
- sudo access manipulation  

### **Sudo Activity (`sudo_activity`)**
Provides:
- forensic trail of all privileged commands  
- correlation with SIEM detections  
- visibility into insider misuse  

### **Binary Integrity (`binary_modification`)**
Monitors critical executables for:
- replacement with trojanized binaries  
- privilege escalation backdoors  
- unauthorized patches  

### **Suspicious Commands (`network_activity`, `hacking_tools`, `recon`)**
Detects attacker behavior:
- external data exfiltration  
- reconnaissance  
- pivoting  
- exploitation preparation  

### **Auditd Integrity (`audit_config`, `audit_rules`)**
Prevents attackers from:
- disabling logging  
- wiping forensic trails  
- modifying detection controls  

### **Process Execution (`process_exec`)**
Captures *every* executed command via execve.  
This provides:
- detection engineering visibility  
- incident response reconstruction  
- behavior analytics  

---

## Validation Commands


---

## Rationale for Rule Categories

### **SSH Configuration (`ssh_config`)**
Detects:
- unauthorized SSH hardening changes  
- backdoor insertion  
- weakening of ciphers/MACs  
- persistence via SSH keys  

### **User Database (`user_changes`, `auth_changes`)**
Detects:
- hidden user creation  
- privilege escalation  
- modification of login shells  
- shadow file tampering  
- sudo access manipulation  

### **Sudo Activity (`sudo_activity`)**
Provides:
- forensic trail of all privileged commands  
- correlation with SIEM detections  
- visibility into insider misuse  

### **Binary Integrity (`binary_modification`)**
Monitors critical executables for:
- replacement with trojanized binaries  
- privilege escalation backdoors  
- unauthorized patches  

### **Suspicious Commands (`network_activity`, `hacking_tools`, `recon`)**
Detects attacker behavior:
- external data exfiltration  
- reconnaissance  
- pivoting  
- exploitation preparation  

### **Auditd Integrity (`audit_config`, `audit_rules`)**
Prevents attackers from:
- disabling logging  
- wiping forensic trails  
- modifying detection controls  

### **Process Execution (`process_exec`)**
Captures *every* executed command via execve.  
This provides:
- detection engineering visibility  
- incident response reconstruction  
- behavior analytics  

---

## Validation Commands


---

## Rationale for Rule Categories

### **SSH Configuration (`ssh_config`)**
Detects:
- unauthorized SSH hardening changes  
- backdoor insertion  
- weakening of ciphers/MACs  
- persistence via SSH keys  

### **User Database (`user_changes`, `auth_changes`)**
Detects:
- hidden user creation  
- privilege escalation  
- modification of login shells  
- shadow file tampering  
- sudo access manipulation  

### **Sudo Activity (`sudo_activity`)**
Provides:
- forensic trail of all privileged commands  
- correlation with SIEM detections  
- visibility into insider misuse  

### **Binary Integrity (`binary_modification`)**
Monitors critical executables for:
- replacement with trojanized binaries  
- privilege escalation backdoors  
- unauthorized patches  

### **Suspicious Commands (`network_activity`, `hacking_tools`, `recon`)**
Detects attacker behavior:
- external data exfiltration  
- reconnaissance  
- pivoting  
- exploitation preparation  

### **Auditd Integrity (`audit_config`, `audit_rules`)**
Prevents attackers from:
- disabling logging  
- wiping forensic trails  
- modifying detection controls  

### **Process Execution (`process_exec`)**
Captures *every* executed command via execve.  
This provides:
- detection engineering visibility  
- incident response reconstruction  
- behavior analytics  

---

## Validation Commands

sudo auditctl -l
sudo ausearch -k ssh_config
sudo ausearch -k user_changes
sudo ausearch -k sudo_activity
sudo ausearch -k binary_modification
sudo ausearch -k network_activity
sudo ausearch -k audit_rules
sudo ausearch -k process_exec | tail -n 20



---

#  **Triggered Events (Evidence)**


### **1. SSH Configuration Change (ssh_config)**
Command used: sudo ausearch -k ssh_config

Auditd results:
----
time->Tue Dec  2 16:39:05 2025
type=PROCTITLE msg=audit(1764693545.138:591): proctitle=6E616E6F002F6574632F7373682F737368645F636F6E666967
type=PATH msg=audit(1764693545.138:591): item=1 name="/etc/ssh/sshd_config" inode=413811 dev=08:02 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=PATH msg=audit(1764693545.138:591): item=0 name="/etc/ssh/" inode=393307 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=CWD msg=audit(1764693545.138:591): cwd="/home/Keenan"
type=SYSCALL msg=audit(1764693545.138:591): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=5ec746881630 a2=241 a3=1b6 items=2 ppid=1502 pid=1503 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=3 comm="nano" exe="/usr/bin/nano" subj=unconfined key="ssh_config"

---

### **2. User Add/Delete (user_changes)**
Commands used: sudo useradd testuser AND sudo userdel testuser

---

Auditd results:
---
Keenan@UbuntuLab:~$ sudo ausearch -k user_changes | grep useradd
type=SYSCALL msg=audit(1764693604.055:624): arch=c000003e syscall=257 success=yes exit=5 a0=ffffff9c a1=61fda98db040 a2=20902 a3=0 items=1 ppid=1517 pid=1518 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=3 comm="useradd" exe="/usr/sbin/useradd" subj=unconfined key="user_changes"
type=SYSCALL msg=audit(1764693604.063:625): arch=c000003e syscall=257 success=yes exit=6 a0=ffffff9c a1=61fda98db4a0 a2=20902 a3=0 items=1 ppid=1517 pid=1518 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=3 comm="useradd" exe="/usr/sbin/useradd" subj=unconfined key="user_changes"
type=SYSCALL msg=audit(1764693604.088:629): arch=c000003e syscall=82 success=yes exit=0 a0=7fffb3b7e790 a1=61fda98db040 a2=7fffb3b7e700 a3=100 items=5 ppid=1517 pid=1518 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=3 comm="useradd" exe="/usr/sbin/useradd" subj=unconfined key="user_changes"
type=SYSCALL msg=audit(1764693604.106:631): arch=c000003e syscall=82 success=yes exit=0 a0=7fffb3b7e770 a1=61fda98db4a0 a2=7fffb3b7e6e0 a3=100 items=5 ppid=1517 pid=1518 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=3 comm="useradd" exe="/usr/sbin/useradd" subj=unconfined key="user_changes"
Keenan@UbuntuLab:~$ sudo ausearch -k user_changes | grep userdel
type=SYSCALL msg=audit(1764693613.800:647): arch=c000003e syscall=257 success=yes exit=5 a0=ffffff9c a1=600673a328c0 a2=20902 a3=0 items=1 ppid=1526 pid=1527 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=3 comm="userdel" exe="/usr/sbin/userdel" subj=unconfined key="user_changes"
type=SYSCALL msg=audit(1764693613.812:649): arch=c000003e syscall=257 success=yes exit=7 a0=ffffff9c a1=600673a32d20 a2=20902 a3=0 items=1 ppid=1526 pid=1527 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=3 comm="userdel" exe="/usr/sbin/userdel" subj=unconfined key="user_changes"
type=SYSCALL msg=audit(1764693613.828:654): arch=c000003e syscall=82 success=yes exit=0 a0=7ffc1fc99130 a1=600673a328c0 a2=7ffc1fc990a0 a3=100 items=5 ppid=1526 pid=1527 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=3 comm="userdel" exe="/usr/sbin/userdel" subj=unconfined key="user_changes"
type=SYSCALL msg=audit(1764693613.835:656): arch=c000003e syscall=82 success=yes exit=0 a0=7ffc1fc99130 a1=600673a32d20 a2=7ffc1fc990a0 a3=100 items=5 ppid=1526 pid=1527 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=3 comm="userdel" exe="/usr/sbin/userdel" subj=unconfined key="user_changes"
Keenan@UbuntuLab:~$ 

---

### **3. Sudo Activity (sudo_activity)**
Command used: sudo ls/root

Auditd results:
----
time->Tue Dec  2 16:52:03 2025
type=PROCTITLE msg=audit(1764694323.212:790): proctitle=7375646F006175736561726368002D6B007375646F5F6163746976697479
type=PATH msg=audit(1764694323.212:790): item=1 name="/var/log/sudo.log" inode=526464 dev=08:02 mode=0100600 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=PATH msg=audit(1764694323.212:790): item=0 name="/var/log/" inode=524312 dev=08:02 mode=040775 ouid=0 ogid=104 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=CWD msg=audit(1764694323.212:790): cwd="/home/Keenan"
type=SYSCALL msg=audit(1764694323.212:790): arch=c000003e syscall=257 success=yes exit=7 a0=ffffff9c a1=651617772e00 a2=441 a3=180 items=2 ppid=1239 pid=1598 auid=1000 uid=0 gid=1000 euid=0 suid=0 fsuid=0 egid=0 sgid=1000 fsgid=0 tty=pts0 ses=3 comm="sudo" exe="/usr/bin/sudo" subj=unconfined key="sudo_activity"

---

### **4. Suspicious Command Execution (network_activity)**
Commands used: sudo ausearch -k network_activity

Tes:
curl https://example.com
wget http://example.com

Auditd results:
----
time->Tue Dec  2 16:41:13 2025
type=PROCTITLE msg=audit(1764693673.350:695): proctitle=6375726C0068747470733A2F2F6578616D706C652E636F6D
type=PATH msg=audit(1764693673.350:695): item=1 name="/lib64/ld-linux-x86-64.so.2" inode=434614 dev=08:02 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=PATH msg=audit(1764693673.350:695): item=0 name="/usr/bin/curl" inode=395351 dev=08:02 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=CWD msg=audit(1764693673.350:695): cwd="/home/Keenan"
type=EXECVE msg=audit(1764693673.350:695): argc=2 a0="curl" a1="https://example.com"
type=SYSCALL msg=audit(1764693673.350:695): arch=c000003e syscall=59 success=yes exit=0 a0=5aa29ac28570 a1=5aa29ab9beb0 a2=5aa29ac246f0 a3=5aa29ab2f6b0 items=2 ppid=1239 pid=1547 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=3 comm="curl" exe="/usr/bin/curl" subj=unconfined key="network_activity"

---

### **5. Binary Integrity Violation (binary_modification)**
Simulated with: sudo touch /usr/bin/passwd


Auditd results:
----
time->Tue Dec  2 16:41:43 2025
type=PROCTITLE msg=audit(1764693703.049:712): proctitle=746F756368002F7573722F62696E2F706173737764
type=PATH msg=audit(1764693703.049:712): item=1 name="/usr/bin/passwd" inode=395636 dev=08:02 mode=0104755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=PATH msg=audit(1764693703.049:712): item=0 name="/usr/bin/" inode=394395 dev=08:02 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=CWD msg=audit(1764693703.049:712): cwd="/home/Keenan"
type=SYSCALL msg=audit(1764693703.049:712): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7ffc6d8447b0 a2=941 a3=1b6 items=2 ppid=1553 pid=1554 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=3 comm="touch" exe="/usr/bin/touch" subj=unconfined key="binary_modification"

---

### **6. Auditd Config Modification (audit_rules)**
Command used: sudo nano /etc/audit/rules.d/99-security.rules

Auditd results:
----
time->Tue Dec  2 16:36:44 2025
type=PROCTITLE msg=audit(1764693404.430:567): proctitle=2F7362696E2F617564697463746C002D52002F6574632F61756469742F61756469742E72756C6573
type=PATH msg=audit(1764693404.430:567): item=0 name="/etc/audit/rules.d" inode=657923 dev=08:02 mode=040750 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=CWD msg=audit(1764693404.430:567): cwd="/"
type=SOCKADDR msg=audit(1764693404.430:567): saddr=100000000000000000000000
type=SYSCALL msg=audit(1764693404.430:567): arch=c000003e syscall=44 success=yes exit=1088 a0=3 a1=7ffdded8f950 a2=440 a3=0 items=1 ppid=1474 pid=1485 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm="auditctl" exe="/usr/sbin/auditctl" subj=unconfined key=(null)
type=CONFIG_CHANGE msg=audit(1764693404.430:567): auid=4294967295 ses=4294967295 subj=unconfined op=add_rule key="audit_rules" list=4 res=1
Keenan@UbuntuLab:~$ 

sudo ausearch -k process_exec | tail -n 20
type=PATH msg=audit(1764695537.451:861): item=0 name="/usr/bin/sudo" inode=395878 dev=08:02 mode=0104755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=CWD msg=audit(1764695537.451:861): cwd="/home/Keenan"
type=EXECVE msg=audit(1764695537.451:861): argc=4 a0="sudo" a1="ausearch" a2="-k" a3="process_exec"
type=SYSCALL msg=audit(1764695537.451:861): arch=c000003e syscall=59 success=yes exit=0 a0=5aa29ac2fb80 a1=5aa29ac63660 a2=5aa29ac246f0 a3=5aa29abf5290 items=2 ppid=1239 pid=1640 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=3 comm="sudo" exe="/usr/bin/sudo" subj=unconfined key="process_exec"
----
time->Tue Dec  2 17:12:17 2025
type=PROCTITLE msg=audit(1764695537.451:862): proctitle=7461696C002D6E003230
type=PATH msg=audit(1764695537.451:862): item=1 name="/lib64/ld-linux-x86-64.so.2" inode=434614 dev=08:02 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=PATH msg=audit(1764695537.451:862): item=0 name="/usr/bin/tail" inode=395913 dev=08:02 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=CWD msg=audit(1764695537.451:862): cwd="/home/Keenan"
type=EXECVE msg=audit(1764695537.451:862): argc=3 a0="tail" a1="-n" a2="20"
type=SYSCALL msg=audit(1764695537.451:862): arch=c000003e syscall=59 success=yes exit=0 a0=5aa29ab4bc90 a1=5aa29ab3ae80 a2=5aa29ac246f0 a3=8 items=2 ppid=1239 pid=1641 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=3 comm="tail" exe="/usr/bin/tail" subj=unconfined key="process_exec"
----
time->Tue Dec  2 17:12:17 2025
type=PROCTITLE msg=audit(1764695537.461:868): proctitle=6175736561726368002D6B0070726F636573735F65786563
type=PATH msg=audit(1764695537.461:868): item=1 name="/lib64/ld-linux-x86-64.so.2" inode=434614 dev=08:02 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=PATH msg=audit(1764695537.461:868): item=0 name="/usr/sbin/ausearch" inode=441593 dev=08:02 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=CWD msg=audit(1764695537.461:868): cwd="/home/Keenan"
type=EXECVE msg=audit(1764695537.461:868): argc=3 a0="ausearch" a1="-k" a2="process_exec"
type=SYSCALL msg=audit(1764695537.461:868): arch=c000003e syscall=59 success=yes exit=0 a0=5f6814a4ac58 a1=5f6814a3f7b0 a2=5f6814a4f510 a3=64 items=2 ppid=1642 pid=1643 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=3 comm="ausearch" exe="/usr/sbin/ausearch" subj=unconfined key="process_exec"

---

## Conclusion

Auditd is fully configured with a production-grade rule set monitoring:

- SSH integrity  
- User and auth database integrity  
- Sudo activity  
- Process execution  
- File integrity of key binaries  
- Suspicious command activity  
- Audit system tampering  

This configuration mirrors real-world enterprise security requirements and forms
the foundation of endpoint detection, host security monitoring, and audit
compliance workflows used in SOC, security engineering, IAM, IR, and cloud
security roles.








