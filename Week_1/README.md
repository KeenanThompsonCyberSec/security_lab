Week 1 – Host Baseline, Hardening, and Detection Controls

Objective

  Establish a defensible Linux host baseline and implement foundational security controls covering authentication, network access, intrusion prevention, kernel behavior, and host-level detection. All configurations were applied on a live Ubuntu system and validated through command output, log review, and functional testing. This week establishes a hardened foundation suitable for subsequent logging, automation, monitoring, and cloud-security work.

Scope of Work

  Week 1 delivered the following technical areas:
   
    System Baseline Enumeration
      - Identification of OS details, kernel version, services, network configuration, users, and security posture indicators.
    
    SSH Hardening
      - Enforced key-based authentication, access pathways, banners, and session controls using a hardened sshd_config.
    
    Network Boundary Enforcement (UFW)
      - Default-deny inbound policy, controlled exposure, and rate-limited SSH ingress.
    
    Intrusion Prevention (Fail2Ban)
      - Hardened jail profile with aggressive lockout thresholds, persistent bans, and validated block behavior.
    
    Host-Based Detection (auditd)
      - Monitoring of privileged operations, authentication files, SSH configuration, binary execution, and system modifications.
   
    Kernel Hardening (sysctl)
      - Memory-protection settings, ICMP/redirect controls, packet-sanitization, and core-dump restrictions.
 
  Artifact Inventory
  
    Baseline Evidence
      - system_info.txt
      - lynis_baseline.txt
      - auditd_baseline.txt
    
    Hardening Notes
      - ssh_hardening_notes.md
      - firewall_rules_notes.md
      - fail2ban_notes.md
      - auditd_notes.md
      - sysctl_notes.md
    
    Configuration and Rule Files
      - firewall_rules.txt
      - Appendix_Week_1.md
   
    Validation Screenshots
    Located under Week_1/evidence/:
      - SSH.png
      - SSHD_Config.png
      - SSH_Login_Banners.png
      - fail2ban_lockout.png
      - Lynis_Report.png
  
  Control Implementation Summary
 
    1. System Baseline
    Baseline posture captured using system utilities.
        
        Commands executed:
          uname -a
          lsb_release -a
          ip a
          ip route
          netstat -tulnp || ss -tulnp
          systemctl list-units --type=service
          df -h
          top -b -n1
        
        Lynis security audit executed using:
          sudo lynis audit system
    
    Evidence:
      system_info.txt, lynis_baseline.txt, screenshot in /evidence.
    
    2. SSH Hardening
       
       Key modifications applied in /etc/ssh/sshd_config:
        - PasswordAuthentication disabled (after validation)
        - PermitRootLogin disabled
        - MaxAuthTries lowered
        - Protocol 2 enforced
        - AllowUsers applied for explicit user restrictions
        - Banner configured (/etc/issue.net)
        - Dynamic MOTD script created under /etc/update-motd.d/
      
       Validation commands:
          sshd -T
          journalctl -u ssh
          ssh -v user@host
     
       Documentation:
        ssh_hardening_notes.md
     
       Evidence:
        SSH.png, SSHD_Config.png, SSH_Login_Banners.png
    
    3. Network Boundary Controls (UFW)
       
       Firewall hardened using:
        - Default deny inbound
        - Default allow outbound
        - SSH ingress limited with ufw limit ssh
        - Redundant services purged
        - Commands executed:
        - sudo ufw default deny incoming
        - sudo ufw default allow outgoing
        - sudo ufw limit ssh
        - sudo ufw status verbose
     
       Evidence:
        firewall_rules.txt, firewall_rules_notes.md
   
    4. Intrusion Prevention (Fail2Ban)
       
       Hardened configuration under /etc/fail2ban/jail.local:
        - Systemd backend
        - Extended SSH filter
        - Increased bantime
        - Reduced maxretry
        - Persistent bans enabled
        
       Validation:
          sudo fail2ban-client status
          sudo fail2ban-client status sshd
        
       Documentation:
        fail2ban_notes.md
        
       Evidence:
        fail2ban_lockout.png
    
    5. Host-Based Detection (auditd)
   
      Rules placed under /etc/audit/rules.d/99-security.rules to monitor:
        - /etc/passwd, /etc/shadow, /etc/group, /etc/sudoers
        - Sudo logs and privileged executions
        - SSH configuration integrity
        - Critical binaries (/usr/bin/passwd, /usr/bin/sudo, etc.)
        - Global execve syscall monitoring
      
      Validation commands:
          sudo auditctl -l
          sudo ausearch -k <rule-key>
          sudo aureport --summary
     
      Documentation:
        auditd_notes.md
      
      Evidence:
        auditd_baseline.txt
   
    6. Kernel Hardening (sysctl)
   
      Security settings applied under /etc/sysctl.d/99-security.conf:
        - ASLR enforcement (randomize_va_space=2)
        - Reverse-path filtering (rp_filter=1)
        - ICMP restrictions
        - Redirects disabled
        - Source routing disabled
        - Kernel pointer protection (kptr_restrict=2)
        - Core dumps disabled (fs.suid_dumpable=0)
     
      Validation commands:
        sudo sysctl -a | grep -E 'rp_filter|icmp|redirect|randomize|kptr|dump'
      
      Documentation:
        sysctl_notes.md
  
  Validation Summary
 
  All controls were verified by:
 
  Reviewing live system logs (journalctl, /var/log/auth.log)
  Inspecting applied configurations and rule sets (sshd -T, auditctl -l)
  Functional testing (SSH login attempts, Fail2Ban lockout, auditd rule triggers)
  Reboot persistence checks
  Lynis differential comparison

Each major control family includes a corresponding evidence file or screenshot in Week_1/.

Result
  
  Week 1 produced a hardened Linux host with controlled authentication pathways, reduced ingress surface area, active brute-force prevention, kernel-level protections, and comprehensive host-level detection. This forms a stable, validated platform for Week 2 logging architecture and subsequent engineering phases.
