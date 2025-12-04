Week 1 – Host Baseline, Hardening, and Detection Controls

Objective

  Establish a defensible Linux host baseline and implement foundational security controls
  covering authentication, password policy, filesystem protections, network access,
  intrusion prevention, kernel behavior, and host-level detection. All configurations
  were applied on a live Ubuntu system and validated through command output, log review,
  functional testing, and a pre/post Lynis audit. This week establishes a hardened
  foundation for Week 2 vulnerability management and subsequent engineering work.

Scope of Work

  Week 1 delivered the following technical areas:

    System Baseline Enumeration
      - Identification of OS details, kernel version, services, network configuration,
        users, and basic security posture indicators.

    SSH Hardening
      - Enforced key-based authentication, controlled login pathways, banners, and
        session controls using a hardened sshd_config.

    Network Boundary Enforcement (UFW)
      - Default-deny inbound policy, controlled exposure of SSH, and rate-limited
        ingress to reduce brute-force noise.

    Intrusion Prevention (Fail2Ban)
      - Hardened jail profile with aggressive lockout thresholds, persistent bans,
        and validated blocking behavior against repeated SSH failures.

    Host-Based Detection (auditd)
      - Monitoring of privileged operations, authentication files, SSH configuration,
        binary execution, and system modifications using tuned audit rules.

    Kernel Hardening (sysctl)
      - Memory-protection settings, ICMP/redirect controls, packet-sanitization, and
        core-dump restrictions applied via /etc/sysctl.d/99-security.conf.

    PAM Hardening (faillock)
      - Account lockout controls enforced via pam_faillock in common-auth/account and
        /etc/security/faillock.conf to block repeated authentication failures.

    Password Quality Policy (pwquality)
      - Strong password complexity policy (length, character classes, repetition and
        dictionary checks) enforced via /etc/security/pwquality.conf.

    Password Hashing Upgrade (yescrypt)
      - PAM configuration updated to use yescrypt for password hashing, replacing
        SHA512 with a modern memory-hard algorithm.

    Filesystem Hardening (/tmp and /var/tmp)
      - /tmp and /var/tmp mounted as tmpfs with noexec, nosuid, and nodev to prevent
        execution and persistence in temporary directories.

    Post-Hardening Lynis Audit
      - Lynis re-run after all changes; baseline vs hardened state captured in a
        differential report (delta) to show measurable improvement.

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
    - pam_hardening_notes.md   
    - pwquality_hardening_notes.md
    - fstab_hardening_notes.md

  Configuration and Rule Files
   
    - firewall_rules.txt
    - Appendix_Week_1.md

  Validation / Evidence Outputs
    
    - tmp_hardening_validation.txt
    - pwscore_output.txt    
    - pam_unix_yescrypt_grep.txt   
    - lynis_after.txt  
    - lynis_delta.txt

  Validation Screenshots (under 01_host_hardening/evidence/)
   
    - SSH.png   
    - SSHD_Config.png    
    - SSH_Login_Banners.png    
    - fail2ban_lockout.png    
    - Lynis_Report.png

Control Implementation Summary

  1. System Baseline

     Baseline posture captured using standard utilities and Lynis.

       Commands executed:

         - uname -a
         - lsb_release -a
         - ip a          
         - ip route          
         - ss -tulnp            
         - systemctl list-units --type=service           
         - df -h        
         - top -b -n1

       Initial security audit:

          - sudo lynis audit system > lynis_baseline.txt

       Evidence:

         - system_info.txt
          - lynis_baseline.txt
         - screenshot in /evidence

  3. SSH Hardening

     Key modifications in /etc/ssh/sshd_config:

         - PasswordAuthentication disabled (after key-based access confirmed) 
         - PermitRootLogin disabled     
         - MaxAuthTries lowered     
         - Protocol 2 enforced     
         - AllowUsers restricting which accounts may SSH     
         - Banner configured (legal / security notice)    
         - MOTD-style security messaging via /etc/update-motd.d/

     Validation:

         - sshd -T    
         - journalctl -u ssh    
         - ssh -v user@UbuntuLab

     Documentation:

         - ssh_hardening_notes.md

     Evidence:
     
         - SSH.png
         - SSHD_Config.png
         - SSH_Login_Banners.png

  5. Network Boundary Controls (UFW)

     Firewall hardened to reduce exposed attack surface:
  
         - Default deny inbound     
         - Default allow outbound     
         - Rate-limit SSH using ufw limit    
         - Unneeded services removed/blocked

       Commands executed:
     
         - sudo ufw default deny incoming    
         - sudo ufw default allow outgoing     
         - sudo ufw limit ssh    
         - sudo ufw status verbose

     Documentation:
       
         - firewall_rules_notes.md

     Evidence:
       
         - firewall_rules.txt

  7. Intrusion Prevention (Fail2Ban)

     Fail2Ban jail configuration (jail.local):

         - Backend set to systemd    

         - SSH jail tuned with:
             - Lower maxretry     
             - Increased bantime    
             - Persistent bans
     
         - Validated that repeated failed logins from a test source are banned

     Validation:

         - sudo fail2ban-client status    
         - sudo fail2ban-client status sshd

     Documentation:
     
         - fail2ban_notes.md

     Evidence:
     
         - fail2ban_lockout.png

  9. Host-Based Detection (auditd)

     Detection coverage via /etc/audit/rules.d/99-security.rules:

         - Watches on:    
           - /etc/passwd, /etc/shadow, /etc/group, /etc/sudoers
           - SSH configuration files
           - Sudo activity and privileged binaries
           - execve events for process monitoring

     Validation:

         - sudo auditctl -l    
         - sudo ausearch -k <rule-key>     
         - sudo aureport --summary

     Documentation:
      
         - auditd_notes.md

     Evidence:
       
         - auditd_baseline.txt

  11. Kernel Hardening (sysctl)

     Security-related sysctl parameters in /etc/sysctl.d/99-security.conf:

       - randomize_va_space=2 (ASLR)       
       - rp_filter on interfaces       
       - ICMP rate limiting       
       - Redirects disabled       
       - Source routing disabled       
       - kptr_restrict for pointer protection       
       - fs.suid_dumpable=0 to prevent SUID core dumps

     Validation:

       - sudo sysctl -a | grep -E 'rp_filter|icmp|redirect|randomize|kptr|dump'

     Documentation:
     
       - sysctl_notes.md

  11. PAM Hardening (Account Lockout Policy)

     Account lockout implemented using pam_faillock:

       /etc/pam.d/common-auth:
       
         - auth required pam_faillock.so preauth silent deny=3 unlock_time=600 fail_interval=900        
         - auth [success=1 default=ignore] pam_unix.so nullok_secure         
         - auth [default=die] pam_faillock.so authfail deny=3 unlock_time=600 fail_interval=900
       /etc/pam.d/common-account:
        
         - account required pam_faillock.so

       /etc/security/faillock.conf:
        
         - deny = 3
         - unlock_time = 600         
         - fail_interval = 900

     Validation:

       - faillock --user <username> (fail_cnt increments and resets)       
       - journalctl -u ssh (failed auth + lockout entries)

     Documentation:
      
       - pam_hardening_notes.md

  11. Password Quality Policy (pwquality)

     Strong password policy enforced via /etc/security/pwquality.conf:

       - minlen = 14       
       - dcredit = -1 (digit required)       
       - ucredit = -1 (uppercase required)       
       - lcredit = -1 (lowercase required)       
       - ocredit = -1 (special character required)       
       - maxrepeat = 2 (limit identical character repetition)       
       - # maxclassrepeat = 2 (disabled after testing)       
       - dictcheck = 1 (dictionary checks enabled)       
       - enforce_for_root (policy applies to root as well)

     Notes:

       - maxclassrepeat was initially enabled and caused overly strict rejections.
         It is now commented out and documented as an intentional usability tradeoff.

     Validation:

       - printf 'AStrongP@ssw0rd!2025\n' | pwscore  (score: 86)
       - sudo passwd testuser  (strong password accepted)

     Documentation:
       - pwquality_hardening_notes.md
       - pwscore_output.txt

  11. Password Hashing (yescrypt)

     PAM updated to use yescrypt instead of SHA512:

       /etc/pam.d/common-password:
         - password [success=1 default=ignore] pam_unix.so obscure yescrypt

       /etc/shadow:
         - testuser:$y$...  (yescrypt hash prefix)

    Result:

       - Passwords are now hashed using a modern, memory-hard algorithm that is more
         resistant to GPU/ASIC cracking than legacy SHA512.

     Evidence:
       - pam_unix_yescrypt_grep.txt

 11. Filesystem Hardening – /tmp and /var/tmp

     /etc/fstab entries:

         - tmpfs   /tmp       tmpfs   defaults,noexec,nosuid,nodev,mode=1777   0  0
         - tmpfs   /var/tmp   tmpfs   defaults,noexec,nosuid,nodev,mode=1777   0  0

     Security impact:

         - noexec: binaries cannot run from /tmp or /var/tmp
         - nosuid: SUID/SGID bits in these directories cannot be abused
         - nodev: device files cannot be created/used here
         - tmpfs: contents are non-persistent and cleared on reboot

     Validation:

         - mount | grep -E '/tmp|/var/tmp'
           - tmpfs on /tmp ...
           - tmpfs on /var/tmp ...

     Documentation:
     
         - fstab_hardening_notes.md
         - tmp_hardening_validation.txt

 13. Lynis Post-Hardening Scan and Delta

     Final Lynis audit after all Week 1 controls:

         - sudo lynis audit system > lynis_after.txt
         - diff -u lynis_baseline.txt lynis_after.txt > lynis_delta.txt

     Outcome:

         - Reduced number of warnings and suggestions
         - Resolved SSH, filesystem, and password-related findings
         - Improved kernel, auth, and logging posture
         - Remaining findings tracked for future weeks (e.g., additional services, logging stack)

     Documentation:
     
         - lynis_after.txt
         - lynis_delta.txt
         - lynis_delta.md (summary of key changes)

Validation Summary

  All controls were validated through:

    - Review of live system logs (journalctl, /var/log/auth.log)
    - Inspection of applied configs (sshd -T, auditctl -l, sysctl -a)
    - Functional tests (SSH access, Fail2Ban bans, PAM lockouts, pwquality behavior)
    - Reboot persistence checks for firewall, sysctl, PAM, and filesystem changes
    - Lynis baseline vs post-hardening comparison

Result

  Week 1 produced a hardened Linux host with controlled authentication pathways, strong
  password policy, modern hashing (yescrypt), locked-down temporary storage, reduced
  network attack surface, active brute-force prevention, kernel-level protections, and
  comprehensive host-level detection. This platform is now ready for Week 2:
  vulnerability scanning, remediation, and validation.
