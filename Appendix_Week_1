Technical Appendix

The following appendix outlines the specific technical areas, controls, and validation mechanisms covered in Week 1 of the lab.

1. System Baseline & Host Inventory
  
    Artifacts: system_info.txt
    
      Capabilities demonstrated:
      
        - OS and kernel enumeration
        
        - Hardware and resource baseline collection
        
        - Network interface and routing enumeration
        
        - Listening service identification
        
        - Baseline evidence capture for auditing and drift detection
      
      Primary commands/tools:
      
        - hostnamectl, uname -a, ip a, ss -tulnp, df -h, free -h, systemctl


2. SSH Hardening & Remote Access Control

    Artifacts: ssh_hardening_notes.md, custom MOTD files
    
      Controls implemented:
      
        - Key-based authentication enforcement
        
        - Password authentication disabled
        
        - Root login disabled
        
        - Session rate limits
        
        - User allowlist
      
        - Pre-auth banner for security/legal notice
        
        - Dynamic MOTD providing session visibility, failed login counts, uptime, and security context
      
      Validation:
      
        - SSH reconnection testing
        
        - Log verification (/var/log/auth.log)
        
        - sshd_config syntax validation


3. Network Access Control & Firewall Enforcement

    Artifacts: firewall_rules.txt, firewall_notes.md
    
      Controls implemented:
      
        - Default deny inbound
        
        - Default allow outbound
        
        - SSH-specific allowlist
        
        - UFW rate limiting for brute-force mitigation
        
        - Logging enablement and log inspection
      
      Evidence:
      
        - ufw status verbose
        
        - Packet log sample validation


4. Intrusion Prevention (Fail2Ban)

    Artifacts: fail2ban_notes.md
    
      Controls implemented:
        
        - Persistent ban configuration
        
        - Hardened jail.local with extended findtime/bantime
        
        - Enhanced regex detection for SSH anomalies
        
        - Integration with UFW for automated blocking
      
      Validation:
      
        - Intentional failed SSH attempts
        
        - Ban and unban testing
        
        - fail2ban-client status sshd verification
        
        - Log correlation via journalctl and /var/log/auth.log


5. Host-Based Detection Engineering (auditd)

    Artifacts: auditd_baseline.txt, auditd_notes.md
    
      Audit rules designed for:
      
        - Monitoring changes to SSH configuration
        
        - Monitoring modifications to passwd, shadow, group, and sudoers
        
        - Logging privileged commands
        
        - Detecting execution of network reconnaissance tools
        
        - Monitoring audit rule changes (anti-tamper)
        
        - Capturing full execve process records
        
        - Logging sudo usage via custom logfile
      
      Validation:
      
        - ausearch for targeted rule events
        
        - /var/log/audit/audit.log review
        
        - auditctl -l rules loaded


6. Kernel-Level Hardening (sysctl)

    Artifacts: sysctl_notes.md
    
      Controls implemented:
      
        - Reverse-path filtering
        
        - ICMP redirect hardening
        
        - Source routing disabled
        
        - SYN cookie protection
        
        - Kernel pointer restrictions
        
        - Address Space Layout Randomization (ASLR) enforcement
        
        - Core dump disablement
        
        - IPv6 privacy enhancements
        
        - Logging of martian packets
      
      Validation:
      
        - sysctl -a queries
        
        - Reload verification via sysctl --system


7. Evidence, Documentation, and Structure

  Capabilities demonstrated:
  
   - Producing audit-ready configuration documentation
    
   - Capturing before/after states for transparency and security validation
  
   - Organizing artifacts in a hierarchical, review-friendly structure
    
   - Maintaining reproducibility through explicit commands and logs
