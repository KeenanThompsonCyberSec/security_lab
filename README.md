Project Summary

This repository contains a structured collection of security engineering artifacts demonstrating practical capability in Linux system hardening, host-based detection engineering, secure configuration enforcement, and defensive control implementation. The material reflects hands-on work expected of engineers responsible for maintaining secure production hosts, validating system posture, and supporting incident response and audit activities.

The environment was configured and hardened using industry-standard controls covering authentication, access control, network boundary protection, intrusion prevention, kernel-level hardening, and audit instrumentation. All configurations were applied on a live Ubuntu system and validated through command outputs, log review, audit records, and functional testing. The repository includes both the applied configurations and the evidence produced during validation, aligned with expectations for verifiable security engineering work.


Technical Scope
  
  The project delivers a cohesive, end-to-end host security baseline through:
  
    - Baseline Establishment
      Creation of a measurable system baseline supporting configuration governance, drift detection, and forensic comparison.
    
    - Remote Access Hardening
      SSH policy enforcement including key-based authentication, session controls, and hardened access pathways.
    
    - Network Boundary Controls
      Least-privilege ingress filtering and service exposure management using UFW with rate limiting and controlled access policies.
    
    - Host-Level Intrusion Prevention
      Deployment and tuning of Fail2Ban to detect brute-force activity and enforce automated response actions.
    
    - Audit & Visibility Instrumentation
      Comprehensive auditd policy capturing privileged operations, configuration changes, authentication behavior, and command execution.
    
    - Kernel-Level Hardening
      sysctl configurations supporting memory protection, ICMP and packet-handling restrictions, tamper resistance, and attack-surface reduction.
    
    - Documentation & Evidence Generation
      Repeatable procedures, validation output, implementation notes, and supporting artifacts demonstrating each configuration’s effect.
