SIEM Architecture — Linux Authentication & Privileged Activity Monitoring
1. Overview

This document defines the SIEM architecture supporting authentication, authorization, and privileged activity visibility across Linux systems. The design standardizes log collection, normalization, enrichment, and analytics within Splunk to support security monitoring, incident investigation, and detection engineering.

The architecture aggregates Linux security telemetry from multiple log sources, correlates them into a unified index, and exposes analytics through purpose-built dashboards and detection content.

2. Data Flow Architecture
```   
+-----------------------+  
| Linux Host            |  
| Ubuntu 22.04          |  
+-----------------------+  
| Log Sources:          |  
|  - auth.log           |  
|  - sudo events        |  
|  - auditd syscalls    |  
+-----------+-----------+  
            |  
            v  
+-------------------------------+  
| Splunk Indexer / Search Head  |  
+-------------------------------+  
| Index: index=linux            |  
| Sourcetypes:                  |  
|  - linux_secure               |  
|  - linux_audit                |  
+-------------------------------+  
            |  
            v  
+------------------------+  
| Analytics & Detections |  
+------------------------+  
| - Authentication Dash  |  
| - Privileged Activity  |  
| - Detection Rules      |  
+------------------------+  
```
3. Log Sources & Normalization

3.1 Authentication Events (sourcetype=linux_secure)

Collected data includes:
```
SSH login successes and failures

Public key authentication

Password authentication

Invalid user attempts

PAM session events
```
Normalized fields:
```
+-------------------------------------------+
|   Field	            Description         |
+-------------------------------------------+
|   _time	         Event timestamp        |
|   user	         Account involved       |
|   src_ip	         Remote source address  |
|   Country	         Geolocation lookup     |
|   action	         success / failure      |
+-------------------------------------------+
```

3.2 Sudo Privileged Activity

Parsed telemetry includes:
```
sudo command execution

session open / close

UID transitions

Terminal and working-directory context
```
Normalized fields:
```
+---------------------------------------------+
|  Field	            Description           |
+---------------------------------------------+
|  user	               Sudoing user           |
|  cmd	Extracted      command                |
|  sudo_count	       Aggregated usage count |
|  tty	Terminal       context                |
+---------------------------------------------+
```
3.3 auditd System Activity (sourcetype=linux_audit)

Captured behaviors include:
```
execve process execution

file modification events

access to monitored directories

execution of sensitive binaries
```
Normalized fields:
```
+------------------------------------+
|  Field	         Description     |
+------------------------------------+
|  exe	           Binary executed   |
|  uid	           User ID           |
|  audit_key	   auditd rule key   |
|  exec_count	   Occurrence count  | 
+------------------------------------+
 ```
4. Index & Sourcetype Strategy

Index	Sourcetype	Purpose
```
index=linux	linux_secure	Authentication, sudo, PAM
index=linux	linux_audit	auditd syscall events
```
All analytics reference this unified index to simplify correlation.

5. Dashboards

5.1 Linux Authentication Overview

Purpose: visibility into authentication activity and risk indicators.

Panels:
```
Failed root password attempts

Failed SSH login volume

Successful login attempts

Successful vs failed authentication over time

Login sources by IP address

Geolocation distribution of login activity

Country-based successful and failed login aggregation
```
Each panel uses structured field extraction (rex), IP enrichment (iplocation), and aggregation (stats, timechart).

5.2 Privileged Activity & System Monitoring

Purpose: visibility into privilege use and system-level activity.

Panels:
```
Sudo usage trends

Top sudo users and commands

User and group management events

auditd monitored process activity

Sensitive binary execution

High-value file modification indicators
```
This dashboard correlates auth, sudo, and auditd datasets to surface privileged behaviors and operational anomalies.

6. Detection Content

All detections are implemented as Splunk SPL queries and stored under
```
/02_siem_engineering/dashboards/.
```
6.1 Privilege Escalation Detection

Monitors repeated sudo use and anomalous commands.
```
index=linux sourcetype=linux_secure "sudo:" "COMMAND="
| rex "COMMAND=(?<cmd>.*)"
| stats count by user cmd
| where count > 3
```
6.2 Unauthorized SSH Configuration Modification

Monitors changes to SSH configuration files.

Targets:
```
/etc/ssh/sshd_config

/etc/ssh/ssh_config
```
6.3 SSH Brute-Force Detection
```
index=linux sourcetype=linux_secure "Failed password"
| bucket _time span=5m
| stats count AS failed_logins by _time src_ip
| where failed_logins >= 5
```
6.4 Permission Change Monitoring
```
Monitors chmod/chown/setuid-related audit events.
```
6.5 User Account or PAM Policy Modification

Tracks modifications to:
```
/etc/passwd

/etc/group

/etc/pam.d/*
```
7. Dashboard–Detection Mapping
```
+----------------------------------------------------------------------------------------------------------------------------------------+
|    Security Function	            Logs Used	                        Dashboard	                     Detection Coverage              |
+----------------------------------------------------------------------------------------------------------------------------------------+
|   SSH access monitoring	        linux_secure	                Linux Auth Overview	            Success/failure anomalies            |
|   Privileged activity	            linux_secure	                Privileged Activity	            Sudo escalation, command risk        |
|   Process execution	            linux_audit	                    Privileged Activity	            Suspicious exec patterns             |
|   Geographic access	            iplocation + auth logs	        Linux Auth Overview	            Unusual origin, travel anomalies     |
|   Account changes	                linux_secure	                Privileged Activity	            New/removed users, PAM edits         |
+----------------------------------------------------------------------------------------------------------------------------------------+
```

8. Design Rationale

Standardized sourcetypes ensure consistent data modeling.

Authentication and privileged activity are separated into dedicated dashboards for clarity.

All SPL queries use deterministic field extraction to support reliable detections.

Geolocation analysis augments authentication trends for richer context.

auditd integration extends visibility beyond login events to actual system-level behavior.
