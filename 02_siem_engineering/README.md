# SIEM Engineering (Splunk) – Linux Focus

This folder contains the Week 2 deliverables for my Security Engineer Lab: SIEM engineering with Splunk, focused on Linux authentication and privileged activity.

## Objectives

- Move from basic “log viewing” to actual **detection engineering**.
- Ingest core Linux security telemetry into Splunk:
  - `linux_secure` / `auth.log` (SSH, sudo, user management)
  - auditd (`type=EXECVE`, sensitive file access, user changes)
- Build two dashboards:
  - **Linux Auth Overview**
  - **Linux Privileged Activity & System Monitoring**
- Define and document high-signal detection rules, not just pretty charts.

## Data Sources

All searches assume:

- `index=linux`
- `sourcetype=linux_secure` for SSH, sudo, and user management logs.
- `sourcetype=auditd` for auditd events (e.g., `type=EXECVE`, `PATH`, `SYSCALL`).

If your environment uses different sourcetypes, update the SPL accordingly.

---

## Dashboards

### 1. Linux Auth Overview

File: `dashboards/linux_auth_overview.json`

Purpose:

- Monitor SSH authentication activity.
- Highlight failed logins, brute-force attempts, and successful login distribution by user/IP.
- Provide quick pivots during investigations (who, from where, and how often).

Key panels:

- Failed SSH logins over time
- Brute-force windows (≥5 failures in 5 minutes)
- Failed logins by user
- Failed logins by source IP
- Successful logins by IP
- Success vs failed over time

Underlying searches are documented in:

- `searches/linux_auth_searches.md`

---

### 2. Linux Privileged Activity & System Monitoring

File: `dashboards/linux_privileged_activity.json`

Purpose:

- Monitor **sudo** usage and privileged commands.
- Track user and group management events (creates/modifies/deletes).
- Monitor process execution via auditd.
- Track changes to sensitive files (`/etc/shadow`, `/etc/passwd`, `/etc/sudoers`, `/etc/ssh/sshd_config`).

Key panels:

- `sudo` usage over time
- Top sudo users and commands
- User/group management events
- auditd process execution (EXECVE)
- Sensitive file modifications
- Suspicious execve on sensitive binaries (e.g., `su`, `passwd`, `sudo`)

Underlying searches are documented in:

- `searches/linux_privileged_activity_searches.md`

---

## Detection Rules

Detection documentation lives under:

- `detections/`

Each detection rule has:

- **Name and purpose**
- **Data source**
- **SPL query**
- **Detection logic**
- **Operational notes** (tuning ideas, false positives, etc.)

Current rules:

1. `linux_ssh_bruteforce.md` – SSH brute-force detection (failed auth).
2. `linux_failed_root_logins.md` – Excessive failed logins for `root`.
3. `linux_sudo_priv_escalation.md` – Suspicious or frequent `sudo` usage.
4. `linux_user_mgmt_changes.md` – User / group creation, modification, deletion.
5. `linux_sensitive_file_mods.md` – Modifications to `/etc/shadow`, `/etc/passwd`, `/etc/sudoers`, `/etc/ssh/sshd_config`.

---

## Status

- [x] Folder structure defined
- [x] Core SPL for auth and privileged activity documented
- [ ] Dashboards exported as JSON and checked into `dashboards/`
- [ ] Detection rules wired into Splunk as saved searches/correlation searches
- [ ] Sample screenshots captured for portfolio use

As telemetry grows (more events over time), these dashboards and detections will start surfacing useful patterns without needing to change the structure.
