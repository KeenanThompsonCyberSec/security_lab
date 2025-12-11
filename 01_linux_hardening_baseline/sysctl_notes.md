# Sysctl Kernel Hardening Notes

## Overview
Sysctl is configured to implement kernel-level hardening across network,
memory, and system security settings. These changes align with industry
standards including CIS Benchmarks, STIGs, and cloud security baselines.

The configuration protects the system from:
- IP spoofing
- ICMP abuse and redirect attacks
- SYN flood attacks
- Source route attacks
- Kernel memory disclosure
- Core dump leakage
- Reduced ASLR entropy
- IPv6 redirect & routing abuse

This represents production-level host hardening expected in SOC,
infrastructure security, cloud, and detection engineering roles.

---

## Modified File
/etc/sysctl.d/99-security.conf

## Applied Hardening Settings

### Network Protection
- rp_filter enabled (anti-spoofing)
- ICMP broadcast ignoring
- Redirects disabled
- Source routing disabled
- Martian packet logging enabled
- SYN cookies enabled
- IPv6 privacy extensions enabled

### Kernel & System Protections
- kptr_restrict set to 2 (protect kernel pointers)
- dmesg_restrict set to 1 (non-root cannot view kernel logs)
- suid_dumpable set to 0 (disable core dumps)
- randomize_va_space set to 2 (full ASLR)

---

## Commands Executed
sudo nano /etc/sysctl.d/99-security.conf  
sudo sysctl --system  
sudo sysctl -a | grep <key>  

---

## Validation Outputs

root@UbuntuLab:/home/Keenan# sysctl net.ipv4.tcp_syncookies
net.ipv4.tcp_syncookies = 1
root@UbuntuLab:/home/Keenan# sysctl kernel.kptr_restrict
kernel.kptr_restrict = 2
root@UbuntuLab:/home/Keenan# sysctl kernel.randomize_va_space
kernel.randomize_va_space = 2
root@UbuntuLab:/home/Keenan# sysctl net.ipv4.conf.all.accept_redirects
net.ipv4.conf.all.accept_redirects = 0
root@UbuntuLab:/home/Keenan# sysctl fs.suid_dumpable
fs.suid_dumpable = 0
root@UbuntuLab:/home/Keenan#

---

## Notes
- IPv6 disablement is commented out but available depending on environment needs.
- All settings persist across reboot via sysctl.d.
- Hardening verified after load using sysctl queries.

---

## Conclusion
The system now enforces a kernel-level security baseline appropriate for
enterprise Linux hosts, cloud workloads, and production server environments.
This configuration demonstrates competency in host hardening, network defense,
and kernel security management.


