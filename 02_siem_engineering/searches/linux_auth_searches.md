# Linux Auth Searches – Splunk

All queries assume:

- `index=linux`
- `sourcetype=linux_secure`

Adjust to match your environment.

---

## 1. Failed SSH Logins Over Time

```spl
index=linux sourcetype=linux_secure "Failed password for"
| bucket _time span=15m
| stats count AS failed_logins BY _time
