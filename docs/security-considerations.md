# Security Considerations

- Regex-based detection is an initial control, not a complete defense.
- False positives must be monitored during rollout.
- All security events should be retained and reviewed.
- Blocking decisions should be rate-limited and logged.
- Replace the null block executor with audited `iptables` or `nftables` integration before production use.
- Add TLS termination, request size limits, and upstream allowlists in deployment.
