# Authorized use and security boundaries

Use the lab only with explicit authorization. Default fixtures are inert JSON and reserved documentation addresses/domains. The project does not install Sysmon, run Atomics, disable endpoint controls, change host policy, or execute process command-line fields. Optional endpoint experimentation is separate and requires a disposable VM and approved test plan.

## Default controls

- Generated 256-bit random passwords and persistent encryption keys; no committed credentials.
- Verified TLS for Elasticsearch/Kibana clients and backend traffic. Browser trust is scoped to the private lab CA.
- Backend `internal` network; a localhost-only fixed-destination gateway supplies UI/API access.
- Separate writer credential volume for the generator and Filebeat. No Docker socket, host PID namespace, privileged mode, or writable host OS mounts.
- Nonroot application processes, dropped Linux capabilities, no-new-privileges, bounded resources and healthchecks. Certificate and secret initialization briefly run as root inside their containers.
- The private CA signing key is not mounted into runtime services.

## Important limitations

This is not a hardened production SIEM, an internet-facing service, or a sandbox for untrusted executables. Elasticsearch and Kibana share the runtime certificate volume, and bootstrap service containers can read the administrative secret volume. A compromised runtime service or Docker administrator is outside this lab's isolation guarantee. The gateway joins an ordinary bridge network and has egress; it forwards incoming traffic only to fixed internal services.

The lab has a single node, no high availability, no backup scheduler, no external identity provider, and no production log-retention or incident-response guarantees. Production deployment requires a separate reviewed design with external secrets, least-privilege bootstrap/API keys, separate certificate mounts, firewall controls, monitoring, patch management, tested backups and organizational access policy. There is no switch that turns this lab into a production service.

The original rules are experimental teaching detections. Some intentionally broad discovery and RDP rules can be noisy. Lab domain matching and a TCP port signal do not detect arbitrary command and control. Synthetic data validates the selected fields and rule execution; it does not prove real Sysmon collection, attack success, or complete ATT&CK coverage.

## Maintenance

Pin and review dependency updates, test upgrades against fresh volumes, then run offline and live tests. Keep credentials and generated certificates out of Git. Rotate users and encryption keys through supported Elastic procedures and coordinated secret updates; changing only a file does not change an existing Elasticsearch password. Export manual rule changes before reprovisioning.

For vulnerabilities in this repository, follow [SECURITY.md](../SECURITY.md). For Elastic or other dependencies, report through the vendor's security process.
