# 20 Portfolio Project Ideas

**Background:** Computer Science, System & Network Engineering, Cybersecurity  
**Cloud Platform:** Microsoft Azure

---

## 1. Secure Multi-Tier Web Application Infrastructure (Azure + Terraform)

**What it solves:** Companies need secure, scalable web hosting with proper network segmentation.

Deploy a production-grade 3-tier architecture on Azure using Terraform — a frontend behind an Application Gateway with WAF, a backend API in a private subnet, and an Azure SQL database accessible only from the backend. Include NSG rules, Azure Key Vault for secrets, and a Log Analytics workspace for centralized monitoring.

**Tech:** Terraform, Azure (VNet, App Gateway, App Service, SQL, Key Vault), CI/CD with GitHub Actions

---

## 2. Network Traffic Analyzer & Intrusion Detection Dashboard

**What it solves:** Small businesses and home labs need affordable network visibility without enterprise SIEM costs.

Build a tool that captures network traffic (via a TAP or mirror port), analyzes packets for anomalies (port scans, brute-force attempts, unusual DNS queries, data exfiltration patterns), and displays findings on a real-time web dashboard. Include alerting via email or Slack webhooks.

**Tech:** Python (Scapy, dpkt), InfluxDB or Elasticsearch, Grafana or custom React dashboard, Docker

---

## 3. Automated Vulnerability Scanner for Home Networks

**What it solves:** Average users have no idea what's exposed on their home network — open ports, outdated firmware, default credentials.

Create a lightweight scanner that discovers devices on a local network, fingerprints OS and services, checks for known CVEs (via NVD API), tests for default credentials, and generates a human-readable security report with remediation steps.

**Tech:** Python, Nmap (python-nmap), NVD REST API, PDF report generation (ReportLab), Flask web UI

---

## 4. Zero-Trust VPN Gateway on Azure

**What it solves:** Remote workers need secure access to private resources without exposing them to the internet.

Set up a WireGuard-based VPN server on an Azure VM with identity-aware access control. Users authenticate via Azure AD (Entra ID), and access policies are enforced per-user/per-resource. Include a self-service web portal where approved users can download their VPN configuration.

**Tech:** WireGuard, Azure VM, Azure AD/Entra ID, Python (FastAPI), Terraform

---

## 5. Phishing Email Detector (Browser Extension + API)

**What it solves:** Phishing remains the #1 attack vector. Most people can't distinguish phishing from legitimate email.

Build a browser extension that analyzes emails in Gmail/Outlook Web for phishing indicators: suspicious sender domains, URL mismatches, urgency language patterns, lookalike characters, and newly registered domains. The extension calls a backend API that runs the analysis and returns a risk score.

**Tech:** JavaScript (browser extension), Python (FastAPI), spaCy or a fine-tuned model for text classification, whois API, VirusTotal API

---

## 6. Infrastructure-as-Code Security Linter

**What it solves:** DevOps teams push insecure Terraform/ARM templates without realizing it — open security groups, unencrypted storage, public databases.

Create a CLI tool that scans Terraform and ARM templates for security misconfigurations against a rule set (e.g., "no public IP on databases," "encryption at rest required," "no wildcard IAM permissions"). Output results in SARIF format for GitHub Security tab integration.

**Tech:** Python or Go, HCL parser, JSON/YAML parsing, SARIF output, GitHub Actions integration

---

## 7. Encrypted File Sharing Service (Azure-Hosted)

**What it solves:** People regularly share sensitive files via unencrypted email or sketchy file-sharing sites.

Build a web app where users upload files that are encrypted client-side (AES-256) before leaving the browser. Files are stored in Azure Blob Storage. The sender gets a shareable link and the decryption key is never sent to the server. Links expire after a configurable time or number of downloads.

**Tech:** React (Web Crypto API for client-side encryption), Node.js or Python backend, Azure Blob Storage, Azure Functions

---

## 8. DNS Sinkhole & Ad Blocker (Pi-hole Alternative)

**What it solves:** Users want network-wide ad blocking and malware domain filtering without relying on browser extensions.

Build a DNS server that intercepts queries, blocks known malicious/ad-serving domains using curated blocklists, and logs all DNS activity to a searchable dashboard. Include the ability to add custom block/allow rules and view per-device query stats.

**Tech:** Python or Go (DNS server), SQLite or Redis, React dashboard, Docker, blocklist aggregation scripts

---

## 9. Azure Cloud Security Posture Monitor

**What it solves:** Organizations spin up Azure resources and forget to check security configurations, leading to breaches.

Build a tool that connects to an Azure subscription via a service principal and continuously audits resources: storage accounts with public access, VMs with open management ports, unencrypted disks, missing diagnostic settings, overly permissive RBAC roles. Generate a compliance score and a report with one-click remediation scripts.

**Tech:** Python (Azure SDK), Azure Resource Graph, Flask/FastAPI dashboard, scheduled Azure Function

---

## 10. Centralized Log Management & SIEM (Lite)

**What it solves:** Small teams need log aggregation and security event correlation without paying for Splunk or Sentinel.

Build a lightweight SIEM that ingests logs from multiple sources (syslog, Windows Event Log, cloud audit logs), normalizes them, and applies detection rules (e.g., "5 failed logins in 60s from same IP," "new admin account created"). Include a search interface, alert rules editor, and incident timeline view.

**Tech:** Python, Elasticsearch or Loki, Kafka or Redis Streams for ingestion, React dashboard, Sigma rules for detection

---

## 11. Automated SSL/TLS Certificate Manager

**What it solves:** Expired certificates cause outages. Many organizations track certificates in spreadsheets.

Build a service that discovers all SSL/TLS certificates across an organization's domains and subdomains, monitors expiration dates, integrates with Let's Encrypt for auto-renewal, and sends alerts before expiry. Include a dashboard showing certificate health, chain validity, and cipher strength.

**Tech:** Python (ssl, cryptography libraries), Let's Encrypt (certbot/ACME), PostgreSQL, React dashboard, Azure Functions for scheduled checks

---

## 12. Secure Password Manager with Azure Key Vault Backend

**What it solves:** People reuse passwords everywhere. Existing password managers require trusting a third party.

Build a self-hosted password manager that stores encrypted credentials in Azure Key Vault. Include a web UI and CLI for managing passwords, TOTP-based 2FA, password strength analysis, breach detection (via Have I Been Pwned API), and a browser extension for autofill.

**Tech:** Python (FastAPI), Azure Key Vault SDK, React, Web Crypto API, browser extension (JS), HIBP API

---

## 13. Network Configuration Backup & Compliance Checker

**What it solves:** Network engineers manually back up switch/router configs and have no way to detect configuration drift or policy violations.

Build a tool that connects to network devices (Cisco, MikroTik, etc.) via SSH/NETCONF, automatically backs up configurations on a schedule, diffs changes between versions, and checks configs against compliance policies (e.g., "NTP must be configured," "SNMP community string must not be 'public'," "unused ports must be shut down").

**Tech:** Python (Netmiko, NAPALM, Nornir), Git for version control of configs, Jinja2 templates for compliance rules, Flask dashboard

---

## 14. Honeypot Deployment & Attack Analytics Platform

**What it solves:** Security teams need to understand real-world attack patterns targeting their infrastructure.

Build a system that deploys configurable honeypots (SSH, HTTP, SMB, RDP) on Azure VMs across multiple regions. All interactions are logged, categorized (brute force, exploit attempts, lateral movement), and visualized on a geo-map dashboard. Include IOC (Indicators of Compromise) export for threat intelligence sharing.

**Tech:** Python (Twisted or asyncio for service emulation), Azure VMs (multiple regions), Elasticsearch, Kibana or custom React dashboard, STIX/TAXII for IOC export

---

## 15. Automated Server Hardening Tool

**What it solves:** New servers deployed with default configurations are a major attack surface. CIS benchmarks are long and manual.

Build a CLI tool that audits a Linux or Windows server against CIS benchmarks (or a custom baseline) and optionally auto-remediates findings: disabling unused services, configuring firewall rules, setting password policies, enabling audit logging, removing unnecessary packages. Generate before/after compliance reports.

**Tech:** Python or Bash (with Ansible for remediation), CIS benchmark parsing, PDF report generation, support for Ubuntu/RHEL/Windows Server

---

## 16. Multi-Cloud Cost & Security Dashboard

**What it solves:** Teams running workloads on Azure (and potentially AWS/GCP) need a single pane of glass for cost tracking and security alerts.

Build a dashboard that connects to Azure (and optionally other clouds) via APIs, aggregates cost data with forecasting, highlights cost anomalies (e.g., a VM running 24/7 that's usually off on weekends), and correlates it with security findings. Include tagging compliance checks and idle resource detection.

**Tech:** Python (Azure SDK, boto3 for AWS), React dashboard, PostgreSQL, Azure Functions for data collection, Chart.js or D3 for visualization

---

## 17. Secure Chat Application with End-to-End Encryption

**What it solves:** People need private communication channels they fully control, not dependent on big tech.

Build a real-time chat application with Signal Protocol-inspired end-to-end encryption. The server (hosted on Azure) never sees plaintext messages. Include features: group chats, file sharing, message expiration, and device verification via QR codes. The server only stores encrypted blobs.

**Tech:** React (frontend), Node.js or Python (WebSocket server), Azure App Service, libsodium or Web Crypto API, IndexedDB for local message storage

---

## 18. Automated Incident Response Playbook Engine

**What it solves:** When a security incident occurs, teams scramble. Documented playbooks exist but aren't automated.

Build a platform where security teams define incident response playbooks as workflows (e.g., "On malware detection: isolate host, capture memory, block IOCs in firewall, notify SOC lead, create ticket"). When triggered (manually or via webhook from SIEM), the engine executes steps automatically, logs actions, and provides an audit trail.

**Tech:** Python (Celery for workflow orchestration), FastAPI, React (drag-and-drop playbook editor), Azure Logic Apps for some automations, PostgreSQL

---

## 19. Website Uptime & Security Monitor

**What it solves:** Small businesses need to know when their website goes down or gets defaced/compromised, but can't afford Datadog or PagerDuty.

Build a monitoring service that checks websites at regular intervals for: availability (HTTP status), response time, SSL certificate validity, content changes (defacement detection via DOM hashing), and open port changes. Alert via email, SMS (Twilio), or Slack. Host the checker as Azure Functions for global distribution.

**Tech:** Python, Azure Functions (multi-region), Azure Table Storage or Cosmos DB, Twilio API, React dashboard

---

## 20. Active Directory Lab with Attack & Defense Scenarios

**What it solves:** Cybersecurity professionals need hands-on practice with real AD attacks and defenses, but setting up labs is tedious.

Build an automated deployment (Terraform + Ansible) that spins up a realistic Active Directory environment on Azure: Domain Controller, workstations, users with realistic permissions, and intentional misconfigurations. Include guided attack scenarios (Kerberoasting, Pass-the-Hash, DCSync) and corresponding detection/defense exercises. Tear down with one command to save costs.

**Tech:** Terraform, Ansible, Azure VMs (Windows Server, Windows 10), PowerShell, BloodHound, Sysmon, Azure Sentinel for detection

---

## Suggested Starting Order

If you're unsure where to begin, here's a prioritized path that builds skills progressively and creates an impressive, cohesive portfolio:

| Priority | Project | Why Start Here |
|----------|---------|---------------|
| 1 | **#1** Secure Multi-Tier Infrastructure | Foundation — shows you can architect cloud solutions |
| 2 | **#15** Server Hardening Tool | Demonstrates deep OS security knowledge |
| 3 | **#3** Home Network Vulnerability Scanner | Practical tool anyone can use, shows offensive skills |
| 4 | **#9** Azure Security Posture Monitor | Cloud security is in massive demand |
| 5 | **#5** Phishing Email Detector | Combines ML + security, highly visible impact |
| 6 | **#20** AD Attack & Defense Lab | The capstone — shows both red and blue team skills |

---

## Tips for Maximum Portfolio Impact

1. **Host everything on GitHub** with clear READMEs, architecture diagrams, and demo screenshots/videos.
2. **Write a blog post** for each project explaining your design decisions and what you learned.
3. **Deploy live demos** where possible (the Azure-hosted projects are perfect for this).
4. **Include CI/CD pipelines** — even a simple GitHub Actions workflow shows professionalism.
5. **Add tests** — security tools especially benefit from test suites that prove they work correctly.
6. **Use Docker** for everything — makes it trivial for recruiters/hiring managers to try your projects.
