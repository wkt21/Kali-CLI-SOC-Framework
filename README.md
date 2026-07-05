# Kali-SOC-Compliance-CLI-Framework-

Complete custom Kali CLI SOC Framework

🛡️ Kali SOC Compliance Framework — Custom Automated SOC Analyst Toolkit

A modular Bash + Python framework for ATT&CK simulations, log generation, lab automation, detection testing, and reporting. This repo supports lab exercises and the SOC Analyst Roadmap, enabling repeatable simulations and verification.

Features
- MITRE ATT&CK Integration — Simulate techniques mapped to roadmap labs.
- Log Generation & Analysis — Produce realistic execution, network, and auth events for SIEM/ELK practice.
- Lab Automation — Bootstrap environments tied to roadmap sections.
- Rich Reporting — Track progress across Core Skills → Advanced Blue Team.
- Extensible — Add new modules and plugins with a simple manifest format.
- Secure Ingest — TLS and optional mTLS support for endpoint ingestion.

Installation (lab)
1. Clone:
   git clone https://github.com/wkt21-0/Kali-CLI-SOC-Framework.git
   cd Kali-CLI-SOC-Framework

2. Make scripts executable and install:
   chmod +x scripts/*.sh
   # Install dependencies (create venv recommended)
   python3 -m venv venv
   venv/bin/pip install -r requirements.txt

3. Run server locally (lab):
   export INGEST_API_KEY="lab-secret"
   # Self-signed cert for lab: generate soc_cert.pem / soc_key.pem, then:
   uvicorn ops.ingest.server:app --host 0.0.0.0 --port 5514 --ssl-certfile ./soc_cert.pem --ssl-keyfile ./soc_key.pem

Usage (examples)
- soc --help
- soc attack simulate T1059
- soc logs generate execution
- soc report generate soc-operations
- python -m core.engine status

Project Structure (high-level)
- bin/ — Main CLI wrappers
- core/ — Engine, CLI router, module glue
- ops/ — Operational modules (ingest, threatintel, detection, alerts, dashboard)
- agent/ — Endpoint agent and transport code
- scripts/ — Helper scripts (cert generation, setup)
- config/ — Mappings & configuration (soc.yaml, rbac.yaml, compliance.yaml)
- system/ — systemd units, hardening scripts
- deployment/ — nginx/certbot snippets and deployment notes

Roadmap Alignment
Every command links back to roadmap lab sections and ATT&CK mappings to help SOC analysts progress through practical exercises.

Security & Notes
- Do NOT commit private keys or secrets to this repository.
- Use the scripts/generate_mtls_certs.sh script for local CA and cert creation, then distribute client certs securely.
- For production: use nginx + certbot + mTLS, and set REQUIRE_MTLS=true for the ingest server.
