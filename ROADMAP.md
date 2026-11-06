# Agent Wall: Technical & Commercial Development Roadmap

This document consolidates all planned feature additions, architectural enhancements, and packaging requirements to transition Agent Wall from its current proof-of-concept state into a commercial, multi-tenant MSP security product.

---

## 1. Feature Architecture & Capabilities

To support a nationwide B2B MSP rollout, the product must expand across three operational pillars: **MSP Administration**, **End-Client Reporting**, and **System Capabilities**.

### A. Multi-Tenant MSP Administration
* **Centralized Management Console:** A single-pane-of-glass dashboard allowing an MSP to monitor, configure, and manage security policies across dozens to hundreds of distinct client environments.
* **Role-Based Access Control (RBAC):** Tiered permissions enabling tier-1 support technicians to view security alerts while tier-3 security engineers configure detection thresholds and regex rules.
* **Granular Policy Management:** Ability to apply global rules across all clients while permitting per-client overrides (e.g., custom path exemptions for specific web applications).

### B. Automated Co-Branded Reporting
* **Executive Summary Reports (PDF):** Automated monthly 1-page reports designed for non-technical executives (CEOs/CTOs), summarizing total evasion attempts blocked, canary hits, and overall security posture.
* **White-Label Customization:** Full logo and color-scheme customization, enabling MSPs to brand the security reports as their own value-added service.
* **Compliance Alignment Helpers:** Direct mapping of threat detections to compliance frameworks (such as Australian ISM, Essential Eight, and ARNECC MPR standards).

### C. Advanced Detection & Tagging Mechanisms
* **Dynamic Actor & Behavioral Tagging:** 
  * Classifying incoming actors beyond static IPs using structural behavioral fingerprints (evasion grammars).
  * Integration with cryptographic verification standards (such as Web Bot Auth) to suppress false positives on verified crawlers while elevating severity on unverified agent User-Agents.
* **Cross-Tenant Swarm Intelligence:** Privacy-preserving signal digests (hashing evasion signatures and resource shapes without raw customer logs) to detect low-and-slow distributed scraping swarms across multiple MSP clients.
* **Active Mitigation Hooks:** Optional automated block generation via APIs (Cloudflare WAF API, Nginx `deny` lists, IPTables) to transition from passive detection to active enforcement on demand.

---

## 2. Infrastructure & Integration Requirements

| System Domain | Feature Requirement | Practical Benefit |
| :--- | :--- | :--- |
| **Log Ingestion** | Support for Cloudflare Logpush, Nginx, Apache, and IIS | Allows deployment without forcing clients to migrate web servers. |
| **SIEM / RMM Connectors** | Syslog, CEF, and JSON Webhooks | Forward alerts natively into MSP tools (ConnectWise, Datto, Sentinel). |
| **Deployment Packaging** | Docker containers & 1-line installation scripts | Reduces onboarding time to under 15 minutes per target environment. |
| **Log Privacy** | Streaming zero-storage log processing | Avoids local storage of client log data, simplifying data privacy compliance. |

---

## 3. Productization Phases & Feature Priority

### Phase 1: V1.0 Core Engine & Easy Deployment
* **Focus:** Stability, minimal operational footprint, zero false positives.
* **Key Features:**
  * Containerized deployment (Docker image).
  * Automated log path discovery for Linux/Nginx environments.
  * Basic email/webhook alerting.
  * Native implementation of `block_defiance` and `injection_tripwire` detectors.

### Phase 2: V1.5 MSP Pilot & Proof Pack
* **Focus:** Partner value demonstration and white-label features.
* **Key Features:**
  * Automated white-labeled PDF report generation (HTML-to-PDF pipeline).
  * Denial-page tracking nonces (`/cb/<nonce>`) for proof-grade detection evidence.
  * Standardized SIEM integration webhooks.

### Phase 3: V2.0 Scaled Network & Swarm Intelligence
* **Focus:** Platform scaling, multi-tenancy, and channel expansion.
* **Key Features:**
  * Multi-tenant web dashboard for centralized MSP administration.
  * Cross-tenant correlator engine (`correlation.py`) for swarm defense.
  * Dynamic IP/Subnet auto-blocking via Cloudflare and firewall APIs.

---

## 4. Evaluation Checklist for Future Engineering

Before committing resources to building out new features, evaluate each proposed addition against these three criteria:

1. **Does it preserve the low-touch model?** Features must not add ongoing manual maintenance per tenant.
2. **Does it enhance the MSP's margin or sales story?** Priority is given to features that help MSPs sell the service to their end-clients (e.g., reports, white-labeling).
3. **Does it maintain near-zero false positives?** Any advanced detection rule must be validated against noisy baseline traffic before inclusion in standard releases.