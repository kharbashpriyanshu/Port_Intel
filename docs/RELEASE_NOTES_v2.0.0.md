# 🚀 Release Notes - PortIntel v2.0.0

**Release Date:** 2026-07-16

We are thrilled to announce the release of **PortIntel v2.0.0**! 

This release marks a massive paradigm shift. PortIntel has transitioned from a monolithic, script-based scanner into a mature, enterprise-grade reconnaissance framework driven by SOLID design principles, Design Patterns, and a highly decoupled Intelligence pipeline.

---

## 🏗️ Major Architecture Rewrite
The entire codebase was stripped down and rebuilt. The previous `ping.py` and `portintel.py` scripts were abandoned in favor of a clean package structure. 
- **Strategy Pattern:** Utilized extensively across Discovery, Intelligence, and Reporting engines.
- **Dependency Injection:** Providers and Strategies are now injected via the `Orchestrator`, ensuring modules are completely independent and effortlessly testable.

## 🚀 Engine Improvements

### Scanner Engine
- Strictly isolated. It now does absolutely nothing except attempt connections and return raw `PortResult` objects.
- Migrated to a reusable `ThreadedScanner` execution pool with graceful thread shutdown logic.

### Fingerprint Engine
- Spun off into its own independent module.
- Now features robust `BannerGrabber` socket classes.
- Introduced a regex-based `VersionParser` capable of semantically extracting product versions directly from raw banners.

### Intelligence Engine (New!)
- **Automated CPE Formulation:** Banners and Service names are automatically transformed into `CPE 2.3` strings.
- **MITRE ATT&CK Mapping:** Services are automatically mapped to tactical threat vectors.
- **Risk Scoring:** Assigns Severity scores (Info, Medium, High, Critical) based on extracted vulnerability data.
- **CVE Provider Strategy:** Fetches CVEs cleanly via a swappable API interface.

### Discovery Engine
- Refactored into a `DiscoveryStrategy`. Currently supports ICMP sweeps, but perfectly poised to support ARP or TCP SYN sweeps in future updates without touching core code.

### Reporting Engine 2.0 (New!)
- Replaced the procedural, hard-coded exporters with a polymorphic Reporting Strategy Engine.
- Outputs completely redesigned for professional auditing:
  - ANSI-colorized Console Output
  - JSON for SIEM ingestion
  - CSV for Database importing
  - HTML for Premium Visual Assessments
  - Markdown for GitHub/Wiki tracking
  - PDF/Text for structured printing

## 🖥️ Professional CLI
- Converted to `argparse` subparsers (`portintel scan`, `portintel discover`, `portintel config`, `portintel version`).
- Integrated strong input sanitization (`ipaddress` and regex boundary checking).
- Guaranteed backward compatibility through intelligent `sys.argv` pre-processors for legacy users.

## 🧪 Testing & Packaging
- Transitioned to PyPI-standard packaging (`pyproject.toml`).
- Can now be executed simply via `portintel` anywhere on the CLI or `python -m portintel`.
- Introduced a rigorous `pytest` suite ensuring 60%+ code coverage for the entire CI/CD pipeline.
- Established `ruff` as the linter of choice.
