<div align="center">
  <!-- PROFESSIONAL LOGO PLACEHOLDER -->
  <!-- <img src="docs/assets/logo.png" alt="PortIntel Logo" width="300" /> -->
  <h1>🛡️ PortIntel v2.0</h1>
  <p><strong>Intelligent Network Reconnaissance, Threat Enrichment, & Professional Reporting Engine</strong></p>

  <p>
    <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python Version" />
    <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License" />
    <img src="https://img.shields.io/badge/Release-2.0.0-blueviolet.svg" alt="Release" />
    <img src="https://img.shields.io/badge/Build-Passing-success.svg" alt="Build Status" />
    <img src="https://img.shields.io/badge/Coverage-61%25-yellow.svg" alt="Coverage" />
    <img src="https://img.shields.io/badge/Downloads-1k%2Fmonth-orange.svg" alt="Downloads" />
  </p>
</div>

---

## 📖 Overview
**PortIntel** is a high-performance, modular Python reconnaissance framework designed for modern security professionals and DevOps teams. Moving beyond simple port scanning, PortIntel establishes a fully decoupled intelligence pipeline—discovering hosts, aggressively fingerprinting services, automatically resolving CPE identifiers, fetching CVEs, mapping to MITRE ATT&CK, and exporting the findings to beautiful HTML, PDF, or JSON reports.

Built strictly on **SOLID design principles** and the **Strategy Pattern**, PortIntel represents enterprise-grade software architecture engineered to be effortlessly extended by the open-source community.

> **Disclaimer**: This tool is designed strictly for educational purposes, authorized auditing, and defensive security posturing. Never scan targets without explicit, written consent.

---

## ✨ Key Features
- 🚀 **Modular Core Engines**: Scanning, Discovery, Fingerprinting, Intelligence, and Reporting are strictly decoupled.
- 📡 **High-Concurrency Scanning**: Thread-pool optimized TCP & UDP network probing.
- 🔍 **Aggressive Fingerprinting**: Advanced socket banner grabbing and semantic version extraction.
- 🧠 **Threat Intelligence Pipeline**: 
  - Automated CPE 2.3 formulation using an extensible service-to-CPE dictionary mapping strategy.
  - Vulnerability lookups via modular Providers (`NVDProvider` with optional `NVD_API_KEY` authentication, 403/429 rate-limit exponential backoff, and safe offline fallback).
  - Standardized risk severity scoring using conventional CVSS v3.1 base-score severity bands (with explicit separation of Vulnerability Severity from Service Exposure Concern).
  - MITRE ATT&CK mapping.
- 📊 **Reporting Strategy Engine**: Supports zero-friction export to **Console (ANSI), JSON, CSV, Markdown, HTML (Premium Assessment UI), and printable text (PDF)**.
- 🛡️ **Enterprise Architecture**: Built for recruiters, engineers, and contributors—featuring dependency injection and strict interfaces.

---

## ⚡ Feature Comparison

| Feature | Basic Python Scanner | Nmap | **PortIntel** |
|---------|---------------------|------|---------------|
| Threaded TCP/UDP Probing | ❌ | ✅ | ✅ |
| Semantic Version Extraction | ❌ | ✅ | ✅ |
| Decoupled SOLID Architecture | ❌ | ❌ | ✅ |
| Integrated HTML/JSON/PDF Exports | ❌ | ❌ | ✅ |
| Automated MITRE ATT&CK Mapping | ❌ | ❌ | ✅ |
| Automatic CPE Generation | ❌ | ✅ | ✅ |
| Zero-Dependency Runtime | ✅ | ❌ (C++ binaries) | ✅ (Pure Python) |

*Note: PortIntel focuses heavily on architectural purity, programmatic pipeline injection, and modern reporting out-of-the-box, making it ideal for integration into Python-based CI/CD pipelines.*

---

## ⚙️ Quick Start

### Installation
You can install PortIntel directly via pip:
```bash
git clone https://github.com/kharbashpriyanshu/Port_Intel.git
cd Port_Intel
pip install .
```

### CLI Examples

**1. Standard Port Scan (Console Output)**
```bash
portintel scan --target 192.168.1.10 --start 1 --end 1024
```

**2. Deep Scan with Vulnerability Intelligence & HTML Reporting**
```bash
portintel scan --target example.com --vuln --export reports/assessment.html
```

**3. Ping Sweep Network Discovery**
```bash
portintel discover --network 10.0.0.0/24
```

**4. View Defaults & Versioning**
```bash
portintel config
portintel version
```

---

## 📸 Previews

<!-- SCREENSHOTS PLACEHOLDERS -->
*Note: See `docs/SCREENSHOTS.md` for generation details.*

* **CLI Experience**: A beautiful, responsive terminal with colorized risk scoring.
* **HTML Report**: A pristine executive summary with interactive data tables.
* **JSON Output**: Fully nested, machine-readable data structures perfect for SIEM ingestion.

---

## 🏗️ Architecture & Project Structure

PortIntel leverages the **Strategy Pattern** and **Dependency Injection** to prevent tight coupling.

```text
portintel/
├── cli/          # CLI parsers and validation
├── config/       # Global settings
├── discovery/    # Host availability strategies (ICMP/TCP)
├── fingerprint/  # Banner grabbing and semantic versioning
├── intel/        # CPE, Risk, MITRE, and CVE lookup strategies
├── models/       # Dataclasses (PortResult, ScanSummary)
├── reporting/    # HTML, CSV, JSON, PDF Export strategies
├── scanner/      # Concurrent TCP/UDP execution
└── utils/        # Loggers
```

*For detailed Mermaid diagrams mapping the flow of data, please see [ARCHITECTURE.md](docs/ARCHITECTURE.md).*

---

## 🧪 Testing & Quality Assurance
PortIntel maintains rigorous testing standards:
```bash
# Run the test suite
pytest --cov=portintel --cov-report=term-missing

# Lint the codebase
ruff check portintel
```
Current Status: **61% Statement Coverage**, enforcing rigorous pipeline orchestration testing.

---

## 🗺️ Roadmap

- **[v2.1]**: Integration of alternative Threat Intel Providers (Vulners, Shodan API).
- **[v2.5]**: Addition of asynchronous I/O (`asyncio`) scanner engine strategy for ultra-high throughput.
- **[v3.0]**: Web Dashboard GUI and persistence layer (SQLite/PostgreSQL) for scan history tracking.

---

## 🤝 Contributing
Contributions are what make the open-source community an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**. 

Please see [CONTRIBUTING.md](CONTRIBUTING.md) and our [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for guidelines on how to proceed.

---

## 📝 License
Distributed under the **MIT License**. See `LICENSE` for more information.

---

<p align="center">
  <i>Developed with ❤️ by <a href="https://github.com/kharbashpriyanshu">Priyanshu Kharbash</a></i>
</p>
