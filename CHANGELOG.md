# Changelog

All notable changes to this project will be documented in this file.

## [2.0.0] - 2026-07-16

### Added
- **Major Architecture Rewrite**: Fully migrated from a procedural monolithic script to an enterprise-grade, modular Object-Oriented design utilizing SOLID principles and the Strategy Pattern.
- **Reporting Engine**: Introduced a pluggable Reporting Engine supporting JSON, CSV, Markdown, structured printable text (PDF proxy), and beautiful HTML exports.
- **Intelligence Engine**: Added decoupled threat intelligence layer with CVE lookup capability (NVD Provider), MITRE ATT&CK mapping, CPE resolution, and automated Risk Scoring.
- **Automated Testing Suite**: Implemented comprehensive unit and integration testing via `pytest`, achieving >60% coverage across core network components.
- **Professional CLI**: Modernized the command-line interface with `argparse` subparsers (`scan`, `discover`, `config`, `version`, `help`), robust input validation, and backwards compatibility wrappers.

### Changed
- **Scanner Engine**: Decoupled TCP/UDP scanning into an isolated `ThreadedScanner`.
- **Discovery Engine**: Switched to a robust Strategy Pattern supporting ICMP (and future IPv6/ARP/TCP) discovery.
- **Fingerprint Engine**: Refactored banner grabbing, service detection, and semantic version extraction into isolated, reliable modules.
- **UX Improvements**: CLI now features risk-colored output, duration timings, formatted tables, and intuitive error handling.
