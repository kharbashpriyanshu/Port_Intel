# 🏗️ PortIntel Architecture

This document describes the internal engineering, SOLID design principles, and module interaction pipeline of the PortIntel reconnaissance framework.

---

## 1. High-Level Data Flow Pipeline

The framework ensures that data flows in a strict, sequential pipeline. Each Engine is completely unaware of the other's implementation, communicating entirely via shared standard models (`PortResult`, `HostResult`, `ScanSummary`).

```mermaid
graph TD
    A[CLI / Orchestrator] -->|Target IP| B(Scanner Engine)
    B -->|List of PortResults| C(Fingerprint Engine)
    C -->|Enriched Banners/Versions| D(Intelligence Engine)
    D -->|CVEs, MITRE, Risk, CPE| E(Reporting Engine)
    E -->|Formatted Output| F[Disk / Console]
```

---

## 2. Engine Decoupling via Strategy Pattern

To prevent architectural decay, major modules utilize the **Strategy Pattern**. This allows developers to easily extend PortIntel without modifying core classes.

### Reporting Engine Strategy
```mermaid
classDiagram
    class ReportStrategy {
        <<interface>>
        +generate(summary: ScanSummary, filename: str)
    }
    
    class JSONReport {
        +generate()
    }
    class HTMLReport {
        +generate()
    }
    class MarkdownReport {
        +generate()
    }
    
    ReportStrategy <|-- JSONReport
    ReportStrategy <|-- HTMLReport
    ReportStrategy <|-- MarkdownReport
    
    class ReportingEngine {
        -strategies: dict
        +add_strategy(name: str, strategy: ReportStrategy)
        +report(summary: ScanSummary, filenames: dict)
    }
    
    ReportingEngine o-- ReportStrategy
```

### Intelligence Provider Strategy & Threat Enrichment
The Intelligence Engine orchestrates threat enrichment across four core subsystems:
1. **`CPEResolver`**: Uses an extensible service-to-CPE dictionary mapping strategy (`CPEMappingRule`) with word-boundary and regex banner matching and version normalization. Never fabricates CPEs when fingerprint evidence is insufficient.
2. **`CVEProvider` / `NVDProvider`**: The Intelligence Engine injects a `CVEProvider` into the `CVELookup` logic. `NVDProvider` queries the NIST NVD REST API 2.0, supporting optional `NVD_API_KEY` authentication from environment variables, bounded exponential backoff for HTTP 403/429 rate limits, and safe fallback to offline/empty results without throwing exceptions.
3. **`RiskScorer`**: Implements standards-based CVSS v3.1 base-score severity bands (`Critical`: 9.0+, `High`: 7.0+, `Medium`: 4.0+, `Low`: 0.1+, `None`: 0.0) while clearly separating **Vulnerability Severity** (`risk`) from **Service Exposure Concern** (`exposure_concern`, e.g. cleartext Telnet/FTP exposure).
4. **`MITREMapper`**: Automatically maps detected services and ports to MITRE ATT&CK enterprise tactics and techniques.

```mermaid
classDiagram
    class CVEProvider {
        <<interface>>
        +get_cves(keyword: str) List~str~
    }
    
    class NVDProvider {
        +get_cves(keyword: str) List~str~
    }
    class VulnersProvider {
        +get_cves(keyword: str) List~str~
    }
    
    CVEProvider <|-- NVDProvider
    CVEProvider <|-- VulnersProvider
    
    class CVELookup {
        -provider: CVEProvider
        +find_cves(cpe: str, banner: str)
    }
    CVELookup o-- CVEProvider
```

---

## 3. Package Relationships

PortIntel is strictly layered. Inner layers (Models, Config) cannot import from outer layers (CLI, Engines).

```mermaid
graph LR
    Models(models/schemas.py)
    Config(config/settings.py)
    Utils(utils/logger.py)
    
    Engines[Scanner, Fingerprint, Intel, Discovery, Reporting]
    
    CLI[cli/orchestrator.py]
    
    CLI --> Engines
    Engines --> Models
    Engines --> Config
    Engines --> Utils
```

---

## 4. Execution Workflow

When a user initiates a scan, the `Orchestrator` governs the lifecycle.

```mermaid
sequenceDiagram
    participant User
    participant Orchestrator
    participant Scanner
    participant Fingerprinter
    participant Intelligence
    participant Reporter
    
    User->>Orchestrator: `portintel scan --target 192.168.1.1`
    Orchestrator->>Scanner: scan_range_threaded(192.168.1.1, 1, 1024)
    Scanner-->>Orchestrator: List[PortResult] (raw)
    
    Orchestrator->>Fingerprinter: enrich(List[PortResult])
    Fingerprinter-->>Orchestrator: List[PortResult] (banners added)
    
    Orchestrator->>Intelligence: enrich(List[PortResult])
    Intelligence-->>Orchestrator: List[PortResult] (cve, risk added)
    
    Orchestrator->>Reporter: report(ScanSummary)
    Reporter-->>User: Console output & Files saved
```
