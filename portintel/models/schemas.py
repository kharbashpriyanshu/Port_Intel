from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional


@dataclass
class ScanTarget:
    target: str
    start_port: int
    end_port: int
    is_udp: bool = False

@dataclass
class VulnerabilityInfo:
    cve_id: str
    description: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_version: Optional[str] = None
    severity: Optional[str] = None

@dataclass
class BannerInfo:
    raw_banner: str
    clean_banner: str

@dataclass
class PortResult:
    port: int
    service: str
    status: str
    banner: Optional[str] = None
    version: Optional[str] = None
    cpe: Optional[str] = None
    risk: Optional[str] = None
    mitre: List[str] = field(default_factory=list)
    cves: List[str] = field(default_factory=list)
    vulnerabilities: List[VulnerabilityInfo] = field(default_factory=list)
    cvss_score: Optional[float] = None
    cvss_version: Optional[str] = None
    exposure_concern: Optional[str] = None

@dataclass
class HostResult:
    ip: str
    is_alive: bool
    open_ports: List[PortResult] = field(default_factory=list)

@dataclass
class ScanSummary:
    target: str
    start_time: datetime
    end_time: datetime
    total_ports_scanned: int
    open_ports_count: int
    results: List[PortResult] = field(default_factory=list)
