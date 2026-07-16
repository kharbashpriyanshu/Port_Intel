from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime

@dataclass
class ScanTarget:
    target: str
    start_port: int
    end_port: int
    is_udp: bool = False

@dataclass
class VulnerabilityInfo:
    cve_id: str

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
    cves: List[str] = field(default_factory=list)

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
