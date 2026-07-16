from portintel.intel.cpe import CPEResolver
from portintel.intel.cve import CVELookup
from portintel.intel.engine import IntelligenceEngine
from portintel.intel.mitre import MITREMapper
from portintel.intel.providers import CVEProvider
from portintel.intel.risk import RiskScorer
from portintel.models.schemas import PortResult


def test_cpe_resolver():
    pr = PortResult(port=80, service="HTTP", status="OPEN", version="2.4")
    cpe = CPEResolver.resolve(pr)
    assert cpe == "cpe:2.3:a:http:http:2.4:*:*:*:*:*:*:*"

    pr_no_ver = PortResult(port=22, service="SSH", status="OPEN")
    cpe_no_ver = CPEResolver.resolve(pr_no_ver)
    assert cpe_no_ver == "cpe:2.3:a:ssh:ssh:*:*:*:*:*:*:*:*"

def test_risk_scorer():
    pr_safe = PortResult(port=80, service="HTTP", status="OPEN")
    assert RiskScorer.score(pr_safe) == "Info"

    pr_medium = PortResult(port=23, service="TELNET", status="OPEN")
    assert RiskScorer.score(pr_medium) == "Medium"

    pr_high = PortResult(port=80, service="HTTP", status="OPEN", cves=["CVE-2021-1234"])
    assert RiskScorer.score(pr_high) == "High"

    pr_critical = PortResult(port=80, service="HTTP", status="OPEN", cves=["CVE-1", "CVE-2"])
    assert RiskScorer.score(pr_critical) == "Critical"

def test_mitre_mapper():
    pr = PortResult(port=445, service="SMB", status="OPEN")
    mitre = MITREMapper.map_service(pr)
    assert len(mitre) > 0
    assert "Lateral Movement" in mitre[0]

class MockCVEProvider(CVEProvider):
    def get_cves(self, keyword: str):
        if "ssh" in keyword.lower():
            return ["CVE-2020-15778"]
        return []

def test_cve_lookup():
    provider = MockCVEProvider()
    lookup = CVELookup(provider)

    # Test via CPE
    assert "CVE-2020-15778" in lookup.find_cves(cpe="cpe:2.3:a:openssh:openssh:*:*:*:*:*:*:*:*")

    # Test via Banner fallback
    assert "CVE-2020-15778" in lookup.find_cves(banner="SSH-2.0-OpenSSH_8.2p1")

def test_intelligence_engine():
    provider = MockCVEProvider()
    lookup = CVELookup(provider)
    engine = IntelligenceEngine(cve_lookup=lookup)

    pr = PortResult(port=22, service="SSH", status="OPEN", banner="SSH-2.0-OpenSSH_8.2p1")
    results = engine.enrich([pr])

    assert results[0].cpe == "cpe:2.3:a:ssh:ssh:*:*:*:*:*:*:*:*"
    assert results[0].risk == "High" # Has 1 CVE
    assert len(results[0].mitre) > 0
    assert "CVE-2020-15778" in results[0].cves
