from unittest.mock import MagicMock, patch

import requests

from portintel.config.settings import config
from portintel.intel.cpe import CPEResolver
from portintel.intel.cve import CVELookup
from portintel.intel.engine import IntelligenceEngine
from portintel.intel.mitre import MITREMapper
from portintel.intel.providers import CVEProvider, NVDProvider
from portintel.intel.risk import RiskScorer
from portintel.models.schemas import PortResult, VulnerabilityInfo


def test_cpe_resolver():
    # Known service mappings
    pr_apache = PortResult(
        port=80,
        service="HTTP",
        status="OPEN",
        banner="Apache/2.4.41 (Ubuntu)",
        version="2.4.41",
    )
    assert CPEResolver.resolve(pr_apache) == "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"

    pr_nginx = PortResult(
        port=80,
        service="HTTP",
        status="OPEN",
        banner="nginx/1.18.0",
        version="1.18.0",
    )
    assert CPEResolver.resolve(pr_nginx) == "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"

    pr_ssh = PortResult(
        port=22,
        service="SSH",
        status="OPEN",
        banner="SSH-2.0-OpenSSH_8.2p1",
    )
    # Missing version normalized to '*'
    assert CPEResolver.resolve(pr_ssh) == "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"

    pr_vsftpd = PortResult(
        port=21,
        service="FTP",
        status="OPEN",
        banner="220 (vsFTPd 2.3.4)",
        version="2.3.4",
    )
    assert CPEResolver.resolve(pr_vsftpd) == "cpe:2.3:a:beasts:vsftpd:2.3.4:*:*:*:*:*:*:*"

    pr_proftpd = PortResult(
        port=21,
        service="FTP",
        status="OPEN",
        banner="220 ProFTPD 1.3.5 Server",
        version="1.3.5",
    )
    assert CPEResolver.resolve(pr_proftpd) == "cpe:2.3:a:proftpd:proftpd:1.3.5:*:*:*:*:*:*:*"

    pr_samba = PortResult(
        port=445,
        service="SMB",
        status="OPEN",
        banner="Samba 3.0.20",
        version="3.0.20",
    )
    assert CPEResolver.resolve(pr_samba) == "cpe:2.3:a:samba:samba:3.0.20:*:*:*:*:*:*:*"

    pr_mysql = PortResult(
        port=3306,
        service="MYSQL",
        status="OPEN",
        banner="MySQL Community Server 5.7.33",
        version="5.7.33",
    )
    assert CPEResolver.resolve(pr_mysql) == "cpe:2.3:a:mysql:mysql:5.7.33:*:*:*:*:*:*:*"

    pr_postgres = PortResult(
        port=5432,
        service="POSTGRESQL",
        status="OPEN",
        banner="PostgreSQL 13.2",
        version="13.2",
    )
    assert CPEResolver.resolve(pr_postgres) == "cpe:2.3:a:postgresql:postgresql:13.2:*:*:*:*:*:*:*"

    pr_bind = PortResult(
        port=53,
        service="DNS",
        status="OPEN",
        banner="ISC BIND 9.16.1",
        version="9.16.1",
    )
    assert CPEResolver.resolve(pr_bind) == "cpe:2.3:a:isc:bind:9.16.1:*:*:*:*:*:*:*"

    pr_postfix = PortResult(
        port=25,
        service="SMTP",
        status="OPEN",
        banner="220 mail.example.com ESMTP Postfix",
    )
    assert CPEResolver.resolve(pr_postfix) == "cpe:2.3:a:postfix:postfix:*:*:*:*:*:*:*:*"

    pr_unreal = PortResult(
        port=6667,
        service="IRC",
        status="OPEN",
        banner="UnrealIRCd-4.2.1",
        version="4.2.1",
    )
    assert CPEResolver.resolve(pr_unreal) == "cpe:2.3:a:unrealircd:unrealircd:4.2.1:*:*:*:*:*:*:*"

    # Version normalization (strip leading v/ver and lowercase)
    pr_norm = PortResult(
        port=80,
        service="HTTP",
        status="OPEN",
        banner="Apache/v2.4.41",
        version="v2.4.41",
    )
    assert CPEResolver.resolve(pr_norm) == "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"

    # Unknown services and generic banners return None (never guess vendor/product)
    pr_unknown = PortResult(
        port=9999,
        service="UNKNOWN",
        status="OPEN",
        banner="220 Welcome to custom server",
        version="1.0",
    )
    assert CPEResolver.resolve(pr_unknown) is None

    # Case variations
    pr_case = PortResult(
        port=80,
        service="HTTP",
        status="OPEN",
        banner="APACHE/2.4.41",
        version="2.4.41",
    )
    assert CPEResolver.resolve(pr_case) == "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"


def test_risk_scorer():
    pr_safe = PortResult(port=80, service="HTTP", status="OPEN")
    assert RiskScorer.score(pr_safe) == "Info"
    assert pr_safe.exposure_concern is None

    # Inherently risky protocol exposed (exposure concern separated from CVSS)
    pr_telnet = PortResult(port=23, service="TELNET", status="OPEN")
    assert RiskScorer.score(pr_telnet) == "Medium"
    assert pr_telnet.exposure_concern is not None
    assert "TELNET" in pr_telnet.exposure_concern

    # Multiple CVEs without CVSS score should NOT be labeled Critical
    pr_unscored = PortResult(
        port=80, service="HTTP", status="OPEN", cves=["CVE-1", "CVE-2"]
    )
    assert RiskScorer.score(pr_unscored) == "Medium"

    # CVSS base-score severity bands
    pr_critical = PortResult(
        port=80,
        service="HTTP",
        status="OPEN",
        vulnerabilities=[
            VulnerabilityInfo(cve_id="CVE-2023-1", cvss_score=9.8, cvss_version="3.1")
        ],
    )
    assert RiskScorer.score(pr_critical) == "Critical"

    pr_high = PortResult(
        port=80,
        service="HTTP",
        status="OPEN",
        vulnerabilities=[
            VulnerabilityInfo(cve_id="CVE-2023-2", cvss_score=7.5, cvss_version="3.1")
        ],
    )
    assert RiskScorer.score(pr_high) == "High"

    pr_med = PortResult(
        port=80,
        service="HTTP",
        status="OPEN",
        vulnerabilities=[
            VulnerabilityInfo(cve_id="CVE-2023-3", cvss_score=5.0, cvss_version="3.1")
        ],
    )
    assert RiskScorer.score(pr_med) == "Medium"

    pr_low = PortResult(
        port=80,
        service="HTTP",
        status="OPEN",
        vulnerabilities=[
            VulnerabilityInfo(cve_id="CVE-2023-4", cvss_score=2.0, cvss_version="3.1")
        ],
    )
    assert RiskScorer.score(pr_low) == "Low"

    pr_none = PortResult(
        port=80,
        service="HTTP",
        status="OPEN",
        vulnerabilities=[
            VulnerabilityInfo(cve_id="CVE-2023-5", cvss_score=0.0, cvss_version="3.1")
        ],
    )
    assert RiskScorer.score(pr_none) == "None"


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
    assert "CVE-2020-15778" in lookup.find_cves(
        cpe="cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"
    )

    # Test via Banner fallback
    assert "CVE-2020-15778" in lookup.find_cves(banner="SSH-2.0-OpenSSH_8.2p1")


def test_intelligence_engine():
    provider = MockCVEProvider()
    lookup = CVELookup(provider)
    engine = IntelligenceEngine(cve_lookup=lookup)

    pr = PortResult(
        port=22,
        service="SSH",
        status="OPEN",
        banner="SSH-2.0-OpenSSH_8.2p1",
        version="8.2p1",
    )
    results = engine.enrich([pr])

    assert results[0].cpe == "cpe:2.3:a:openbsd:openssh:8.2p1:*:*:*:*:*:*:*"
    assert results[0].risk == "Medium"  # Has 1 CVE without CVSS score
    assert len(results[0].mitre) > 0
    assert "CVE-2020-15778" in results[0].cves


# --- Comprehensive NVDProvider Unit Tests (Mocked) ---


@patch("portintel.intel.providers.requests.get")
def test_nvd_provider_success(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-44228",
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": "Apache Log4j2 remote code execution.",
                        }
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "version": "3.1",
                                    "baseScore": 10.0,
                                    "baseSeverity": "CRITICAL",
                                }
                            }
                        ]
                    },
                }
            }
        ]
    }
    mock_get.return_value = mock_response

    provider = NVDProvider()
    vulns = provider.get_vulnerabilities("apache log4j")
    assert len(vulns) == 1
    assert vulns[0].cve_id == "CVE-2021-44228"
    assert "Log4j2" in vulns[0].description
    assert vulns[0].cvss_score == 10.0
    assert vulns[0].cvss_version == "3.1"
    assert vulns[0].severity == "CRITICAL"


@patch("portintel.intel.providers.requests.get")
def test_nvd_provider_api_key_header(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"vulnerabilities": []}
    mock_get.return_value = mock_response

    with patch.object(config, "NVD_API_KEY", "test-secret-api-key"):
        provider = NVDProvider()
        provider.get_vulnerabilities("apache")
        _, kwargs = mock_get.call_args
        assert kwargs["headers"].get("apiKey") == "test-secret-api-key"

    with patch.object(config, "NVD_API_KEY", None):
        provider = NVDProvider()
        provider.get_vulnerabilities("apache")
        _, kwargs = mock_get.call_args
        assert "apiKey" not in kwargs["headers"]


@patch("portintel.intel.providers.time.sleep")
@patch("portintel.intel.providers.requests.get")
def test_nvd_provider_rate_limit_retry(mock_get, mock_sleep):
    # First call returns 429, second returns 200
    resp_429 = MagicMock()
    resp_429.status_code = 429
    resp_200 = MagicMock()
    resp_200.status_code = 200
    resp_200.json.return_value = {"vulnerabilities": []}

    mock_get.side_effect = [resp_429, resp_200]

    provider = NVDProvider()
    vulns = provider.get_vulnerabilities("nginx")
    assert vulns == []
    assert mock_get.call_count == 2
    mock_sleep.assert_called_once_with(1.0)


@patch("portintel.intel.providers.time.sleep")
@patch("portintel.intel.providers.requests.get")
def test_nvd_provider_rate_limit_exhausted(mock_get, mock_sleep):
    resp_403 = MagicMock()
    resp_403.status_code = 403

    mock_get.side_effect = [resp_403, resp_403, resp_403, resp_403]

    provider = NVDProvider()
    vulns = provider.get_vulnerabilities("nginx")
    assert vulns == []
    assert mock_get.call_count == 4  # Initial attempt + 3 retries


@patch("portintel.intel.providers.requests.get")
def test_nvd_provider_timeout_and_error(mock_get):
    mock_get.side_effect = requests.exceptions.Timeout("Timeout")
    provider = NVDProvider()
    assert provider.get_vulnerabilities("nginx") == []

    mock_get.side_effect = Exception("Unexpected")
    assert provider.get_vulnerabilities("nginx") == []


@patch("portintel.intel.providers.requests.get")
def test_nvd_provider_cvss_fallback(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2010-0001",
                    "descriptions": [{"lang": "en", "value": "Legacy bug."}],
                    "metrics": {
                        "cvssMetricV2": [
                            {
                                "cvssData": {
                                    "version": "2.0",
                                    "baseScore": 6.8,
                                },
                                "baseSeverity": "MEDIUM",
                            }
                        ]
                    },
                }
            }
        ]
    }
    mock_get.return_value = mock_response

    provider = NVDProvider()
    vulns = provider.get_vulnerabilities("legacy")
    assert len(vulns) == 1
    assert vulns[0].cvss_score == 6.8
    assert vulns[0].cvss_version == "2.0"
    assert vulns[0].severity == "MEDIUM"
