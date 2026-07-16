from unittest.mock import MagicMock, patch

from portintel.cli.orchestrator import Orchestrator
from portintel.models.schemas import PortResult


@patch("portintel.cli.orchestrator.scan_range_threaded")
@patch("portintel.cli.orchestrator.FingerprintEngine")
@patch("portintel.cli.orchestrator.IntelligenceEngine")
@patch("portintel.cli.orchestrator.ReportingEngine")
def test_cli_orchestrator_integration(mock_reporter, mock_intel, mock_fingerprint, mock_scan):
    # Setup Mocks
    mock_scan.return_value = [PortResult(port=80, service="UNKNOWN", status="OPEN")]

    mock_fingerprint_instance = MagicMock()
    mock_fingerprint_instance.enrich.return_value = [PortResult(port=80, service="HTTP", status="OPEN", banner="Server: Apache")]
    mock_fingerprint.return_value = mock_fingerprint_instance

    mock_intel_instance = MagicMock()
    mock_intel_instance.enrich.return_value = [PortResult(port=80, service="HTTP", status="OPEN", risk="Info", cpe="cpe:test")]
    mock_intel.return_value = mock_intel_instance

    mock_reporter_instance = MagicMock()
    mock_reporter.return_value = mock_reporter_instance

    orchestrator = Orchestrator(threads=1, timeout=1.0, is_udp=False, vuln_lookup=False, export_path="out.json")

    # Execute
    orchestrator.run_scan("127.0.0.1", 80, 80)

    # Verify Pipeline Flow
    mock_scan.assert_called_once()
    mock_fingerprint_instance.enrich.assert_called_once()
    mock_intel_instance.enrich.assert_called_once()
    mock_reporter_instance.report.assert_called_once()

@patch("portintel.cli.orchestrator.DiscoveryEngine")
def test_cli_discovery_integration(mock_discovery):
    mock_engine_instance = MagicMock()
    mock_engine_instance.sweep.return_value = []
    mock_discovery.return_value = mock_engine_instance

    orchestrator = Orchestrator(threads=1, timeout=1.0, is_udp=False, vuln_lookup=False)
    orchestrator.run_discovery("192.168.1.0/24")

    mock_engine_instance.sweep.assert_called_once_with("192.168.1.0/24")
