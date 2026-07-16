from unittest.mock import MagicMock, patch

from portintel.discovery.engine import DiscoveryEngine
from portintel.discovery.icmp import ICMPDiscoveryStrategy
from portintel.models.schemas import HostResult


@patch("portintel.discovery.icmp.subprocess.run")
def test_icmp_discovery_alive(mock_run):
    mock_run.return_value = MagicMock(returncode=0)

    strategy = ICMPDiscoveryStrategy()
    result = strategy.discover("192.168.1.1", timeout=1.0)

    assert isinstance(result, HostResult)
    assert result.ip == "192.168.1.1"
    assert result.is_alive is True

@patch("portintel.discovery.icmp.subprocess.run")
def test_icmp_discovery_dead(mock_run):
    mock_run.return_value = MagicMock(returncode=1)

    strategy = ICMPDiscoveryStrategy()
    result = strategy.discover("192.168.1.2", timeout=1.0)

    assert result is None

@patch("portintel.discovery.engine.DiscoveryStrategy")
def test_discovery_engine(mock_strategy):
    instance = mock_strategy.return_value
    instance.discover.side_effect = lambda ip, timeout: HostResult(ip=ip, is_alive=True) if ip == "192.168.1.5" else None

    engine = DiscoveryEngine(strategy=instance, threads=2, timeout=1.0)
    # Testing a /30 subnet gives 4 IPs (.0, .1, .2, .3)
    results = engine.sweep("192.168.1.4/30")

    # Only 192.168.1.5 should be alive based on our mock
    assert len(results) == 1
    assert results[0].ip == "192.168.1.5"
