from unittest.mock import MagicMock, patch

from portintel.fingerprint.banner import BannerGrabber
from portintel.fingerprint.engine import FingerprintEngine
from portintel.fingerprint.service import ServiceDetector
from portintel.fingerprint.version import VersionParser
from portintel.models.schemas import PortResult


def test_service_detector():
    assert ServiceDetector.detect(80) == "HTTP"
    assert ServiceDetector.detect(443) == "HTTPS"
    assert ServiceDetector.detect(99999) == "UNKNOWN"

@patch("portintel.fingerprint.banner.socket.socket")
def test_banner_grabber(mock_socket):
    mock_sock_instance = MagicMock()
    mock_socket.return_value.__enter__.return_value = mock_sock_instance
    mock_sock_instance.recv.return_value = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"

    grabber = BannerGrabber()
    banner = grabber.grab("127.0.0.1", 22, timeout=1.0)

    assert "SSH-2.0-OpenSSH" in banner

def test_version_parser():
    assert VersionParser.parse("220 VMware Authentication Daemon Version 1.10: SSL Requir...") == "1.10"
    assert VersionParser.parse("OpenSSH_8.2p1") == "8.2p1"
    assert VersionParser.parse("Apache/2.4.41 (Ubuntu)") == "2.4.41"
    assert VersionParser.parse("No version here") is None

@patch.object(BannerGrabber, "grab")
def test_fingerprint_engine(mock_grab):
    mock_grab.return_value = "OpenSSH_8.2p1"

    engine = FingerprintEngine(timeout=1.0)
    ports = [PortResult(port=22, service="UNKNOWN", status="OPEN")]

    enriched = engine.enrich("127.0.0.1", ports, is_udp=False)

    assert enriched[0].service == "SSH"
    assert enriched[0].banner == "OpenSSH_8.2p1"
    assert enriched[0].version == "8.2p1"
