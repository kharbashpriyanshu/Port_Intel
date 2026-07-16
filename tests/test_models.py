from datetime import datetime

from portintel.models.schemas import HostResult, PortResult, ScanSummary


def test_port_result_defaults():
    pr = PortResult(port=80, service="HTTP", status="OPEN")
    assert pr.port == 80
    assert pr.service == "HTTP"
    assert pr.status == "OPEN"
    assert pr.banner is None
    assert pr.version is None
    assert pr.cpe is None
    assert pr.risk is None
    assert pr.mitre == []
    assert pr.cves == []

def test_host_result_defaults():
    hr = HostResult(ip="192.168.1.1", is_alive=True)
    assert hr.ip == "192.168.1.1"
    assert hr.is_alive is True
    assert hr.open_ports == []

def test_scan_summary():
    dt = datetime.now()
    summary = ScanSummary(
        target="10.0.0.1",
        start_time=dt,
        end_time=dt,
        total_ports_scanned=100,
        open_ports_count=0
    )
    assert summary.target == "10.0.0.1"
    assert summary.total_ports_scanned == 100
    assert summary.results == []
