import os
import tempfile
from datetime import datetime

import pytest

from portintel.models.schemas import PortResult, ScanSummary, VulnerabilityInfo
from portintel.reporting.console import ConsoleReport
from portintel.reporting.csv import CSVReport
from portintel.reporting.engine import ReportingEngine
from portintel.reporting.html import HTMLReport
from portintel.reporting.json import JSONReport
from portintel.reporting.markdown import MarkdownReport
from portintel.reporting.pdf import PDFReport


@pytest.fixture
def sample_summary():
    dt = datetime.now()
    vuln = VulnerabilityInfo(
        cve_id="CVE-2023-9999",
        description="Test vuln description",
        cvss_score=9.8,
        cvss_version="3.1",
        severity="CRITICAL",
    )
    pr = PortResult(
        port=80,
        service="HTTP",
        status="OPEN",
        version="1.0",
        risk="Critical",
        cpe="cpe:2.3:a:apache:http_server:1.0:*:*:*:*:*:*:*",
        cvss_score=9.8,
        cvss_version="3.1",
        exposure_concern="Insecure service exposed",
        vulnerabilities=[vuln],
        cves=["CVE-2023-9999"],
        mitre=["Initial Access"],
    )
    return ScanSummary(
        target="127.0.0.1",
        start_time=dt,
        end_time=dt,
        total_ports_scanned=10,
        open_ports_count=1,
        results=[pr],
    )


def test_json_report(sample_summary):
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "test.json")
        JSONReport().generate(sample_summary, path)
        assert os.path.exists(path)
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
            assert "127.0.0.1" in content
            assert "HTTP" in content
            assert "9.8" in content
            assert "Insecure service exposed" in content


def test_csv_report(sample_summary):
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "test.csv")
        CSVReport().generate(sample_summary, path)
        assert os.path.exists(path)
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
            assert "Port,Service,Version" in content
            assert "80,HTTP,1.0" in content
            assert "9.8" in content
            assert "Insecure service exposed" in content


def test_html_report(sample_summary):
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "test.html")
        HTMLReport().generate(sample_summary, path)
        assert os.path.exists(path)
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
            assert "<!DOCTYPE html>" in content
            assert "127.0.0.1" in content
            assert "9.8" in content
            assert "Insecure service exposed" in content


def test_markdown_report(sample_summary):
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "test.md")
        MarkdownReport().generate(sample_summary, path)
        assert os.path.exists(path)
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
            assert "# PortIntel Security Assessment" in content
            assert "9.8" in content
            assert "Insecure service exposed" in content


def test_pdf_report(sample_summary):
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "test.txt")
        PDFReport().generate(sample_summary, path)
        assert os.path.exists(path)
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
            assert "PORTINTEL SECURITY ASSESSMENT" in content
            assert "9.8" in content
            assert "Insecure service exposed" in content


def test_console_report(sample_summary):
    ConsoleReport().generate(sample_summary, "")
    # Testing that console report executes cleanly without error
    empty_summary = ScanSummary(
        target="127.0.0.1",
        start_time=datetime.now(),
        end_time=datetime.now(),
        total_ports_scanned=10,
        open_ports_count=0,
        results=[],
    )
    ConsoleReport().generate(empty_summary, "")


def test_reporting_engine(sample_summary):
    engine = ReportingEngine()
    engine.add_strategy("json", JSONReport())
    engine.add_strategy("pdf", PDFReport())

    with tempfile.TemporaryDirectory() as tmpdir:
        json_path = os.path.join(tmpdir, "test.json")
        pdf_path = os.path.join(tmpdir, "test.txt")
        engine.report(sample_summary, {"json": json_path, "pdf": pdf_path})
        assert os.path.exists(json_path)
        assert os.path.exists(pdf_path)
