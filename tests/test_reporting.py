import os
import tempfile
from datetime import datetime

import pytest

from portintel.models.schemas import PortResult, ScanSummary
from portintel.reporting.csv import CSVReport
from portintel.reporting.engine import ReportingEngine
from portintel.reporting.html import HTMLReport
from portintel.reporting.json import JSONReport
from portintel.reporting.markdown import MarkdownReport


@pytest.fixture
def sample_summary():
    dt = datetime.now()
    pr = PortResult(port=80, service="HTTP", status="OPEN", version="1.0", risk="Info", cpe="cpe:2.3:a:http:http:1.0:*:*:*:*:*:*:*")
    return ScanSummary(
        target="127.0.0.1",
        start_time=dt,
        end_time=dt,
        total_ports_scanned=10,
        open_ports_count=1,
        results=[pr]
    )

def test_json_report(sample_summary):
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "test.json")
        JSONReport().generate(sample_summary, path)
        assert os.path.exists(path)
        with open(path, "r") as f:
            content = f.read()
            assert "127.0.0.1" in content
            assert "HTTP" in content

def test_csv_report(sample_summary):
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "test.csv")
        CSVReport().generate(sample_summary, path)
        assert os.path.exists(path)
        with open(path, "r") as f:
            content = f.read()
            assert "Port,Service,Version" in content
            assert "80,HTTP,1.0" in content

def test_html_report(sample_summary):
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "test.html")
        HTMLReport().generate(sample_summary, path)
        assert os.path.exists(path)
        with open(path, "r") as f:
            content = f.read()
            assert "<!DOCTYPE html>" in content
            assert "127.0.0.1" in content

def test_markdown_report(sample_summary):
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "test.md")
        MarkdownReport().generate(sample_summary, path)
        assert os.path.exists(path)
        with open(path, "r") as f:
            content = f.read()
            assert "# PortIntel Security Assessment" in content

def test_reporting_engine(sample_summary):
    engine = ReportingEngine()
    engine.add_strategy("json", JSONReport())

    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "test.json")
        engine.report(sample_summary, {"json": path})
        assert os.path.exists(path)
