# 📸 PortIntel Screenshot Generation Guide

This placeholder document describes the visual assets needed for the public `README.md` repository.

Maintainers: Before publicly publishing the repository, please capture the following screenshots and save them in `docs/assets/`.

---

## 1. CLI Help Output (`docs/assets/cli-help.png`)
**How to capture:**
Run `portintel help`.
**Focus:** 
Ensure the professional banner, color-coded headers (DESCRIPTION, COMMANDS, EXAMPLES), and standard formatting are visible. Shows the polished UX.

## 2. Console Scan Execution (`docs/assets/cli-scan.png`)
**How to capture:**
Run `portintel scan --target 127.0.0.1 --start 130 --end 920`.
**Focus:**
Capture the `SCAN SUMMARY` box. Make sure the color-coding on the `RISK` column is visible (e.g., green `Info`, red `Critical`). Emphasizes the CLI UX improvements.

## 3. HTML Assessment Report (`docs/assets/html-report.png`)
**How to capture:**
Run a scan with `--export reports/demo.html`. Open the file in Chrome/Firefox.
**Focus:**
Capture the clean, minimalist CSS design. Show the Executive Summary (Target, Total Time, Open Ports) and the color-coded Vulnerabilities table. Highlights PortIntel's enterprise-readiness.

## 4. JSON Output File (`docs/assets/json-report.png`)
**How to capture:**
Run a scan with `--export reports/demo.json`. Open in VSCode with JSON formatting enabled.
**Focus:**
Show the cleanly nested schema:
```json
{
  "metadata": {
    "target": "127.0.0.1",
    "total_ports_scanned": 1000,
    "open_ports_count": 4
  },
  "findings": [
    {
      "port": 135,
      "service": "EPMAP",
      "cpe": "cpe:2.3:a:epmap:epmap:*:*:*:*:*:*:*:*"
    }
  ]
}
```
Highlights ease of SIEM/API integration.

## 5. Markdown Report (`docs/assets/markdown-report.png`)
**How to capture:**
Run a scan with `--export reports/demo.md`. Open in GitHub or a Markdown previewer.
**Focus:**
Shows the neat tables and formatting, perfect for attaching to DevOps Jira tickets or GitHub Issues.
