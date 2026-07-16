# Contributing to PortIntel

Thank you for your interest in contributing! We welcome bug reports, feature requests, and pull requests.

## Development Setup
1. Clone the repository
2. Install development dependencies: `pip install -r requirements-dev.txt`
3. Run tests before submitting a PR: `pytest`
4. Lint code using: `ruff check portintel/`

## Architecture Rules
- Do not bypass the `Scanner Engine`. All port results must flow sequentially.
- Implement new discovery or reporting methods using the established Strategy Patterns (`DiscoveryStrategy`, `ReportStrategy`).
- Maintain backward compatibility where possible.
