import logging
from typing import Dict

from portintel.models.schemas import ScanSummary
from portintel.reporting.base import ReportStrategy
from portintel.reporting.console import ConsoleReport

logger = logging.getLogger(__name__)

class ReportingEngine:
    """
    Coordinates the generation of professional reports.
    Takes fully enriched data (ScanSummary) and delegates to active ReportStrategies
    via Dependency Injection.
    """
    def __init__(self):
        # Console output is always active by default
        self.strategies: Dict[str, ReportStrategy] = {
            "console": ConsoleReport()
        }

    def add_strategy(self, name: str, strategy: ReportStrategy):
        """
        Injects a new reporting strategy (e.g., HTML, PDF).
        """
        self.strategies[name] = strategy

    def report(self, summary: ScanSummary, filenames: Dict[str, str] = None):
        """
        Executes all configured reporting strategies using the fully enriched summary.
        """
        if filenames is None:
            filenames = {}

        logger.debug(f"Starting ReportingEngine with {len(self.strategies)} strategies.")

        for name, strategy in self.strategies.items():
            # Get the requested filename for this strategy, or empty string for console
            filename = filenames.get(name, "")
            try:
                strategy.generate(summary, filename)
            except Exception as e:
                logger.error(f"Error generating {name} report: {e}")
