import abc

from portintel.models.schemas import ScanSummary


class ReportStrategy(abc.ABC):
    """
    Abstract Base Class for reporting strategies.
    Ensures all report generators implement the generate() method identically.
    """
    @abc.abstractmethod
    def generate(self, summary: ScanSummary, filename: str = "") -> None:
        pass
