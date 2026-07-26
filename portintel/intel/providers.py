import abc
import logging
import time
import urllib.parse
from typing import List

import requests

from portintel.config.settings import config
from portintel.models.schemas import VulnerabilityInfo

logger = logging.getLogger(__name__)


class CVEProvider(abc.ABC):
    """
    Abstract Base Class for CVE lookup providers.
    Allows for future providers (like Vulners or a Local DB) to be plugged in seamlessly.
    """
    @abc.abstractmethod
    def get_cves(self, keyword: str) -> List[str]:
        pass

    def get_vulnerabilities(self, keyword: str) -> List[VulnerabilityInfo]:
        """
        Returns structured vulnerability information.
        Default implementation wraps get_cves(keyword) into basic VulnerabilityInfo objects.
        """
        return [VulnerabilityInfo(cve_id=cve) for cve in self.get_cves(keyword)]


class NVDProvider(CVEProvider):
    """
    Concrete implementation of CVEProvider utilizing the NIST NVD REST API 2.0.
    Supports optional NVD_API_KEY, bounded exponential backoff on rate limits (403/429),
    and structured CVSS v3.1/v3.0/v2.0 parsing.
    """
    def get_vulnerabilities(self, keyword: str) -> List[VulnerabilityInfo]:
        if not keyword:
            return []

        url = f"{config.NVD_API_URL}?keywordSearch={urllib.parse.quote(keyword)}&resultsPerPage=3"
        headers = {"User-Agent": config.USER_AGENT}
        if config.NVD_API_KEY:
            headers["apiKey"] = config.NVD_API_KEY

        max_retries = 3
        base_delay = 1.0

        for attempt in range(max_retries + 1):
            try:
                logger.debug(
                    f"Querying NVD API for keyword: {keyword} "
                    f"(Authenticated: {bool(config.NVD_API_KEY)})"
                )

                response = requests.get(
                    url, headers=headers, timeout=config.NVD_TIMEOUT
                )

                if response.status_code == 200:
                    data = response.json()
                    vulnerabilities: List[VulnerabilityInfo] = []

                    for item in data.get("vulnerabilities", []):
                        cve_data = item.get("cve", {})
                        cve_id = cve_data.get("id")
                        if not cve_id:
                            continue

                        # Extract description (prefer English)
                        description = None
                        for desc in cve_data.get("descriptions", []):
                            if desc.get("lang") == "en":
                                description = desc.get("value")
                                break
                        if not description and cve_data.get("descriptions"):
                            description = cve_data.get("descriptions")[0].get("value")

                        # Extract CVSS metrics (prefer v3.1 -> v3.0 -> v2.0)
                        cvss_score = None
                        cvss_version = None
                        severity = None
                        metrics = cve_data.get("metrics", {})

                        for ver_key, ver_label in [
                            ("cvssMetricV31", "3.1"),
                            ("cvssMetricV30", "3.0"),
                            ("cvssMetricV2", "2.0"),
                        ]:
                            metric_list = metrics.get(ver_key, [])
                            if (
                                metric_list
                                and isinstance(metric_list, list)
                                and len(metric_list) > 0
                            ):
                                metric_item = metric_list[0]
                                cvss_data = metric_item.get("cvssData", {})
                                cvss_score = cvss_data.get("baseScore")
                                cvss_version = ver_label
                                severity = cvss_data.get(
                                    "baseSeverity"
                                ) or metric_item.get("baseSeverity")
                                if cvss_score is not None:
                                    try:
                                        cvss_score = float(cvss_score)
                                    except (ValueError, TypeError):
                                        cvss_score = None
                                break

                        vulnerabilities.append(
                            VulnerabilityInfo(
                                cve_id=cve_id,
                                description=description,
                                cvss_score=cvss_score,
                                cvss_version=cvss_version,
                                severity=severity,
                            )
                        )
                    return vulnerabilities

                elif response.status_code in (403, 429):
                    if attempt < max_retries:
                        delay = base_delay * (2**attempt)
                        logger.warning(
                            f"NVD API rate limit encountered (status {response.status_code}). "
                            f"Retrying in {delay}s..."
                        )
                        time.sleep(delay)
                        continue
                    else:
                        logger.warning(
                            f"NVD API rate limit retry attempts exhausted for keyword: {keyword}"
                        )
                        return []
                else:
                    logger.warning(
                        f"NVD API returned unexpected status code: {response.status_code}"
                    )
                    return []

            except requests.exceptions.Timeout:
                logger.warning(f"NVD API request timed out for keyword: {keyword}")
                return []
            except requests.exceptions.RequestException:
                logger.error("Network error while querying NVD API.")
                return []
            except Exception:
                logger.error("Unexpected error while querying NVD API.")
                return []

        return []

    def get_cves(self, keyword: str) -> List[str]:
        return [v.cve_id for v in self.get_vulnerabilities(keyword)]
