import abc
import requests
import urllib.parse
import logging
from typing import List
from portintel.config.settings import config

logger = logging.getLogger(__name__)

class CVEProvider(abc.ABC):
    """
    Abstract Base Class for CVE lookup providers.
    Allows for future providers (like Vulners or a Local DB) to be plugged in seamlessly.
    """
    @abc.abstractmethod
    def get_cves(self, keyword: str) -> List[str]:
        pass

class NVDProvider(CVEProvider):
    """
    Concrete implementation of CVEProvider utilizing the NIST NVD REST API.
    """
    def get_cves(self, keyword: str) -> List[str]:
        if not keyword:
            return []
            
        url = f"{config.NVD_API_URL}?keywordSearch={urllib.parse.quote(keyword)}&resultsPerPage=3"
        
        try:
            headers = {'User-Agent': config.USER_AGENT}
            logger.debug(f"Querying NVD API for keyword: {keyword}")
            
            response = requests.get(url, headers=headers, timeout=config.NVD_TIMEOUT)
            
            if response.status_code == 200:
                data = response.json()
                cves = []
                for item in data.get("vulnerabilities", []):
                    cve_id = item.get("cve", {}).get("id")
                    if cve_id:
                        cves.append(cve_id)
                return cves
            elif response.status_code == 403:
                logger.warning("NVD API request forbidden. You may have hit a rate limit.")
            else:
                logger.warning(f"NVD API returned unexpected status code: {response.status_code}")
                
        except requests.exceptions.Timeout:
            logger.warning("NVD API request timed out.")
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error while querying NVD API: {e}")
        except Exception as e:
            logger.error(f"Unexpected error while querying NVD API: {e}")
            
        return []
