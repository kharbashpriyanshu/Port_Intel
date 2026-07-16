import requests
import urllib.parse
import logging
from typing import List
from portintel.config.settings import config

logger = logging.getLogger(__name__)

def check_vulnerabilities(banner: str) -> List[str]:
    """
    Queries the NIST NVD API for potential CVEs based on the software banner.
    Returns a list of CVE IDs.
    """
    if not banner or len(banner) < 4:
        return []
        
    # Extract the first two meaningful words to use as a search keyword
    # e.g., "SSH-2.0-OpenSSH_8.2p1" -> "OpenSSH 8.2p1"
    clean_banner = banner.replace("-", " ").replace("_", " ")
    keywords = " ".join(clean_banner.split()[:2])
    
    url = f"{config.NVD_API_URL}?keywordSearch={urllib.parse.quote(keywords)}&resultsPerPage=3"
    
    try:
        headers = {'User-Agent': config.USER_AGENT}
        logger.debug(f"Querying NVD API for keywords: {keywords}")
        
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
