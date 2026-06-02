import requests
import urllib.parse

def check_vulnerabilities(banner: str) -> list:
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
    
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={urllib.parse.quote(keywords)}&resultsPerPage=3"
    
    try:
        headers = {'User-Agent': 'PortIntel-Scanner'}
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            cves = []
            for item in data.get("vulnerabilities", []):
                cve_id = item["cve"]["id"]
                cves.append(cve_id)
            return cves
    except Exception:
        # Silently fail if the API is down or times out
        return []
        
    return []
