import re
from typing import Optional


class VersionParser:
    """
    Dedicated module for extracting reliable version numbers from banners.
    """
    @staticmethod
    def parse(banner: Optional[str]) -> Optional[str]:
        """
        Extracts a version number from a raw string banner.
        Returns the version string, or None if no reliable version was found.
        """
        if not banner:
            return None

        # Basic, reliable regex for versions (e.g. OpenSSH_8.2, Apache/2.4.41, 1.10)
        # Matches formats like 'version 1.2', 'v2.0', 'software/3.4.1', '8.2p1'
        match = re.search(r'(?i)(?:version|v)?\s*[\/_-]?\s*([0-9]+\.[0-9]+[a-zA-Z0-9\.\-]*)', banner)
        if match:
            return match.group(1)

        return None
