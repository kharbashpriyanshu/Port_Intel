import re
from dataclasses import dataclass
from typing import List, Optional

from portintel.models.schemas import PortResult


@dataclass
class CPEMappingRule:
    vendor: str
    product: str
    patterns: List[str]  # Regex patterns to match in banner


def _word_pat(word: str) -> str:
    return rf"(?:^|[^a-z0-9]){word}(?:[^a-z0-9]|$)"


class CPEResolver:
    """
    Reusable resolver to build Common Platform Enumeration (CPE) 2.3 identifiers.
    Uses fingerprint evidence (banner and version) to match known vendors and products.
    Returns None when evidence is insufficient to avoid fabricating incorrect CPEs.
    """
    RULES = [
        CPEMappingRule("apache", "http_server", [_word_pat("apache")]),
        CPEMappingRule("nginx", "nginx", [_word_pat("nginx")]),
        CPEMappingRule("openbsd", "openssh", [_word_pat("openssh")]),
        CPEMappingRule("beasts", "vsftpd", [_word_pat("vsftpd")]),
        CPEMappingRule("proftpd", "proftpd", [_word_pat("proftpd")]),
        CPEMappingRule("samba", "samba", [_word_pat("samba"), _word_pat("smbd")]),
        CPEMappingRule("mysql", "mysql", [_word_pat("mysql")]),
        CPEMappingRule("postgresql", "postgresql", [_word_pat("postgresql"), _word_pat("postgres")]),
        CPEMappingRule("isc", "bind", [_word_pat("bind"), _word_pat("named"), r"isc\s+bind"]),
        CPEMappingRule("postfix", "postfix", [_word_pat("postfix")]),
        CPEMappingRule("unrealircd", "unrealircd", [_word_pat("unrealircd"), r"unreal\s*3\.", r"unreal\s*4\."]),
    ]

    @classmethod
    def add_rule(cls, vendor: str, product: str, patterns: List[str]) -> None:
        """
        Programmatically registers a new CPE mapping rule.
        """
        cls.RULES.append(CPEMappingRule(vendor, product, patterns))

    @staticmethod
    def normalize_version(version: Optional[str]) -> str:
        """
        Normalizes a version string for CPE 2.3 format.
        Returns '*' if version is missing, empty, or invalid.
        """
        if not version:
            return "*"
        ver = version.strip().lower()
        # Remove leading 'v' or 'ver' if followed by digit
        ver = re.sub(r"^(?:ver|v)?[\s\-_/]*([0-9].*)$", r"\1", ver)
        # Remove invalid CPE characters
        ver = re.sub(r"[^a-z0-9\.\-\_]", "", ver)
        return ver if ver else "*"

    @classmethod
    def resolve(cls, pr: PortResult) -> Optional[str]:
        """
        Attempts to generate a CPE 2.3 formatted string based on fingerprint evidence.
        Format: cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*

        Returns None if fingerprint evidence is insufficient or unrecognized.
        Never fabricates a vendor/product solely from generic service names.
        """
        if not pr.banner and not pr.version:
            return None

        banner_text = (pr.banner or "").lower()

        matched_rule: Optional[CPEMappingRule] = None
        for rule in cls.RULES:
            for pattern in rule.patterns:
                if re.search(pattern, banner_text, re.IGNORECASE):
                    matched_rule = rule
                    break
            if matched_rule:
                break

        if not matched_rule:
            # Do not guess a vendor/product when fingerprint evidence is insufficient
            return None

        version = cls.normalize_version(pr.version)

        return f"cpe:2.3:a:{matched_rule.vendor}:{matched_rule.product}:{version}:*:*:*:*:*:*:*"
