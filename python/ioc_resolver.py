# ioc_resolver.py
from typing import Dict, List
import re

def extract_ioc_value(question: str) -> str:
    url_match = re.search(r"https?://[^\s\"'<>]+", question)
    if url_match:
        print(f"URL matcheada: {url_match.group(0)}")
        return url_match.group(0)

    sha256_match = re.search(r"\b[a-fA-F0-9]{64}\b", question)
    if sha256_match:
        print(f"SHA256 matcheado: {sha256_match.group(0)}")
        return sha256_match.group(0)

    sha1_match = re.search(r"\b[a-fA-F0-9]{40}\b", question)
    if sha1_match:
        print(f"SHA1 matcheado: {sha1_match.group(0)}")
        return sha1_match.group(0)

    md5_match = re.search(r"\b[a-fA-F0-9]{32}\b", question)
    if md5_match:
        print(f"MD5 matcheado: {md5_match.group(0)}")
        return md5_match.group(0)

    ip_match = re.search(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        question,
    )
    if ip_match:
        print(f"IPv4 matcheada: {ip_match.group(0)}")
        return ip_match.group(0)

    domain_match = re.search(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", question)
    if domain_match:
        print(f"Dominio matcheado: {domain_match.group(0)}")
        return domain_match.group(0)

    return ""


def resolve_ioc(ioc_value: str, opencti_client) -> Dict:
    result = {
        "ioc_value": ioc_value,
        "direct_indicators": [],
        "pattern_matches": [],
        "related_reports": [],
    }

    direct = opencti_client.find_indicators_by_value(ioc_value)
    result["direct_indicators"] = direct

    pattern_matches = opencti_client.find_indicators_by_pattern(ioc_value)
    result["pattern_matches"] = pattern_matches

    reports = opencti_client.find_reports_mentioning(ioc_value)
    result["related_reports"] = reports

    return result
