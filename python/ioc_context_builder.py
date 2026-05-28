# ioc_context_builder.py
from typing import Dict, List

def _summarize_indicators(indicators: List[Dict]) -> List:
    summaries = []

    for ind in indicators:
        value = ind.get("name", "unknown")
        pattern = ind.get("pattern", "")
        confidence = ind.get("confidence", "N/A")
        revoked = ind.get("revoked", False)

        status = "Revoked" if revoked else "Active"

        summaries.append(
            f"- {value} ({status}, confidence: {confidence})"
        )
    return summaries

def _summarize_reports(reports: List[Dict]) -> List:
    summaries = []

    for rpt in reports:
        name = rpt.get("name", "Unnamed report")
        published = rpt.get("published", "unknown")
        confidence = rpt.get("confidence", "N/A")

        summaries.append(
            f"- {name} (published: {published}, confidence: {confidence})"
        )

    return summaries

def _safe(value, default="N/A"):
    if value is None:
        return default
    if value == "":
        return default
    return value

def _indicator_value(indicator: Dict) -> str:
    return (
        indicator.get("name")
        or indicator.get("value")
        or indicator.get("observable value")
        or "unknown"
    )

def _indicator_status(indicator: Dict) -> str:
    return "Revoked" if indicator.get("revoked") else "Active"

def _indicator_type(indicator: Dict) -> str:
    return (
        indicator.get("x_opencti_main_observable_type")
        or indicator.get("entity_type")
        or "Unknown"
    )

def _source_org(indicator: Dict) -> str:
    created_by = indicator.get("createdBy") or {}
    return created_by.get("name") or "N/A"

def _external_references(indicator: Dict) -> str:
    refs = indicator.get("externalReferences") or []
    output = []

    for ref in refs:
        description = ref.get("description")
        source_name = ref.get("source_name")
        url = ref.get("url")

        parts = []

        if source_name:
            parts.append(source_name)

        if description:
            parts.append(description)

        if url:
            parts.append(url)

        if parts:
            output.append(" | ".join(parts))

    return output

def _deduplicate_indicators(indicators: list[Dict]) -> list[Dict]:
    seen = set()
    result = []

    for indicator in indicators:
        value = _indicator_value(indicator)
        status = _indicator_status(indicator)
        confidence = indicator.get("confidence")
        pattern = indicator.get("pattern")

        key = (value, status, confidence, pattern)

        if key not in seen:
            seen.add(key)
            result.append(indicator)

    return result

def _render_indicator(indicator: Dict) -> str:
    value = _indicator_value(indicator)
    status = _indicator_status(indicator)
    observable_type = _indicator_type(indicator)

    lines = [
        f"- Indicator: {value}",
        f" Type: {_safe(observable_type)}"
        f" Status: {status}"
        f" Confidence: {_safe(indicator.get('confidence'))}"
    ]

    score = indicator.get("x_opencti_score")
    if score is not None:
        lines.append(f"  Score: {score}")

    detection = indicator.get("x_opencti_detection")
    if detection is not None:
        lines.append(f"  Detection: {detection}")

    pattern = indicator.get("pattern")
    if pattern:
        lines.append(f"  Pattern: {pattern}")

    description = indicator.get("description")
    if description:
        lines.append(f"  Description: {description}")

    valid_from = indicator.get("valid_from")
    if valid_from:
        lines.append(f"  Valid from: {valid_from}")

    valid_until = indicator.get("valid_until")
    if valid_until:
        lines.append(f"  Valid until: {valid_until}")

    source_org = _source_org(indicator)
    if source_org != "N/A":
        lines.append(f"  Source organization: {source_org}")

    markings = indicator.get("objectMarking") or []
    if markings:
        marking_values = [
            m.get("definition")
            for m in markings
            if m.get("definition")
        ]
        if marking_values:
            lines.append(f"  Marking: {','.join(marking_values)}")

    refs = _external_references(indicator)
    if refs:
        lines.append("  External references:")
        for ref in refs[:3]:
            lines.append(f"  - {ref}")

    return "\n".join(lines)

def build_ioc_context(ioc_context: Dict | None) -> str | None:
    if not ioc_context:
        return None

    ioc_value = ioc_context.get("ioc_value", "unknown")

    direct_indicators = ioc_context.get("direct_indicators") or []
    pattern_matches = ioc_context.get("pattern_matches") or []

    all_indicators = direct_indicators + pattern_matches
    unique_indicators = _deduplicate_indicators(all_indicators)

    lines = [
        "### IOC ANALYZED",
        f"- Value: {ioc_value}",
        f"- Direct pattern indicators found: {len(direct_indicators)}",
        f"- Pattern-based indicators found: {len(pattern_matches)}",
        f"- Unique indicators shown: {len(unique_indicators)}",
        "",
        "### INDICATORS ASSOCIATED WITH THIS IOC",
        "The following indicators are EXPLICITLY RELATED to this IOC according to OpenCTI.",
        ""
    ]

    if unique_indicators:
        for indicator in unique_indicators:
            lines.append(_render_indicator(indicator))
            lines.append("")
    else:
        lines.append("- No explicit indicators found.")
        lines.append("")

    related_reports = ioc_context.get("related_reports") or []
    if related_reports:
        lines.append("### RELATED REPORTS")
        for report in related_reports:
            name = report.get("name") or report.get("description") or report.get("id")
            lines.append(f"- {name}")

    return "\n".join(lines).strip()
