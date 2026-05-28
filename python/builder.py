# builder.py
from typing import List
from rag.context.context_profiles import get_context_profile

# Si el contexto es grande y hay que recortar el contexto inferido, sacar información relevante en vez de un identificador ilegible.
def _extract_human_header(doc: str) -> str:
    lines = [l.strip() for l in doc.splitlines() if l.strip()]

    for line in lines:
        if ":" in line and not line.startswith("["):
            return line

    for line in lines:
        if not (line.startswith("[") and line.endswith("]")):
            return line

def _extract_section_items(lines: List[str], section_names: List[str]) -> List[str]:
    """
    Extrae elementos tipo lista bajo secciones como:
    - TTPs usados:
    - Malware asociado:
    - Threat actors asociados:
    """

    items = []
    capture = False

    normalized_sections = [s.lower() for s in section_names]

    for line in lines:
        lower = line.lower().strip()

        if any(lower.startswith(section) for section in normalized_sections):
            capture = True
            continue

        if capture and lower.endswith(":") and not line.startswith("-"):
            break

        if capture:
            if line.startswith("-"):
                value = line[1:].strip()
                if value and value.lower() not in ("n/a", "none", "null"):
                    items.append(value)
            elif line and not line.startswith("-"):
                break

    return items


def _extract_first_matching_line(lines: List[str], prefixes: List[str]) -> str | None:
    normalized_prefixes = [p.lower() for p in prefixes]

    for line in lines:
        lower = line.lower().strip()
        if any(lower.startswith(prefix) for prefix in normalized_prefixes):
               return line

    return None


def _extract_compact_context(doc: str) -> str:
    lines = [l.strip() for l in doc.splitlines() if l.strip()]

    if not lines:
        return "- CTI_OBJECT (empty document)"

    header = _extract_human_header(doc)

    description = _extract_first_matching_line(
        lines,
        [
            "descripción:",
            "descripcion:",
            "description:",
        ]
    )

    created = _extract_first_matching_line(
        lines,
        [
            "creado:",
            "created:",
        ]
    )

    modified = _extract_first_matching_line(
        lines,
        [
            "modificado:",
            "modified:",
            "updated",
        ]
    )

    ttps = _extract_section_items(
        lines,
        [
            "modificado:",
            "modified:",
            "updated:",
        ]
    )

    ttps = _extract_section_items(
        lines,
        [
            "ttps usdos:",
            "ttps:",
            "techniques:",
            "attack patterns:",
            "attack_patterns:",
        ]
    )

    malware = _extract_section_items(
        lines,
        [
            "malware asociado:",
            "associated malware:",
            "malware:",
        ]
    )

    threat_actors = _extract_section_items(
        lines,
        [
            "threat actors asociados:",
            "associated threat actors:",
            "threat actors:",
            "actors:",
        ]
    )

    reports = _extract_section_items(
        lines,
        [
            "reports asociados:",
            "associated reports",
            "reports",
        ]
    )

    indicators = _extract_section_items(
        lines,
        [
            "indicators asociados:",
            "indicadores asociados:",
            "associated indicators:",
            "indicators:",
            "indicadores:",
        ]
    )

    output = [f" - {header}"]

    if description:
        output.append(f"    {description}")

    if ttps:
        output.append(" TTPs / Techniques:")
        for item in ttps[:5]:
            output.append(f"    - {item}")

    if malware:
        output.append(" Associated malware:")
        for item in malware[:5]:
            output.append(f"    - {item}")

    if threat_actors:
        output.append(" Associated threat actors:")
        for item in threat_actors[:5]:
            output.append(f"    - {item}")

    if reports:
        output.append(" Associated reports:")
        for item in reports[:3]:
            output.append(f"    - {item}")

    if indicators:
        output.append(" Assciated indicators:")
        for item in indicators[:5]:
            output.append(f"    - {item}")

    if created:
        output.append(f"    {created}")

    if modified:
        output.append(f"    {modified}")

    return "\n".join(output)


def _prepare_contextual_docs(context_docs: List[str], detail: str) -> List[str]:
    if detail == "titles":
        return [_extract_human_header(doc) for doc in context_docs]

    if detail == "compact":
            return [_extract_compact_context(doc) for doc in context_docs]

    # Si el nivel de detalle es completo
    return context_docs

def build_final_context(
    *,
    ioc_context_text: str | None,
    context_docs: List[str],
    context_profile: str,
) -> str:
    profile = get_context_profile(context_profile)

    context_blocks = []
    # CONTEXTO FUERTE
    if ioc_context_text:
        context_blocks.append(
            f"{ioc_context_text}"
        )

    # CONTEXTO DÉBIL
    if context_docs:
        docs = context_docs[:profile["max_contextual_docs"]]
        docs = _prepare_contextual_docs(docs, profile["contextual_detail"])


        context_blocks.append(
            "### CONTEXTUAL CTI INFORMATION (INFERRED FROM SIMILARITY)\n"
            "The following CTI-related information is retrieved via semantic "
            "similarity search.\n"
            + "\n".join(docs)
        )

    return "\n\n".join(context_blocks)
