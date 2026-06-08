# normalizer.py
from .ingest import OpenCTIIngestor
from .client import ApiClient
from dotenv import load_dotenv

load_dotenv()


class OpenCTINormalizer:
    def __init__(self):
        self.api = ApiClient().api

    def _get_relationships(self, entity_id, relationship_type=None):
        relationships = self.api.stix_core_relationship.list(
            fromId = entity_id,
            relationship_type = relationship_type,
            first=2000
        )
        return relationships or []

    def _join_list(self, items):
        return ", ".join(items) if items else "N/A"

    # Normalizadores individuales de cada tipo de objeto
    def normalize_threat_actor(self, actor):
        uses_ttps = self._get_relationships(actor["id"], "uses")
        uses_malware = [
            r for r in uses_ttps if r.get("to", {}).get("entity_type") == "Malware"
        ]

        uses_attack_patterns = [
            r for r in uses_ttps if r.get("to", {}).get("entity_type") == "Attack-Pattern"
        ]

        ttps = [
            f"{r['to']['name']} ({r['to'].get('x_mitre_id','')})"
            for r in uses_attack_patterns if r.get("to")
        ]

        malware = [
            r["to"]["name"] for r in uses_malware if r.get("to")
        ]

        text = f"""
THREAT_ACTOR: {actor.get("name","N/A")}
Descripción: ´{actor.get("description","N/A")}

TTPs usados:
- {chr(10).join(ttps) if ttps else "N/A"}

Malware asociado:
- {chr(10).join(malware) if malware else "N/A"}

Creado: {actor.get("created","N/A")}
"""
        return text.strip()


    def normalize_malware(self, malware):
        relationships = self._get_relationships(malware["id"], "uses")

        ttps = [
            f"{r['to']['name']} ({r['to'].get('x_mitre_id','')})"
            for r in relationships if r.get("to",{}).get("entity_type") == "Attack-Pattern"
        ]

        text = f"""
MALWARE: {malware.get("name")}
Tipos: {self._join_list(malware.get("malware_types", []))}
Descripción: {malware.get("description", "N/A")}

TTPs usados:
- {chr(10).join(ttps) if ttps else "N/A"}

Creado: {malware.get("created")}
"""

        return text.strip()


    def normalize_attack_pattern(self,ttp):

        used_by = self._get_relationships(ttp["id"], "uses")
        actors = [
            r["from"]["name"] for r in used_by
            if r.get("from",{}).get("entity_type") == "Threat-Actor"
        ]

        text = f"""
TTP: {ttp.get("name")}
ID_MITRE: {ttp.get("x_mitre_id")}
Descripción: {ttp.get("description")}

Usado por:
- {chr(10).join(actors) if actors else "N/A"}

Creado: {ttp.get("created")}
"""

        return text.strip()


    def normalize_indicator(self, ioc):
        return f"""
INDICATOR (IOC)
Patrón: {ioc.get("pattern")}
Tipo: {ioc.get("pattern_type")}
Creado: {ioc.get("created")}
Válido desde: {ioc.get("valid_from")}
""".strip()


    def normalize_report(self, report):
        return f"""
REPORT: {report.get("name")}
Descripción: {report.get("description","N/A")}
Creado: {report.get("created")}
""".strip()


    def normalize_all_threat_actors(self, actors):
        return [self.normalize_threat_actor(a) for a in actors]

    def normalize_all_malware(self, malware):
        return [self.normalize_malware(m) for m in malware]

    def normalize_all_ttps(self, ttps):
        return [self.normalize_attack_pattern(t) for t in ttps]

    def normalize_all_reports(self, reports):
        return [self.normalize_report(r) for r in reports]

    def normalize_all_iocs(self, iocs):
        return [self.normalize_indicator(i) for i in iocs]


    def metadata_threat_actor(self, actor):
        return {
            "id": actor.get("id"),
            "name": actor.get("name"),
            "type": "Threat Actor"
        }

    def metadata_malware(self, malware):
        return {
            "id": malware.get("id"),
            "name": malware.get("name"),
            "type": "Malware"
        }

    def metadata_ttp(self, ttp):
        return {
            "id": ttp.get("id"),
            "name": ttp.get("name"),
            "type": "Attack-Pattern"
        }

    def metadata_report(self, report):
        return {
            "id": report.get("id"),
            "name": report.get("name"),
            "type": "Report"
        }

    def metadata_ioc(self, ioc):
        return {
            "id": ioc.get("id"),
            "type": "Indicator"
        }
