# ingest.py
import os
import json
from dotenv import load_dotenv
from .client import ApiClient

load_dotenv()

DATA_ROOT=os.getenv("DATA_ROOT", "/opt/data")
RAW_DIR=f"{DATA_ROOT}/raw/opencti"
os.makedirs(RAW_DIR, exist_ok=True)

class OpenCTIIngestor:
    def __init__(self):
        self.api = ApiClient().api

    def _save_json(self, filename,data):
        path = os.path.join(RAW_DIR, filename)

        with open(path, 'w', encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        print(f"[✓] Guardado en {path} ({len(data)} objetos)")

    def _ingest_entities(self, list_function, label, first=200, custom_attributes=None):
        """
        Método general para ingerir entidades desde OpenCTI usando paginación oficial:
        - withPagination=True
        - pagination.hasNextPage / endCursor
        - data["entities"] devuelto por pycti
        """
        print(f"\n[+] Iniciando ingesta de {label}...")

        all_entities = []
        data = {"pagination": {"hasNextPage": True, "endCursor": None}}

        while data["pagination"]["hasNextPage"]:
            after = data["pagination"]["endCursor"]

            # Llamada oficial según documentación OpenCTI
            data = list_function(
                first=first,
                after=after,
                customAttributes=custom_attributes,
                withPagination=True,
                orderBy="created_at",
                orderMode="asc",
            )

            if not data or "entities" not in data:
                print(f"[!] Error obteniendo datos para {label}")
                break

            batch = data["entities"]
            all_entities.extend(batch)

            print(f"    - Descargados {len(batch)} nuevos ({len(all_entities)} total)")

        print(f"[✓] Ingesta completada: {label} ({len(all_entities)} objetos)")
        return all_entities



    def ingest_threat_actors(self):
        custom = """
            id
            name
            description
            created
        """
        data = self._ingest_entities(self.api.threat_actor.list, "Threat Actors", 200, custom)

        self._save_json("threat_actors.json", data)
        return data

    def ingest_malware(self):
        custom = """
            id
            name
            malware_types
            description
            created
        """
        data = self._ingest_entities(self.api.malware.list, "Malware", 200, custom)

        self._save_json("malware.json", data)
        return data

    def ingest_attack_patterns(self):
        custom = """
            id
            name
            x_mitre_id
            description
            created
        """
        data = self._ingest_entities(self.api.attack_pattern.list, "Attack Patterns", 200, custom)

        self._save_json("attack_patterns.json", data)
        return data

    def ingest_indicators(self):
        custom = """
            id
            pattern
            pattern_type
            created
            valid_from
        """
        data = self._ingest_entities(self.api.indicator.list, "Indicators (IOCs)", 200, custom)

        self._save_json("indicators.json", data)
        return data


    def ingest_reports(self):
        custom = """
            id
            name
            description
            created
        """
        data = self._ingest_entities(self.api.report.list, "Reports", 100, custom)

        self._save_json("reports.json", data)
        return data


if __name__ == "__main__":
    ingestor = OpenCTIIngestor()

    actors = ingestor.ingest_threat_actors()
    malware = ingestor.ingest_malware()
    ttps = ingestor.ingest_attack_patterns()
    iocs = ingestor.ingest_indicators()
    reports = ingestor.ingest_reports()

    print("\n=== RESUMEN FINAL ===")
    print(f"  Threat Actors: {len(actors)}")
    print(f"  Malware:       {len(malware)}")
    print(f"  TTPs:          {len(ttps)}")
    print(f"  IOCs:          {len(iocs)}")
    print(f"  Reports:       {len(reports)}")
