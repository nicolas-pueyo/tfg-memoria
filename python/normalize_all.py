# normalize_all.py
import os
import json
from dotenv import load_dotenv

from .normalizer import OpenCTINormalizer

load_dotenv()

DATA_ROOT = os.getenv("DATA_ROOT", "/opt/data")

RAW_DIR = f"{DATA_ROOT}/raw/opencti"
NORMALIZED_DIR = f"{DATA_ROOT}/normalized"

os.makedirs(NORMALIZED_DIR, exist_ok=True)


def load_json(filename):
    path = os.path.join(RAW_DIR, filename)
    if not os.path.exists(path):
        print(f"[!] No existe el fichero: {path}")
        return []
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_normalized_jsonl(filename, texts):
    path = os.path.join(NORMALIZED_DIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        for t in texts:
            f.write(json.dumps({"text": t}) + "\n")
        print(f"[ ] Guardado JSONL: {path} ({len(texts)} documentos)")

def save_metadata(filename, metas):
    path = os.path.join(NORMALIZED_DIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        for m in metas:
            f.write(json.dumps(m) + "\n")
    print(f"[✓] Guardado JSONL: {path} ({len(metas)} metadatos)")

if __name__ == "__main__":
    normalizer = OpenCTINormalizer()

    print("=== NORMALIZANDO ENTIDADES ===\n")

    actors_raw = load_json("threat_actors.json")
    actors_text = normalizer.normalize_all_threat_actors(actors_raw)
    actors_meta = [normalizer.metadata_threat_actor(a) for a in actors_raw]

    save_normalized_jsonl("threat_actors.jsonl", actors_text)
    save_metadata("threat_actors_meta.jsonl", actors_meta)


    malware_raw = load_json("malware.json")
    malware_text = normalizer.normalize_all_malware(malware_raw)
    malware_meta = [normalizer.metadata_malware(m) for m in malware_raw]

    save_normalized_jsonl("malware.jsonl", malware_text)
    save_metadata("malware_meta.jsonl", malware_meta)


    ttps_raw = load_json("attack_patterns.json")
    ttps_text = normalizer.normalize_all_ttps(ttps_raw)
    ttps_meta = [normalizer.metadata_ttp(t) for t in ttps_raw]

    save_normalized_jsonl("attack_patterns.jsonl", ttps_text)
    save_metadata("attack_patterns_meta.jsonl", ttps_meta)


    iocs_raw = load_json("indicators.json")
    iocs_text = normalizer.normalize_all_iocs(iocs_raw)
    iocs_meta = [normalizer.metadata_ioc(i) for i in iocs_raw]

    save_normalized_jsonl("indicators.jsonl", iocs_text)
    save_metadata("indicators_meta.jsonl", iocs_meta)


    reports_raw = load_json("reports.json")
    reports_text = normalizer.normalize_all_reports(reports_raw)
    reports_meta = [normalizer.metadata_report(r) for r in reports_raw]

    save_normalized_jsonl("reports.jsonl", reports_text)
    save_metadata("reports_meta.jsonl", reports_meta)

    print("=== NORMALIZACIÓN COMPLETADA ===\n")
