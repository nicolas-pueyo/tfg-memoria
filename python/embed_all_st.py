# embed_all_st.py
import os
import json
import numpy as np
from sentence_transformers import SentenceTransformer

DATA_ROOT = os.getenv("DATA_ROOT", "/opt/data")

NORMALIZED_DIR = f"{DATA_ROOT}/normalized"
EMB_DIR = f"{DATA_ROOT}/embeddings"

os.makedirs(EMB_DIR, exist_ok=True)

def load_texts_jsonl(filename):
    path = os.path.join(NORMALIZED_DIR, filename)
    texts = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            texts.append(json.loads(line)["text"])
    return texts


def load_metadata(filename):
        path = os.path.join(NORMALIZED_DIR, filename)
        metas = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                metas.append(json.loads(line))
        return metas

def save_embeddings(filename, vecs):
    path = os.path.join(EMB_DIR, filename)
    np.save(path,vecs)
    print(f"[✓] Guardado embeddings: {path} → shape={vecs.shape}")

def check_alignment(texts, metas, entity_type):
    if len(texts) != len(metas):
        raise ValueError(
                f"[ERROR] Desalineación en {entity_type}: {len(texts)} textos vs {len(metas)} metadatos"
        )
    print(f"[✓] Alineación OK para {entity_type}: {len(texts)} items")


if __name__ == "__main__":
    print("[+] Cargando modelo 'sentence-transformers/all-MiniLM-L6-v2...")
    model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")

    # Threat Actors
    actors_text = load_texts_jsonl("threat_actors.jsonl")
    actors_meta = load_metadata("threat_actors_meta.jsonl")
    check_alignment(actors_text, actors_meta, "Threat Actors")

    emb = model.encode(actors_text, batch_size=64, show_progress_bar=True)
    save_embeddings("threat_actors.npy", emb)


    # Malware
    malware_text = load_texts_jsonl("malware.jsonl")
    malware_meta = load_metadata("malware_meta.jsonl")
    check_alignment(malware_text, malware_meta, "Malware")

    emb = model.encode(malware_text, batch_size=64, show_progress_bar=True)
    save_embeddings("malware.npy", emb)


    # Attack Patterns
    ttps_text = load_texts_jsonl("attack_patterns.jsonl")
    ttps_meta = load_metadata("attack_patterns_meta.jsonl")
    check_alignment(ttps_text, ttps_meta, "TTPs")

    emb = model.encode(ttps_text, batch_size=64, show_progress_bar=True)
    save_embeddings("attack_patterns.npy", emb)


    # Reports
    reports_text = load_texts_jsonl("reports.jsonl")
    reports_meta = load_metadata("reports_meta.jsonl")
    check_alignment(reports_text, reports_meta, "Reports")

    emb = model.encode(reports_text, batch_size=64, show_progress_bar=True)
    save_embeddings("reports.npy", emb)


    # Indicators
    iocs_text = load_texts_jsonl("indicators.jsonl")
    iocs_meta = load_metadata("indicators_meta.jsonl")
    check_alignment(iocs_text, iocs_meta, "IOCs")

    emb = model.encode(iocs_text, batch_size=256, show_progress_bar=True)
    save_embeddings("indicators.npy", emb)
