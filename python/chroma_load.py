# chroma_load.py
import os
import json
import numpy as np
from chromadb import HttpClient
from chromadb.config import Settings

DATA_ROOT = os.getenv("DATA_ROOT", "/opt/data")

NORMALIZED_DIR = f"{DATA_ROOT}/normalized"
EMB_DIR = f"{DATA_ROOT}/embeddings"

CHROMA_HOST = os.getenv("CHROMADB_HOST", "localhost")
CHROMA_PORT = int(os.getenv("CHROMADB_PORT", "8000"))

chroma = HttpClient (
    host=CHROMA_HOST,
    port=CHROMA_PORT
)

def load_texts_jsonl(filename):
    path = os.path.join(NORMALIZED_DIR, filename)
    texts = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            texts.append(json.loads(line)["text"])
    return texts

def load_metadata(filename):
    path = os.path.join(NORMALIZED_DIR, filename)
    meta = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            meta.append(json.loads(line))
    return meta

def load_embeddings(filename):
    path = os.path.join(EMB_DIR, filename)
    return np.load(path)


def create_or_get_collection(name):
    try:
        return chroma.get_collection(name=name)
    except:
        return chroma.create_collection(
            name=name,
            metadata={"hnsw:space":"cosine"}
        )

def insert_into_chroma(collection, embeddings, documents, metadata, batch=1000):
    print(f"[+] Insertando documento en lotes de {batch}...")
    total = len(documents)

    for i in range(0, total, batch):
        end = i + batch
        batch_embeddings = embeddings[i:end].tolist()
        batch_docs = documents[i:end]
        batch_meta = metadata[i:end]
        batch_ids = [m["id"] for m in batch_meta]

        collection.add(
            ids=batch_ids,
            embeddings=batch_embeddings,
            documents=batch_docs,
            metadatas=batch_meta
        )

        print(f"    {end}/{total} insertados")


if __name__ == "__main__":
    print("=== CARGA A CHROMADB ===")

    tipos = ["threat_actors", "malware", "attack_patterns", "reports", "indicators"]

    for t in tipos:
        print(f"\n=== {t.upper()} ===")

        collection = create_or_get_collection(t)

        texts = load_texts_jsonl(f"{t}.jsonl")
        meta = load_metadata(f"{t}_meta.jsonl")
        emb = load_embeddings(f"{t}.npy")

        if len(texts) != len(meta) or len(texts) != emb.shape[0]:
            raise ValueError(
                    f"[ERROR] Desalineación en {t}: {len(texts)} textos, {len(meta)} metadatos, {emb.shape[0]} embeddings"
            )

        insert_into_chroma(
                collection,
                embeddings=emb,
                documents=texts,
                metadata=meta,
                batch = 1000 if t != "indicators" else 5000
        )

        print(f"[✓] {t} cargados.\n")
