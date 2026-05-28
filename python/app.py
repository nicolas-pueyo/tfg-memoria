# app.py
from fastapi import FastAPI, Request, HTTPException
import json
from typing import Dict, Optional, Any, List
import os
import logging

from sentence_transformers import SentenceTransformer
from chromadb import HttpClient

from rag.ioc_resolver import extract_ioc_value, resolve_ioc
from rag.ioc_context_builder import build_ioc_context
from opencti.rag_client import OpenCTIRAGClient
from rag.context.builder import build_final_context

logger = logging.getLogger(__name__)
opencti_rag_client = OpenCTIRAGClient()

CHROMADB_HOST = os.getenv("CHROMADB_HOST", "localhost")
CHROMADB_PORT = int(os.getenv("CHROMADB_PORT", "8000"))

TOP_K = int(os.getenv("TOP_K", "5"))

COLLECTIONS = [
    "threat_actors",
    "malware",
    "attack_patterns",
    "reports",
    "indicators"
]

app = FastAPI(
        title="CTI RAG Server",
        description="RAG backend sobre OpenCTI usando ChromaDB y embeddings MiniLM",
        version="1.0.0"
)


embedder = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")

chroma = HttpClient(
    host=CHROMADB_HOST,
    port=CHROMADB_PORT
)

def embed_query(text:str) -> List[float]:
    return embedder.encode([text])[0].tolist()

def retrieve_context(query: str) -> List[str]:
    vector = embed_query(query)
    context_docs = []

    for collection_name in COLLECTIONS:
        try:
            collection = chroma.get_collection(collection_name)
            res = collection.query(
                query_embeddings=[vector],
                n_results=TOP_K
            )

            for doc, meta in zip(res["documents"][0], res["metadatas"][0]):
                doc_id = meta.get("id", "unknown")
                context_docs.append(f"[{doc_id}]\n{doc}")
        except Exception:
            continue
    return context_docs


@app.post("/query-context",  tags=["RAG"])
async def query_rag(request: Request):
    raw_body = await request.body()

    try:
        payload = json.loads(raw_body)
        print(json.dumps(payload, indent=2))
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="El body recibido no es JSON válido"
        )

    question = payload.get("query")


    if not isinstance(question, str) or not question.strip():
        raise HTTPException(
            status_code=422,
            detail="No se recibió una pregunta válida"
        )

    question = question.strip()

    context_profile = payload.get("context_profile", "small")

    # Obtención de contexto por ChromaDB

    ioc_context = None
    ioc_context_text = None

    ioc_value = extract_ioc_value(question)

    if not ioc_value:
        raise HTTPException(
            status_code=422,
            detail="No se encontró ningún indicador válido en la pregunta"
        )

    print(f"[RAG] Detected IOC value: {ioc_value}")


    # resolve_ioc devuele en un objeto el ioc y lo que encuentre por coincidencia directa de valor, patrón o mención
    ioc_context = resolve_ioc(ioc_value, opencti_rag_client)

    print("[RAG] IOC RESOLUTION RESULT:")
    print(ioc_context)

    #build_ioc_context recibe el objeto de contexto creado antes y devuelve como string formateado el contexto objetivo
    ioc_context_text = build_ioc_context(ioc_context)

    context_docs = retrieve_context(f"{ioc_value} threat actor malware infrastructure")

    if not context_docs and not ioc_context_text:
        raise HTTPException(
            status_code=404,
            detail="No se encontró contexto relevante en OpenCTI"
        )


    final_context = build_final_context(
        ioc_context_text=ioc_context_text,
        context_docs=context_docs,
        context_profile=context_profile
    )

    print("[DEBUG] Final context returned")
    print(final_context)
    print("[DEBUG] End context")

    return {
        "context": final_context
    }
