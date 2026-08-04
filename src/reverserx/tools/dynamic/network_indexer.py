"""Index captured HTTP flows into ChromaDB alongside source code for unified search."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

from reverserx.utils.proxy import CapturedFlow, redact_secrets, normalize_url


def flow_to_chunks(
    flow: CapturedFlow,
    chunk_size: int = 2_000,
) -> list[dict[str, Any]]:
    """Convert one captured HTTP flow into indexable text chunks.

    Each chunk carries metadata so context_query can filter and display
    network results alongside source code results.
    """
    chunks: list[dict[str, Any]] = []
    base_meta = {
        "kind": "network_flow",
        "flow_id": flow.id,
        "method": flow.method,
        "url": flow.url,
        "normalized_url": normalize_url(flow.url),
        "status": flow.status,
        "duration_ms": flow.duration_ms,
        "timestamp": flow.timestamp,
    }

    # Chunk 1: Request summary
    req_text = f"[NETWORK FLOW] {flow.method} {flow.url}\nStatus: {flow.status}\nDuration: {flow.duration_ms}ms\n"
    req_text += f"Request Headers:\n"
    for name, value in flow.request_headers.items():
        req_text += f"  {name}: {value}\n"
    if flow.request_body_hash:
        req_text += f"Request Body Hash: {flow.request_body_hash}\n"
    chunks.append(_make_chunk(req_text, {**base_meta, "chunk_type": "request_summary"}))

    # Chunk 2: Response summary
    resp_text = f"[NETWORK RESPONSE] {flow.method} {flow.url}\nStatus: {flow.status}\n"
    resp_text += f"Response Headers:\n"
    for name, value in flow.response_headers.items():
        resp_text += f"  {name}: {value}\n"
    if flow.response_body_hash:
        resp_text += f"Response Body Hash: {flow.response_body_hash}\n"
    chunks.append(_make_chunk(resp_text, {**base_meta, "chunk_type": "response_summary"}))

    return chunks


def flows_to_documents(
    flows: list[CapturedFlow],
) -> list[dict[str, Any]]:
    """Convert captured flows to ChromaDB-compatible documents."""
    docs: list[dict[str, Any]] = []
    for flow in flows:
        for chunk in flow_to_chunks(flow):
            docs.append({
                "id": _chunk_id(flow.id, chunk["metadata"]["chunk_type"]),
                "text": chunk["text"],
                "metadata": chunk["metadata"],
            })
    return docs


def index_flows_to_chroma(
    flows: list[CapturedFlow],
    collection_name: str,
    persist_dir: str,
) -> dict[str, Any]:
    """Index captured network flows into a ChromaDB collection.

    Uses the same embedding provider as the source index so context_query
    can search both source code and network traffic in one query.
    """
    try:
        import chromadb  # type: ignore[import-untyped]
    except ImportError:
        return {"error": "chromadb not installed", "indexed": 0}

    docs = flows_to_documents(flows)
    if not docs:
        return {"indexed": 0, "flows": len(flows)}

    client = chromadb.PersistentClient(path=persist_dir)
    try:
        collection = client.get_collection(collection_name)
    except Exception:
        collection = client.create_collection(
            name=collection_name,
            metadata={"kind": "network_flows", "description": "Captured HTTP/HTTPS traffic"},
        )

    # Upsert documents
    ids = [d["id"] for d in docs]
    texts = [d["text"] for d in docs]
    metadatas = [d["metadata"] for d in docs]

    # Batch to avoid memory issues with large captures
    batch_size = 500
    for i in range(0, len(ids), batch_size):
        batch_ids = ids[i : i + batch_size]
        batch_texts = texts[i : i + batch_size]
        batch_metas = metadatas[i : i + batch_size]
        try:
            collection.upsert(
                ids=batch_ids,
                documents=batch_texts,
                metadatas=batch_metas,
            )
        except Exception:
            # Fallback: add one by one
            for j in range(len(batch_ids)):
                try:
                    collection.upsert(
                        ids=[batch_ids[j]],
                        documents=[batch_texts[j]],
                        metadatas=[batch_metas[j]],
                    )
                except Exception:
                    pass

    return {
        "indexed": len(docs),
        "flows": len(flows),
        "collection": collection_name,
    }


def search_flows(
    query: str,
    collection_name: str,
    persist_dir: str,
    limit: int = 20,
) -> list[dict[str, Any]]:
    """Search indexed network flows by natural language query."""
    try:
        import chromadb  # type: ignore[import-untyped]
    except ImportError:
        return []

    client = chromadb.PersistentClient(path=persist_dir)
    try:
        collection = client.get_collection(collection_name)
    except Exception:
        return []

    try:
        results = collection.query(
            query_texts=[query],
            n_results=min(limit, collection.count()),
        )
    except Exception:
        return []

    hits: list[dict[str, Any]] = []
    if results and results.get("documents") and results["documents"][0]:
        for i, doc in enumerate(results["documents"][0]):
            meta = results["metadatas"][0][i] if results.get("metadatas") else {}
            dist = results["distances"][0][i] if results.get("distances") else 0
            hits.append({
                "text": str(doc)[:2000],
                "metadata": meta,
                "score": float(dist),
            })
    return hits


def _make_chunk(text: str, metadata: dict[str, Any]) -> dict[str, Any]:
    return {
        "text": text[:4_000],
        "metadata": metadata,
    }


def _chunk_id(flow_id: str, chunk_type: str) -> str:
    raw = f"{flow_id}:{chunk_type}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]
