"""Local embedding adapters and Chroma-backed semantic retrieval."""

from __future__ import annotations

import hashlib
import importlib
import json
import math
import re
import urllib.error
import urllib.request
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field

TOKEN_PATTERN = re.compile(r"[A-Za-z_$][A-Za-z0-9_$.-]*|[0-9]+")


class EmbeddingError(RuntimeError):
    """Raised when embeddings or the vector index are unavailable."""


class EmbeddingProvider(Protocol):
    name: str
    dimensions: int

    def embed(self, texts: Sequence[str]) -> list[list[float]]: ...


class SemanticDocument(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    text: str
    metadata: dict[str, str | int | float | bool] = Field(default_factory=dict)


class SemanticMatch(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    score: float = Field(ge=0, le=1)
    text: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class HashingEmbeddingProvider:
    """Dependency-free, deterministic local fallback using hashed code tokens.

    This provider captures lexical and sub-token similarity; it is intentionally
    not presented as a learned semantic model. It keeps indexing functional when
    Ollama or another local embedding runtime is unavailable.
    """

    name = "local-hashing-v1"

    def __init__(self, dimensions: int = 384) -> None:
        if dimensions < 32:
            raise ValueError("embedding dimensions must be at least 32")
        self.dimensions = dimensions

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        return [self._embed_one(text) for text in texts]

    def _embed_one(self, text: str) -> list[float]:
        vector = [0.0] * self.dimensions
        tokens = _tokens(text)
        features = tokens + [
            f"{left}::{right}" for left, right in zip(tokens, tokens[1:], strict=False)
        ]
        for feature in features:
            digest = hashlib.blake2b(feature.encode("utf-8"), digest_size=16).digest()
            index = int.from_bytes(digest[:8], "big") % self.dimensions
            sign = 1.0 if digest[8] & 1 else -1.0
            vector[index] += sign
        norm = math.sqrt(sum(value * value for value in vector))
        if norm:
            vector = [value / norm for value in vector]
        return vector


class OllamaEmbeddingProvider:
    """Local Ollama embedding adapter using the `/api/embed` endpoint."""

    def __init__(
        self,
        model: str = "nomic-embed-text",
        endpoint: str = "http://127.0.0.1:11434",
        timeout: float = 60.0,
    ) -> None:
        self.model = model
        self.endpoint = endpoint.rstrip("/")
        self.timeout = timeout
        self.name = f"ollama:{model}"
        self.dimensions = 0

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        if not texts:
            return []
        payload = json.dumps({"model": self.model, "input": list(texts)}).encode()
        request = urllib.request.Request(
            f"{self.endpoint}/api/embed",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310
                parsed = json.loads(response.read().decode("utf-8"))
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
            raise EmbeddingError(f"Ollama embedding request failed: {exc}") from exc
        embeddings = parsed.get("embeddings") if isinstance(parsed, dict) else None
        if not isinstance(embeddings, list) or len(embeddings) != len(texts):
            raise EmbeddingError("Ollama returned an invalid embeddings response")
        vectors = [[float(value) for value in vector] for vector in embeddings]
        dimensions = len(vectors[0]) if vectors else 0
        if dimensions == 0 or any(len(vector) != dimensions for vector in vectors):
            raise EmbeddingError("Ollama returned inconsistent embedding dimensions")
        self.dimensions = dimensions
        return vectors


class MemoryVectorIndex:
    """Small deterministic vector index used for tests and tiny projects."""

    def __init__(self, embedding_provider: EmbeddingProvider) -> None:
        self.embedding_provider = embedding_provider
        self._documents: dict[str, SemanticDocument] = {}
        self._vectors: dict[str, list[float]] = {}

    def rebuild(self, documents: Sequence[SemanticDocument]) -> None:
        self._documents = {document.id: document for document in documents}
        vectors = self.embedding_provider.embed(
            [document.text for document in documents]
        )
        self._vectors = {
            document.id: vector
            for document, vector in zip(documents, vectors, strict=True)
        }

    def query(self, text: str, limit: int = 10) -> list[SemanticMatch]:
        if limit < 1:
            raise ValueError("limit must be positive")
        query_vector = self.embedding_provider.embed([text])[0]
        scored = [
            (document_id, _cosine(query_vector, vector))
            for document_id, vector in self._vectors.items()
        ]
        scored.sort(key=lambda item: (-item[1], item[0]))
        return [
            SemanticMatch(
                id=document_id,
                score=max(0.0, min(1.0, (score + 1.0) / 2.0)),
                text=self._documents[document_id].text,
                metadata=self._documents[document_id].metadata,
            )
            for document_id, score in scored[:limit]
        ]


class ChromaVectorIndex:
    """Persistent Chroma lifecycle using caller-supplied local embeddings."""

    def __init__(
        self,
        path: Path,
        collection_key: str,
        embedding_provider: EmbeddingProvider,
        *,
        source_fingerprint: str | None = None,
        store_documents: bool = True,
    ) -> None:
        self.path = path.expanduser().resolve()
        self.embedding_provider = embedding_provider
        self.collection_identity = vector_collection_identity(
            collection_key,
            source_fingerprint or collection_key,
            embedding_provider.name,
            store_documents=store_documents,
        )
        self.collection_name = _collection_name(self.collection_identity)
        self.store_documents = store_documents
        self.path.mkdir(parents=True, exist_ok=True)
        try:
            chromadb = importlib.import_module("chromadb")
        except ImportError as exc:  # pragma: no cover - optional dependency path
            raise EmbeddingError(
                "ChromaDB is not installed; run `uv sync --extra phase1`"
            ) from exc
        self._client = chromadb.PersistentClient(path=str(self.path))

    def rebuild(self, documents: Sequence[SemanticDocument]) -> bool:
        """Build the deterministic collection, or reuse it when already complete.

        The source fingerprint and provider are part of the collection identity, so
        changed input is built beside the last complete collection. A collection
        with the expected physical count is immutable and reusable. Only an
        incomplete collection for the same identity is reset.

        Returns ``True`` when records were written and ``False`` when a complete
        collection was reused.
        """

        expected_count = len(documents)
        existing = self._get_collection_or_none()
        if existing is not None:
            try:
                if int(existing.count()) == expected_count:
                    return False
            except Exception as exc:
                raise EmbeddingError(
                    f"cannot inspect Chroma collection: {exc}"
                ) from exc

        try:
            if existing is not None:
                self._client.delete_collection(self.collection_name)
        except Exception as exc:
            raise EmbeddingError(f"cannot reset Chroma collection: {exc}") from exc
        collection = self._client.get_or_create_collection(
            self.collection_name,
            metadata={
                "reverserx_embedding": self.embedding_provider.name,
                "reverserx_identity": self.collection_identity,
            },
        )
        try:
            for batch in _batches(documents, 2_000):
                vectors = self.embedding_provider.embed(
                    [document.text for document in batch]
                )
                upsert_arguments: dict[str, Any] = {
                    "ids": [document.id for document in batch],
                    "embeddings": vectors,
                    "metadatas": [document.metadata for document in batch],
                }
                if self.store_documents:
                    upsert_arguments["documents"] = [
                        document.text for document in batch
                    ]
                collection.upsert(
                    **upsert_arguments,
                )
            actual_count = int(collection.count())
        except Exception as exc:
            raise EmbeddingError(f"cannot build Chroma collection: {exc}") from exc
        if actual_count != expected_count:
            raise EmbeddingError(
                "Chroma collection is incomplete: "
                f"expected {expected_count} documents, found {actual_count}"
            )
        return True

    def count(self) -> int:
        """Return the collection's physical record count."""

        collection = self._get_collection_or_none()
        if collection is None:
            raise EmbeddingError("Chroma collection is unavailable")
        try:
            return int(collection.count())
        except Exception as exc:
            raise EmbeddingError(f"cannot inspect Chroma collection: {exc}") from exc

    def query(self, text: str, limit: int = 10) -> list[SemanticMatch]:
        if limit < 1:
            raise ValueError("limit must be positive")
        collection = self._get_collection_or_none()
        if collection is None:
            raise EmbeddingError("Chroma collection is unavailable")
        try:
            if int(collection.count()) == 0:
                return []
        except Exception as exc:
            raise EmbeddingError(f"cannot inspect Chroma collection: {exc}") from exc
        included_fields = ["metadatas", "distances"]
        if self.store_documents:
            included_fields.append("documents")
        response = collection.query(
            query_embeddings=self.embedding_provider.embed([text]),
            n_results=limit,
            include=included_fields,
        )
        ids = _first_list(response.get("ids"))
        documents = _first_list(response.get("documents"))
        metadatas = _first_list(response.get("metadatas"))
        distances = _first_list(response.get("distances"))
        matches: list[SemanticMatch] = []
        for index, document_id in enumerate(ids):
            distance = float(distances[index]) if index < len(distances) else 1.0
            matches.append(
                SemanticMatch(
                    id=str(document_id),
                    score=max(0.0, min(1.0, 1.0 - distance / 2.0)),
                    text=str(documents[index]) if index < len(documents) else "",
                    metadata=(
                        dict(metadatas[index])
                        if index < len(metadatas) and isinstance(metadatas[index], dict)
                        else {}
                    ),
                )
            )
        return matches

    def _get_collection_or_none(self) -> Any | None:
        try:
            return self._client.get_collection(self.collection_name)
        except Exception as exc:
            message = str(exc).lower()
            if "does not exist" in message or "not found" in message:
                return None
            raise EmbeddingError(f"Chroma collection is unavailable: {exc}") from exc


def _tokens(text: str) -> list[str]:
    tokens: list[str] = []
    for raw in TOKEN_PATTERN.findall(text):
        normalized = raw.lower()
        tokens.append(normalized)
        tokens.extend(
            part.lower()
            for part in re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)|[0-9]+", raw)
            if part.lower() != normalized
        )
    return tokens


def _cosine(left: Sequence[float], right: Sequence[float]) -> float:
    if len(left) != len(right):
        raise EmbeddingError("embedding dimension mismatch")
    return sum(a * b for a, b in zip(left, right, strict=True))


def _collection_name(key: str) -> str:
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:24]
    return f"rx_{digest}"


def vector_collection_identity(
    index_id: str,
    source_fingerprint: str,
    embedding_provider: str,
    *,
    store_documents: bool | None = None,
) -> str:
    """Return the stable identity shared by persisted vector metadata."""

    identity: dict[str, str | bool] = {
        "embedding_provider": embedding_provider,
        "index_id": index_id,
        "source_fingerprint": source_fingerprint,
    }
    if store_documents is not None:
        identity["store_documents"] = store_documents
    return json.dumps(identity, sort_keys=True, separators=(",", ":"))


def chroma_collection_name(
    index_id: str,
    source_fingerprint: str,
    embedding_provider: str,
    *,
    store_documents: bool = True,
) -> str:
    """Return the deterministic Chroma name without opening its database."""

    return _collection_name(
        vector_collection_identity(
            index_id,
            source_fingerprint,
            embedding_provider,
            store_documents=store_documents,
        )
    )


def memory_collection_name(
    index_id: str, source_fingerprint: str, embedding_provider: str
) -> str:
    """Return a deterministic readiness identity for the ephemeral backend."""

    identity = vector_collection_identity(
        index_id, source_fingerprint, embedding_provider
    )
    return f"memory:{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:24]}"


def _batches(
    values: Sequence[SemanticDocument], size: int
) -> Iterable[Sequence[SemanticDocument]]:
    for start in range(0, len(values), size):
        yield values[start : start + size]


def _first_list(value: Any) -> list[Any]:
    if isinstance(value, list) and value and isinstance(value[0], list):
        return list(value[0])
    return []
