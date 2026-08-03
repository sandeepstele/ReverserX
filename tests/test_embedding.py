from reverserx.context.embedding import (
    HashingEmbeddingProvider,
    MemoryVectorIndex,
    SemanticDocument,
)


def test_hashing_embeddings_are_deterministic_and_normalized() -> None:
    provider = HashingEmbeddingProvider(dimensions=64)

    first = provider.embed(["EncryptionManager encryptRequest"])[0]
    second = provider.embed(["EncryptionManager encryptRequest"])[0]

    assert first == second
    assert len(first) == 64
    assert abs(sum(value * value for value in first) - 1.0) < 1e-9


def test_memory_index_ranks_related_code_first() -> None:
    index = MemoryVectorIndex(HashingEmbeddingProvider(dimensions=128))
    index.rebuild(
        [
            SemanticDocument(
                id="crypto",
                text="EncryptionManager encryptRequest AES Cipher SecretKeySpec",
                metadata={"path": "crypto/EncryptionManager.java"},
            ),
            SemanticDocument(
                id="ui",
                text="ProfileActivity render avatar layout button",
                metadata={"path": "ui/ProfileActivity.java"},
            ),
        ]
    )

    matches = index.query("request encryption cipher", limit=2)

    assert [match.id for match in matches] == ["crypto", "ui"]
    assert matches[0].score > matches[1].score
    assert matches[0].metadata["path"] == "crypto/EncryptionManager.java"


def test_empty_text_has_a_stable_zero_vector() -> None:
    provider = HashingEmbeddingProvider(dimensions=32)

    assert provider.embed([""])[0] == [0.0] * 32
