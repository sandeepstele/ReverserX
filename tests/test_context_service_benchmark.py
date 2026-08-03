from collections.abc import Sequence
from pathlib import Path

from reverserx.context.benchmark import (
    BenchmarkCase,
    RetrievedItem,
    assert_benchmark_thresholds,
    evaluate_benchmark,
)
from reverserx.context.service import ContextService
from reverserx.core.models import Project
from reverserx.storage import Database
from reverserx.storage.context import ContextRepository

SOURCES = {
    "crypto/CryptoEngine.java": """
        package fixture.crypto;
        class CryptoEngine {
          byte[] sealOutbound(byte[] payload) {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            return cipher.doFinal(payload);
          }
          byte[] openInbound(byte[] ciphertext) {
            GCMParameterSpec parameters = parseNonce(ciphertext);
            return decryptCipher(parameters).doFinal(ciphertext);
          }
        }
    """,
    "auth/AuthTokenStore.kt": """
        package fixture.auth
        class AuthTokenStore {
          fun authorizationValue(token: String) = "Bearer $token"
          fun renewSession(refreshToken: String) = oauthClient.refresh(refreshToken)
        }
    """,
    "network/CertificatePolicy.java": """
        package fixture.network;
        class CertificatePolicy {
          void verifyPeer(String host, Certificate cert) { pinSet.check(host, cert); }
          void updatePins(List<String> pins) { pinStore.replaceAtomically(pins); }
        }
    """,
    "network/RequestSigner.kt": """
        package fixture.network
        class RequestSigner {
          fun signBody(body: ByteArray) = mac("HmacSHA256", body)
          fun canonicalHeaders(headers: Map<String,String>) = headers.toSortedMap()
        }
    """,
    "storage/SecretVault.java": """
        package fixture.storage;
        class SecretVault {
          Key deriveMaster(char[] passphrase) { return scrypt(passphrase, deviceSalt); }
          void persistSecret(byte[] secret) { encryptedPreferences.put("secret", secret); }
        }
    """,
    "ui/ImageCache.kt": """
        package fixture.ui
        class ImageCache {
          fun decodeProfile(bytes: ByteArray) = bitmapDecoder.decode(bytes)
          fun purgeStale(now: Long) = entries.removeIf { it.expiresAt < now }
        }
    """,
    "analytics/EventQueue.java": """
        package fixture.analytics;
        class EventQueue {
          void recordTelemetry(Event event) { durableQueue.enqueue(event); }
          void uploadBatch() { gzip(batch()).sendToCollector(); }
        }
    """,
    "config/FeatureFlags.kt": """
        package fixture.config
        class FeatureFlags {
          fun enabled(name: String) = snapshot[name] ?: false
          fun applyRemote(config: JsonObject) = snapshot.replace(parseFlags(config))
        }
    """,
    "smali/fixture/NativeBridge.smali": """
        .class public Lfixture/NativeBridge;
        .super Ljava/lang/Object;
        .method public computeNativeTag([B)[B
            .locals 1
            const-string v0, "native_hmac_tag"
            return-object p1
        .end method
        .method public loadHardwareKey()Ljava/lang/String;
            .locals 1
            const-string v0, "android_keystore_alias"
            return-object v0
        .end method
    """,
    "routing/DeepLinkRouter.java": """
        package fixture.routing;
        class DeepLinkRouter {
          Uri parseIncoming(String link) { return Uri.parse(link).normalizeScheme(); }
          Screen chooseDestination(Uri uri) { return routeTable.match(uri.getPath()); }
        }
    """,
}


CASES = (
    (
        "outbound-cipher",
        "Where are outbound bytes sealed with AES GCM doFinal?",
        "crypto/CryptoEngine.java",
    ),
    (
        "inbound-decrypt",
        "Which logic parses a nonce and opens inbound ciphertext?",
        "crypto/CryptoEngine.java",
    ),
    (
        "bearer-header",
        "How is the Bearer authorization value assembled?",
        "auth/AuthTokenStore.kt",
    ),
    (
        "oauth-refresh",
        "Where does an OAuth refresh token renew a session?",
        "auth/AuthTokenStore.kt",
    ),
    (
        "peer-pin",
        "Which code checks a host certificate against a pin set?",
        "network/CertificatePolicy.java",
    ),
    (
        "pin-update",
        "Where are certificate pins replaced atomically?",
        "network/CertificatePolicy.java",
    ),
    (
        "body-hmac",
        "How is a request body signed with HmacSHA256?",
        "network/RequestSigner.kt",
    ),
    (
        "header-canonical",
        "Where are headers sorted into canonical order?",
        "network/RequestSigner.kt",
    ),
    (
        "master-key",
        "Which method derives a master key with scrypt and device salt?",
        "storage/SecretVault.java",
    ),
    (
        "secret-store",
        "Where is a secret written to encrypted preferences?",
        "storage/SecretVault.java",
    ),
    (
        "avatar-decode",
        "Which code decodes profile image bytes into a bitmap?",
        "ui/ImageCache.kt",
    ),
    (
        "cache-purge",
        "Where are expired image cache entries removed?",
        "ui/ImageCache.kt",
    ),
    (
        "telemetry-enqueue",
        "How is a telemetry event placed on the durable queue?",
        "analytics/EventQueue.java",
    ),
    (
        "analytics-upload",
        "Where is an analytics batch compressed and sent to a collector?",
        "analytics/EventQueue.java",
    ),
    (
        "flag-read",
        "Where does snapshot[name] decide whether a flag is enabled?",
        "config/FeatureFlags.kt",
    ),
    (
        "flag-update",
        "Where is remote JSON parsed to replace feature flags?",
        "config/FeatureFlags.kt",
    ),
    (
        "native-tag",
        "Find the native HMAC tag computation bridge.",
        "smali/fixture/NativeBridge.smali",
    ),
    (
        "hardware-key",
        "Where is the Android keystore alias loaded?",
        "smali/fixture/NativeBridge.smali",
    ),
    (
        "link-parse",
        "Which code normalizes the scheme of an incoming deep link?",
        "routing/DeepLinkRouter.java",
    ),
    (
        "route-match",
        "Where does a URI path select its destination screen?",
        "routing/DeepLinkRouter.java",
    ),
)


def test_production_context_service_meets_twenty_question_retrieval_floor(
    tmp_path: Path,
) -> None:
    database = Database(tmp_path / "state.sqlite3")
    database.initialize()
    project = database.create_project(Project(slug="benchmark", name="Benchmark"))
    source_root = tmp_path / "projects" / project.id / "sources"
    for relative, source in SOURCES.items():
        path = source_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
    service = ContextService(ContextRepository(database), tmp_path / "vectors")
    service.build(
        project_id=project.id,
        source_root=source_root,
        vector_backend="memory",
    )

    def retrieve(query: str, limit: int) -> Sequence[RetrievedItem]:
        result = service.query(
            project_id=project.id,
            query=query,
            token_budget=10_000,
            limit=limit,
            vector_backend="memory",
        )
        return tuple(
            RetrievedItem(
                chunk_id=match.chunk_id,
                path=match.path,
                score=match.score,
            )
            for match in result.matches
        )

    summary = evaluate_benchmark(
        tuple(
            BenchmarkCase(
                case_id=case_id,
                query=query,
                expected_paths=(expected_path,),
            )
            for case_id, query, expected_path in CASES
        ),
        retrieve,
        cutoffs=(1, 3, 5),
    )

    assert summary.case_count == 20
    assert_benchmark_thresholds(
        summary,
        minimum_hit_at_k={1: 0.9, 3: 1.0, 5: 1.0},
        minimum_mean_reciprocal_rank=0.95,
    )
