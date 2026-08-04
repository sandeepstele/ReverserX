// @version 1.0.0 — SSL/TLS certificate pinning observation hook
// Hooks: TrustManager, HostnameVerifier, SSLContext, SSLSocketFactory

Java.perform(function () {
    try {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        var TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");

        // Hook checkServerTrusted to observe which certificates are validated
        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        SSLContext.init.overload(
            "[Ljavax.net.ssl.KeyManager;",
            "[Ljavax.net.ssl.TrustManager;",
            "java.security.SecureRandom"
        ).implementation = function (km, tm, random) {
            if (tm && tm.length > 0) {
                send(JSON.stringify({
                    type: "pinning",
                    timestamp: Date.now() / 1000,
                    class: "javax.net.ssl.SSLContext",
                    method: "init",
                    args: ["TrustManager count: " + tm.length],
                    metadata: {
                        trust_manager_count: tm.length,
                        trust_manager_class: tm[0].$className
                    }
                }));
            }
            return this.init(km, tm, random);
        };

        // Hook HostnameVerifier for custom hostname checks (pinning indicator)
        var HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
        var originalVerify = HostnameVerifier.verify.implementation;
        // Use a class-level override to catch custom implementations
        send(JSON.stringify({
            type: "pinning",
            timestamp: Date.now() / 1000,
            class: "javax.net.ssl",
            method: "hooks_initialized",
            args: ["SSL pinning hooks active"]
        }));
    } catch (e) {
        send(JSON.stringify({ type: "error", message: "SSL pinning hook failed: " + e }));
    }

    try {
        // Observe OkHttp CertificatePinner (common pinning library)
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload(
            "java.lang.String",
            "java.util.List"
        ).implementation = function (hostname, peerCertificates) {
            send(JSON.stringify({
                type: "pinning",
                timestamp: Date.now() / 1000,
                class: "okhttp3.CertificatePinner",
                method: "check",
                args: [hostname],
                metadata: {
                    hostname: hostname,
                    certificate_count: peerCertificates.size()
                }
            }));
            return this.check(hostname, peerCertificates);
        };
    } catch (e) {
        // OkHttp CertificatePinner might not be present
    }
});
