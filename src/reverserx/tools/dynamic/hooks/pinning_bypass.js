// @version 1.0.0 — SSL/TLS certificate pinning bypass for authorized security assessment
// Overrides TrustManager, HostnameVerifier, and OkHttp CertificatePinner
// WARNING: Only use on apps you own or have explicit authorization to test.

Java.perform(function () {
    // --- 1. Bypass javax.net.ssl TrustManager ---
    try {
        var TrustManager = Java.registerClass({
            name: 'com.reverserx.PermissiveTrustManager',
            implements: [Java.use('javax.net.ssl.X509TrustManager')],
            methods: {
                checkClientTrusted: function (chain, authType) {},
                checkServerTrusted: function (chain, authType) {},
                getAcceptedIssuers: function () { return []; }
            }
        });

        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var TrustManagerFactory = Java.use('javax.net.ssl.TrustManagerFactory');
        var permissiveTM = [TrustManager.$new()];

        // Hook SSLContext.init to swap in permissive TrustManager
        var originalInit = SSLContext.init;
        SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;',
            '[Ljavax.net.ssl.TrustManager;',
            'java.security.SecureRandom'
        ).implementation = function (km, tm, random) {
            send(JSON.stringify({
                type: 'pinning_bypass',
                timestamp: Date.now() / 1000,
                class: 'javax.net.ssl.SSLContext',
                method: 'init',
                metadata: { action: 'trust_manager_replaced', original_tm_count: tm ? tm.length : 0 }
            }));
            return originalInit.call(this, km, permissiveTM, random);
        };

        send(JSON.stringify({
            type: 'pinning_bypass',
            timestamp: Date.now() / 1000,
            class: 'reverserx',
            method: 'init',
            metadata: { status: 'ssl_trust_manager_bypass_active' }
        }));
    } catch (e) {
        send(JSON.stringify({
            type: 'pinning_bypass_error',
            timestamp: Date.now() / 1000,
            metadata: { error: 'TrustManager bypass failed: ' + e.toString() }
        }));
    }

    // --- 2. Bypass HostnameVerifier ---
    try {
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (verifier) {
            send(JSON.stringify({
                type: 'pinning_bypass',
                timestamp: Date.now() / 1000,
                class: 'javax.net.ssl.HttpsURLConnection',
                method: 'setDefaultHostnameVerifier',
                metadata: { action: 'hostname_verifier_intercepted' }
            }));
            // Don't actually set it — the app's custom verifier gets swallowed
        };
    } catch (e) {
        send(JSON.stringify({
            type: 'pinning_bypass_error',
            timestamp: Date.now() / 1000,
            metadata: { error: 'HostnameVerifier bypass failed: ' + e.toString() }
        }));
    }

    // --- 3. Bypass OkHttp CertificatePinner ---
    try {
        var OkHttpCertPinner = Java.use('okhttp3.CertificatePinner');
        OkHttpCertPinner.check.overload(
            'java.lang.String',
            'java.util.List'
        ).implementation = function (hostname, peerCertificates) {
            send(JSON.stringify({
                type: 'pinning_bypass',
                timestamp: Date.now() / 1000,
                class: 'okhttp3.CertificatePinner',
                method: 'check',
                args: [hostname],
                metadata: {
                    action: 'okhttp_pinning_bypassed',
                    hostname: hostname,
                    certificate_count: peerCertificates.size()
                }
            }));
            // Return empty list — no pinned certs to check against
            return Java.use('java.util.Collections').emptyList();
        };
    } catch (e) {
        send(JSON.stringify({
            type: 'pinning_bypass_error',
            timestamp: Date.now() / 1000,
            metadata: { error: 'OkHttp CertificatePinner not found: ' + e.toString() }
        }));
    }

    // --- 4. Bypass custom TrustManager implementations ---
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        // Hook all implementations of checkServerTrusted
        var checkServerTrusted = X509TrustManager.checkServerTrusted;
        if (checkServerTrusted && checkServerTrusted.overloads) {
            checkServerTrusted.overloads.forEach(function (overload) {
                overload.implementation = function () {
                    send(JSON.stringify({
                        type: 'pinning_bypass',
                        timestamp: Date.now() / 1000,
                        class: this.$className,
                        method: 'checkServerTrusted',
                        metadata: { action: 'custom_trust_manager_neutralized' }
                    }));
                    // Don't throw — silently accept
                };
            });
        }
    } catch (e) {
        send(JSON.stringify({
            type: 'pinning_bypass_error',
            timestamp: Date.now() / 1000,
            metadata: { error: 'Custom TrustManager hook failed: ' + e.toString() }
        }));
    }
});
