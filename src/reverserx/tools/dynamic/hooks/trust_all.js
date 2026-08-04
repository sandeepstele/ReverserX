// @version 1.0.0 — Universal TLS trust bypass for authorized security assessment
// Forces the app to trust all certificates including mitmproxy CA.
// Works on Android 7+ (API 24+) where apps ignore user-installed CAs.
// Also bypasses certificate pinning without the complexity of pinning_bypass.js.

Java.perform(function () {
    var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var TrustManagerFactory = Java.use('javax.net.ssl.TrustManagerFactory');
    var KeyStore = Java.use('java.security.KeyStore');

    // --- 1. Create a permissive TrustManager ---
    var PermissiveTM = Java.registerClass({
        name: 'com.reverserx.PermissiveTrustManager',
        implements: [TrustManager],
        methods: {
            checkClientTrusted: function (chain, authType) {},
            checkServerTrusted: function (chain, authType) {},
            getAcceptedIssuers: function () {
                return Java.array('java.security.cert.X509Certificate', []);
            }
        }
    });

    var permissiveTMArray = Java.array(
        TrustManager,
        [PermissiveTM.$new()]
    );

    // --- 2. Hook SSLContext.init to inject permissive TrustManager ---
    SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;',
        '[Ljavax.net.ssl.TrustManager;',
        'java.security.SecureRandom'
    ).implementation = function (km, tm, random) {
        send(JSON.stringify({
            type: 'tls_bypass',
            timestamp: Date.now() / 1000,
            method: 'SSLContext.init',
            metadata: { action: 'trust_all_active' }
        }));
        return this.init(km, permissiveTMArray, random);
    };

    // --- 3. Hook TrustManagerFactory to return permissive TM ---
    TrustManagerFactory.getTrustManagers.implementation = function () {
        send(JSON.stringify({
            type: 'tls_bypass',
            timestamp: Date.now() / 1000,
            method: 'TrustManagerFactory.getTrustManagers',
            metadata: { action: 'factory_overridden' }
        }));
        return permissiveTMArray;
    };

    // --- 4. Hook HttpsURLConnection to skip hostname verification ---
    try {
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConnection.setDefaultSSLSocketFactory.implementation = function (factory) {
            send(JSON.stringify({
                type: 'tls_bypass',
                timestamp: Date.now() / 1000,
                method: 'setDefaultSSLSocketFactory',
                metadata: { action: 'socket_factory_intercepted' }
            }));
        };

        // All-hostname verifier
        var AllHostnameVerifier = Java.registerClass({
            name: 'com.reverserx.AllHostnameVerifier',
            implements: [Java.use('javax.net.ssl.HostnameVerifier')],
            methods: {
                verify: function (hostname, session) { return true; }
            }
        });
        HttpsURLConnection.setDefaultHostnameVerifier(AllHostnameVerifier.$new());
    } catch (e) {
        send(JSON.stringify({
            type: 'tls_bypass_error',
            metadata: { error: 'HttpsURLConnection hooks failed: ' + e.toString() }
        }));
    }

    // --- 5. OkHttp CertificatePinner bypass ---
    try {
        var OkHttpCertPinner = Java.use('okhttp3.CertificatePinner');

        OkHttpCertPinner.check.overload(
            'java.lang.String', 'java.util.List'
        ).implementation = function (hostname, peerCertificates) {
            send(JSON.stringify({
                type: 'tls_bypass',
                timestamp: Date.now() / 1000,
                method: 'CertificatePinner.check',
                metadata: { action: 'pinning_bypassed', hostname: hostname }
            }));
            return Java.use('java.util.Collections').emptyList();
        };

        // Also bypass the newer CertificatePinner.Builder
        OkHttpCertPinner.check.overload(
            'java.lang.String', 'java.security.cert.Certificate'
        ).implementation = function () {
            send(JSON.stringify({
                type: 'tls_bypass',
                timestamp: Date.now() / 1000,
                method: 'CertificatePinner.check(cert)',
                metadata: { action: 'pinning_bypassed' }
            }));
        };
    } catch (e) {
        send(JSON.stringify({
            type: 'tls_bypass_error',
            metadata: { error: 'OkHttp hooks failed: ' + e.toString() }
        }));
    }

    // --- 6. Android Network Security Config bypass ---
    try {
        var NetworkSecurityConfig = Java.use('android.security.net.config.NetworkSecurityConfig');
        var Builder = Java.use('android.security.net.config.NetworkSecurityConfig$Builder');

        // Hook the builder to disable cleartext restrictions and pinning
        if (Builder.setCleartextTrafficPermitted) {
            var originalSetCleartext = Builder.setCleartextTrafficPermitted;
            Builder.setCleartextTrafficPermitted.implementation = function (permitted) {
                send(JSON.stringify({
                    type: 'tls_bypass',
                    method: 'NetworkSecurityConfig.setCleartextTrafficPermitted',
                    metadata: { action: 'cleartext_enforced' }
                }));
                return originalSetCleartext.call(this, true);
            };
        }
    } catch (e) {
        send(JSON.stringify({
            type: 'tls_bypass_error',
            metadata: { error: 'NetworkSecurityConfig hooks failed: ' + e.toString() }
        }));
    }

    send(JSON.stringify({
        type: 'tls_bypass',
        timestamp: Date.now() / 1000,
        method: 'init_complete',
        metadata: {
            status: 'active',
            capabilities: [
                'trust_all_certificates',
                'hostname_verification_disabled',
                'okhttp_pinning_bypassed',
                'ssl_context_intercepted'
            ]
        }
    }));
});
