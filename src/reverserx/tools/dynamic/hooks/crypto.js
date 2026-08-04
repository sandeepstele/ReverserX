// @version 1.0.0 — Crypto operation instrumentation for authorized analysis
// Hooks: javax.crypto.Cipher.getInstance, javax.crypto.Cipher.doFinal,
//        javax.crypto.spec.SecretKeySpec.<init>, javax.crypto.Mac.getInstance

Java.perform(function () {
    var Cipher = Java.use("javax.crypto.Cipher");

    Cipher.getInstance.overload("java.lang.String").implementation = function (transformation) {
        var result = this.getInstance(transformation);
        send(JSON.stringify({
            type: "crypto",
            timestamp: Date.now() / 1000,
            class: "javax.crypto.Cipher",
            method: "getInstance",
            args: [transformation],
            result: result.toString()
        }));
        return result;
    };

    Cipher.getInstance.overload("java.lang.String", "java.lang.String").implementation = function (transformation, provider) {
        var result = this.getInstance(transformation, provider);
        send(JSON.stringify({
            type: "crypto",
            timestamp: Date.now() / 1000,
            class: "javax.crypto.Cipher",
            method: "getInstance",
            args: [transformation, provider],
            result: result.toString()
        }));
        return result;
    };

    Cipher.doFinal.overload("[B").implementation = function (input) {
        send(JSON.stringify({
            type: "crypto",
            timestamp: Date.now() / 1000,
            class: "javax.crypto.Cipher",
            method: "doFinal",
            args: ["[B len=" + input.length],
            metadata: { input_length: input.length }
        }));
        return this.doFinal(input);
    };

    var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
    SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function (key, algorithm) {
        send(JSON.stringify({
            type: "crypto",
            timestamp: Date.now() / 1000,
            class: "javax.crypto.spec.SecretKeySpec",
            method: "<init>",
            args: [algorithm],
            metadata: { key_length: key.length, algorithm: algorithm }
        }));
        return this.$init(key, algorithm);
    };

    // --- Cipher.init to capture key and IV ---
    try {
        Cipher.init.overload("int", "java.security.Key").implementation = function (opmode, key) {
            send(JSON.stringify({
                type: "crypto",
                timestamp: Date.now() / 1000,
                class: "javax.crypto.Cipher",
                method: "init",
                args: [opmode == 1 ? "ENCRYPT" : "DECRYPT", key.getAlgorithm()],
                metadata: { opmode: opmode, algorithm: key.getAlgorithm(), key_format: key.getFormat() }
            }));
            return this.init(opmode, key);
        };
    } catch (e) {}

    try {
        Cipher.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec").implementation = function (opmode, key, params) {
            var paramClass = params ? params.$className : "none";
            send(JSON.stringify({
                type: "crypto",
                timestamp: Date.now() / 1000,
                class: "javax.crypto.Cipher",
                method: "init",
                args: [opmode == 1 ? "ENCRYPT" : "DECRYPT", key.getAlgorithm(), paramClass],
                metadata: { opmode: opmode, algorithm: key.getAlgorithm(), param_type: paramClass }
            }));
            return this.init(opmode, key, params);
        };
    } catch (e) {}

    var Mac = Java.use("javax.crypto.Mac");
    Mac.getInstance.overload("java.lang.String").implementation = function (algorithm) {
        var result = this.getInstance(algorithm);
        send(JSON.stringify({
            type: "crypto",
            timestamp: Date.now() / 1000,
            class: "javax.crypto.Mac",
            method: "getInstance",
            args: [algorithm]
        }));
        return result;
    };

    // --- IvParameterSpec (captures IV bytes) ---
    try {
        var IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
        IvParameterSpec.$init.overload("[B").implementation = function (iv) {
            send(JSON.stringify({
                type: "crypto",
                timestamp: Date.now() / 1000,
                class: "javax.crypto.spec.IvParameterSpec",
                method: "<init>",
                metadata: { iv_length: iv.length, iv_hex: bytesToHex(iv, 32) }
            }));
            return this.$init(iv);
        };
    } catch (e) {}

    // --- PBEKeySpec (captures password-based key derivation) ---
    try {
        var PBEKeySpec = Java.use("javax.crypto.spec.PBEKeySpec");
        PBEKeySpec.$init.overload("[C").implementation = function (password) {
            send(JSON.stringify({
                type: "crypto",
                timestamp: Date.now() / 1000,
                class: "javax.crypto.spec.PBEKeySpec",
                method: "<init>",
                metadata: { password_length: password.length }
            }));
            return this.$init(password);
        };
    } catch (e) {}

    // --- MessageDigest (hashing) ---
    try {
        var MessageDigest = Java.use("java.security.MessageDigest");
        MessageDigest.getInstance.overload("java.lang.String").implementation = function (algorithm) {
            var result = this.getInstance(algorithm);
            send(JSON.stringify({
                type: "crypto",
                timestamp: Date.now() / 1000,
                class: "java.security.MessageDigest",
                method: "getInstance",
                args: [algorithm]
            }));
            return result;
        };
    } catch (e) {}

    // --- Base64 encode/decode ---
    try {
        var Base64 = Java.use("android.util.Base64");
        Base64.encodeToString.overload("[B", "int").implementation = function (input, flags) {
            send(JSON.stringify({
                type: "crypto",
                timestamp: Date.now() / 1000,
                class: "android.util.Base64",
                method: "encodeToString",
                args: ["[B len=" + input.length],
                metadata: { input_length: input.length, flags: flags }
            }));
            return this.encodeToString(input, flags);
        };
        Base64.decode.overload("[B", "int").implementation = function (input, flags) {
            send(JSON.stringify({
                type: "crypto",
                timestamp: Date.now() / 1000,
                class: "android.util.Base64",
                method: "decode",
                args: ["[B len=" + input.length],
                metadata: { input_length: input.length, flags: flags }
            }));
            return this.decode(input, flags);
        };
    } catch (e) {}
});

// --- Helper: bytes to hex (truncated) ---
function bytesToHex(bytes, maxLen) {
    var hex = '';
    var len = Math.min(bytes.length, maxLen);
    for (var i = 0; i < len; i++) {
        var b = bytes[i] & 0xff;
        hex += ('0' + b.toString(16)).slice(-2);
    }
    if (bytes.length > maxLen) hex += '...';
    return hex;
}
