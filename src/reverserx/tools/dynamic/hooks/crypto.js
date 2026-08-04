// @version 1.0.0 — Crypto operation tracing hook
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
});
