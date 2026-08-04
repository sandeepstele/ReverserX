// @version 1.0.0 — HTTP request/response capture hook
// Hooks: okhttp3.OkHttpClient, okhttp3.Request, okhttp3.Response
//        java.net.HttpURLConnection

Java.perform(function () {
    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        var RealCall = Java.use("okhttp3.RealCall");
        var Request = Java.use("okhttp3.Request");
        var RequestBody = Java.use("okhttp3.RequestBody");

        RealCall.execute.implementation = function () {
            var request = this.request();
            var url = request.url().toString();
            var method = request.method();
            var headers = request.headers().toString();
            send(JSON.stringify({
                type: "http",
                timestamp: Date.now() / 1000,
                class: "okhttp3.RealCall",
                method: "execute",
                args: [method, url],
                metadata: { library: "OkHttp", headers: headers, request_url: url }
            }));
            var response = this.execute();
            send(JSON.stringify({
                type: "http",
                timestamp: Date.now() / 1000,
                class: "okhttp3.RealCall",
                method: "execute_response",
                args: [response.code(), url],
                metadata: { status: response.code(), url: url }
            }));
            return response;
        };
    } catch (e) {
        send(JSON.stringify({ type: "error", message: "OkHttp hook failed: " + e }));
    }

    try {
        var HttpURLConnection = Java.use("java.net.HttpURLConnection");
        HttpURLConnection.connect.implementation = function () {
            var url = this.getURL().toString();
            var method = this.getRequestMethod();
            send(JSON.stringify({
                type: "http",
                timestamp: Date.now() / 1000,
                class: "java.net.HttpURLConnection",
                method: "connect",
                args: [method, url],
                metadata: { library: "HttpURLConnection", url: url }
            }));
            return this.connect();
        };
    } catch (e) {
        send(JSON.stringify({ type: "error", message: "HttpURLConnection hook failed: " + e }));
    }
});
