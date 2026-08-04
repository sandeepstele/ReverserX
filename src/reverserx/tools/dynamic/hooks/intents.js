// @version 1.0.0 — Intent construction and broadcast monitoring hook
// Hooks: android.content.Intent constructors, startActivity, sendBroadcast

Java.perform(function () {
    var Intent = Java.use("android.content.Intent");

    Intent.$init.overload("java.lang.String").implementation = function (action) {
        send(JSON.stringify({
            type: "intent",
            timestamp: Date.now() / 1000,
            class: "android.content.Intent",
            method: "<init>",
            args: [action],
            metadata: { action: action }
        }));
        return this.$init(action);
    };

    Intent.setComponent.implementation = function (component) {
        send(JSON.stringify({
            type: "intent",
            timestamp: Date.now() / 1000,
            class: "android.content.Intent",
            method: "setComponent",
            args: [component.toString()],
            metadata: { component: component.toString() }
        }));
        return this.setComponent(component);
    };

    Intent.putExtra.overload("java.lang.String", "java.lang.String").implementation = function (name, value) {
        if (name && (name.toLowerCase().indexOf("token") >= 0 ||
                     name.toLowerCase().indexOf("auth") >= 0 ||
                     name.toLowerCase().indexOf("secret") >= 0)) {
            send(JSON.stringify({
                type: "intent",
                timestamp: Date.now() / 1000,
                class: "android.content.Intent",
                method: "putExtra",
                args: [name, "[REDACTED]"],
                metadata: { extra_name: name, extra_type: "String" }
            }));
        }
        return this.putExtra(name, value);
    };

    // Hook Activity.startActivity to observe intent launches
    try {
        var Activity = Java.use("android.app.Activity");
        Activity.startActivity.overload("android.content.Intent").implementation = function (intent) {
            send(JSON.stringify({
                type: "intent",
                timestamp: Date.now() / 1000,
                class: "android.app.Activity",
                method: "startActivity",
                args: [intent.getAction(), intent.getComponent() ? intent.getComponent().toString() : ""],
                metadata: {
                    action: intent.getAction(),
                    component: intent.getComponent() ? intent.getComponent().toString() : "",
                    flags: intent.getFlags()
                }
            }));
            return this.startActivity(intent);
        };
    } catch (e) {
        send(JSON.stringify({ type: "error", message: "Activity hook failed: " + e }));
    }

    // Hook Context.sendBroadcast
    try {
        var Context = Java.use("android.content.Context");
        Context.sendBroadcast.overload("android.content.Intent").implementation = function (intent) {
            send(JSON.stringify({
                type: "intent",
                timestamp: Date.now() / 1000,
                class: "android.content.Context",
                method: "sendBroadcast",
                args: [intent.getAction()],
                metadata: { action: intent.getAction() }
            }));
            return this.sendBroadcast(intent);
        };
    } catch (e) {
        send(JSON.stringify({ type: "error", message: "Broadcast hook failed: " + e }));
    }
});
