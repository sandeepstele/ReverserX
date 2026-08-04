"""Generate targeted Frida hook scripts from static analysis findings."""

from __future__ import annotations

import textwrap


def generate_crypto_hook(
    class_name: str,
    method_name: str = "",
    *,
    overload_types: tuple[str, ...] = (),
    capture_result: bool = True,
) -> str:
    """Generate a Frida script targeting a specific crypto-related method.

    Args:
        class_name: Fully qualified Java class, e.g. 'com.app.CustomCrypto'
        method_name: Method to hook. If empty, hooks all methods.
        overload_types: Java type signatures for overload resolution.
        capture_result: Whether to call the original and send the result.

    Returns:
        A complete Frida JavaScript string ready for injection.
    """
    parts: list[str] = [
        f"// Generated crypto hook for {class_name}.{method_name or '*'}",
        "// @generated — authorized security assessment",
        "",
        "Java.perform(function () {",
        f"    var Target = Java.use('{class_name}');",
    ]

    if method_name:
        _emit_overload_hook(parts, "Target", method_name, overload_types, "crypto", capture_result)
    else:
        parts.append(f"    // Hook all declared methods of {class_name}")
        parts.append("    var methods = Target.class.getDeclaredMethods();")
        parts.append("    // Dynamic method enumeration requires runtime reflection")
        parts.append("    send(JSON.stringify({")
        parts.append("        type: 'crypto_hook_loaded',")
        parts.append(f"        metadata: {{ target_class: '{class_name}', mode: 'all_methods' }}")
        parts.append("    }));")

    parts.append("});")
    return "\n".join(parts) + "\n"


def generate_http_hook(
    class_name: str = "",
    method_name: str = "",
    *,
    capture_bodies: bool = False,
) -> str:
    """Generate a Frida script targeting HTTP client methods.

    Common targets: okhttp3.RealCall.execute, java.net.HttpURLConnection.connect,
    or custom HTTP wrappers.
    """
    if not class_name:
        class_name = "okhttp3.RealCall"
        method_name = method_name or "execute"

    parts: list[str] = [
        f"// Generated HTTP observation hook for {class_name}.{method_name or '*'}",
        "// @generated — authorized security assessment",
        "",
        "Java.perform(function () {",
        f"    var Target = Java.use('{class_name}');",
    ]

    if method_name:
        _emit_overload_hook(parts, "Target", method_name, (), "http", True)
    else:
        parts.append(f"    send(JSON.stringify({{ type: 'http_hook_loaded', metadata: {{ target: '{class_name}' }} }}));")

    parts.append("});")
    return "\n".join(parts) + "\n"


def generate_generic_hook(
    class_name: str,
    method_name: str = "",
    *,
    overload_types: tuple[str, ...] = (),
    hook_type: str = "custom",
    capture_args: bool = True,
    capture_result: bool = True,
    capture_stacktrace: bool = False,
) -> str:
    """Generate a Frida script for an arbitrary class/method pair.

    This is the general-purpose generator used for custom targets discovered
    through static analysis (obfuscated crypto, custom encoders, etc.).
    """
    parts: list[str] = [
        f"// Generated {hook_type} hook for {class_name}.{method_name or '*'}",
        "// @generated — authorized security assessment",
        "",
        "Java.perform(function () {",
        f"    var Target = Java.use('{class_name}');",
    ]

    if method_name:
        _emit_overload_hook(parts, "Target", method_name, overload_types, hook_type, capture_result, capture_args, capture_stacktrace)
    else:
        parts.append(f"    send(JSON.stringify({{ type: 'hook_loaded', metadata: {{ target: '{class_name}', type: '{hook_type}' }} }}));")

    parts.append("});")
    return "\n".join(parts) + "\n"


def _emit_overload_hook(
    parts: list[str],
    var: str,
    method: str,
    overload_types: tuple[str, ...],
    hook_type: str,
    capture_result: bool,
    capture_args: bool = True,
    capture_stacktrace: bool = False,
) -> None:
    """Emit the Frida JavaScript for hooking a specific method."""
    if overload_types:
        overload_sig = ", ".join(f"'{t}'" for t in overload_types)
        overload_selector = f".overload({overload_sig})"
    else:
        overload_selector = ""

    parts.append(f"    {var}.{method}{overload_selector}.implementation = function () {{")
    parts.append("        var args = Array.prototype.slice.call(arguments);")

    if capture_args:
        parts.append("        var safeArgs = args.map(function(a) {")
        parts.append("            if (a === null || a === undefined) return null;")
        parts.append("            try { return a.toString().substring(0, 200); }")
        parts.append("            catch(e) { return '<' + (typeof a) + '>'; }")
        parts.append("        });")
    else:
        parts.append("        var safeArgs = [];")

    if capture_stacktrace:
        parts.append("        var stack = Java.use('android.util.Log').getStackTraceString(")
        parts.append("            Java.use('java.lang.Exception').$new()) || '';")
    else:
        parts.append("        var stack = '';")

    parts.append("        send(JSON.stringify({")
    parts.append(f"            type: '{hook_type}',")
    parts.append("            timestamp: Date.now() / 1000,")
    parts.append(f"            class: '{var.replace('Target', '')}' || '',")
    parts.append(f"            method: '{method}',")
    parts.append("            args: safeArgs,")
    if capture_stacktrace:
        parts.append("            stacktrace: stack.substring(0, 1000),")

    if capture_result:
        parts.append("        var result = this." + method + ".apply(this, arguments);")
        parts.append("        try {")
        parts.append("            msg.result = result !== null && result !== undefined ? result.toString().substring(0, 500) : null;")
        parts.append("        } catch(e) { msg.result = '<error>'; }")
        parts.append("        return result;")
    else:
        parts.append("        return this." + method + ".apply(this, arguments);")

    parts.append("    };")
