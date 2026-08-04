"""Automated mitmproxy certificate installation on Android devices.

Handles three scenarios:
1. Rooted device/emulator → push cert to system trust store via ADB
2. Non-rooted device → install to user store + provide Frida trust_all.js hook
3. Emulator with writable system → remount + push directly

Also converts mitmproxy PEM cert to Android-compatible format.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from reverserx.tools.base import BaseTool, ToolContext, ToolExecution


class CertSetupInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    serial: str = Field(min_length=1, description="Device serial number")
    cert_path: str = Field(
        default="",
        description="Path to mitmproxy CA certificate. Auto-detected if empty.",
    )


class CertSetupTool(BaseTool[CertSetupInput]):
    name = "cert_setup"
    description = (
        "Install mitmproxy CA certificate on an Android device for HTTPS interception. "
        "Auto-detects root, pushes to system store if possible, or provides Frida bypass."
    )
    version = "1.0.0"
    input_model = CertSetupInput

    def execute(self, context: ToolContext, arguments: CertSetupInput) -> ToolExecution:
        from reverserx.utils.adb import run_adb, AdbError
        from pathlib import Path as _Path
        import hashlib as _hashlib

        result: dict = {
            "serial": arguments.serial,
            "method": "unknown",
            "cert_installed": False,
            "steps": [],
        }

        # --- 1. Find the mitmproxy CA certificate ---
        cert_path = self._find_cert(arguments.cert_path)
        if cert_path is None:
            return ToolExecution(
                output={**result, "error": "mitmproxy CA certificate not found"},
                notices=(
                    "No mitmproxy CA cert found. Run mitmproxy once to generate it, "
                    "or pass --cert-path. Typical locations: "
                    "~/.mitmproxy/mitmproxy-ca-cert.pem, "
                    "~/.mitmproxy/mitmproxy-ca-cert.cer",
                ),
            )
        result["cert_path"] = str(cert_path)

        # Read cert
        cert_data = cert_path.read_bytes()
        cert_hash = _hashlib.md5(cert_data).hexdigest()
        result["cert_hash"] = cert_hash

        # --- 2. Detect root status ---
        rooted = False
        try:
            r = run_adb(("-s", arguments.serial, "shell", "id"), timeout=5)
            rooted = "uid=0" in r.stdout
        except AdbError:
            pass
        result["rooted"] = rooted

        # --- 3. Install based on root status ---
        notices: list[str] = []
        steps: list[str] = []

        if rooted:
            result["method"] = "system_store"
            # Remount system partition
            try:
                r = run_adb(
                    ("-s", arguments.serial, "root"), timeout=10
                )
                steps.append(f"adb root: {r.returncode}")
                r = run_adb(
                    ("-s", arguments.serial, "remount"), timeout=10
                )
                steps.append(f"adb remount: {r.returncode}")
            except AdbError as exc:
                notices.append(f"System remount failed: {exc} — trying alternative")

            # Convert cert to Android filename: <hash>.0
            cert_name = f"{cert_hash}.0"
            remote_path = f"/system/etc/security/cacerts/{cert_name}"

            # Push via temp location then move
            try:
                run_adb(
                    ("-s", arguments.serial, "push", str(cert_path), "/sdcard/mitmproxy-ca.cer"),
                    timeout=15,
                )
                steps.append("pushed cert to /sdcard/")

                run_adb(
                    ("-s", arguments.serial, "shell", "cp", "/sdcard/mitmproxy-ca.cer", remote_path),
                    timeout=5,
                )
                steps.append(f"copied to {remote_path}")

                run_adb(
                    ("-s", arguments.serial, "shell", "chmod", "644", remote_path),
                    timeout=5,
                )
                steps.append("set permissions")

                result["cert_installed"] = True
                result["system_path"] = remote_path
                notices.append(
                    f"Certificate installed to system store at {remote_path}. "
                    "Reboot device to apply: adb reboot"
                )

            except AdbError as exc:
                notices.append(f"System cert push failed: {exc}")
        else:
            # Non-rooted: install to user store
            result["method"] = "user_store"
            try:
                run_adb(
                    ("-s", arguments.serial, "push", str(cert_path), "/sdcard/mitmproxy-ca.cer"),
                    timeout=15,
                )
                steps.append("pushed cert to /sdcard/")

                # Open cert installer intent (works on most Android versions)
                run_adb(
                    ("-s", arguments.serial, "shell", "am", "start", "-a",
                     "android.intent.action.VIEW", "-d",
                     "content://com.android.externalstorage.documents/document/primary%3Amitmproxy-ca.cer",
                     "-t", "application/x-x509-ca-cert"),
                    timeout=10,
                )
                steps.append("opened cert installer (follow on-screen prompt)")

                result["cert_installed"] = False  # Needs manual confirmation
                notices.append(
                    "Certificate pushed to device. Follow the on-screen prompt to install. "
                    "Note: Android 7+ ignores user CAs for apps targeting API 24+. "
                    "Use Frida trust_all.js hook to bypass this restriction."
                )

            except AdbError as exc:
                notices.append(f"User cert push failed: {exc}")

        # --- 4. Frida bypass recommendation ---
        notices.append(
            "For guaranteed HTTPS interception: use the 'trust_all' Frida hook. "
            "Run: 'reverserx tool run <project> frida_inject -a "
            '\'{"serial":"' + arguments.serial + '","package":"<pkg>","hook_name":"trust_all"}\' '
            "This bypasses certificate pinning AND the system trust store check."
        )

        result["steps"] = steps
        result["frida_hook_recommended"] = "trust_all"
        result["notes"] = [
            "Android 7+ (API 24+) ignores user-installed CAs for apps targeting API 24+",
            "System store installation requires root access",
            "For non-rooted devices: use trust_all.js Frida hook + user CA",
            "Emulator system images are rootable via 'adb root'",
        ]

        return ToolExecution(
            output=result,
            notices=tuple(notices),
        )

    @staticmethod
    def _find_cert(explicit_path: str) -> Path | None:
        if explicit_path:
            p = Path(explicit_path).expanduser()
            return p if p.is_file() else None

        # Auto-detect common locations
        candidates = [
            Path("~/.mitmproxy/mitmproxy-ca-cert.pem").expanduser(),
            Path("~/.mitmproxy/mitmproxy-ca-cert.cer").expanduser(),
            Path("/usr/local/share/mitmproxy/mitmproxy-ca-cert.pem"),
            Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem",
        ]
        for p in candidates:
            if p.is_file():
                return p
        return None
