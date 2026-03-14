#!/usr/bin/env python3
"""repackage.py -- Pull, patch, repack, sign and reinstall an APK.

Adds android:debuggable="true" to AndroidManifest.xml and injects
libart_jit_tracer.so so the agent can attach to any app.

After decompilation, pauses so the user can modify smali files before
rebuilding.

Usage:
    python scripts/repackage.py <package_name>

Prerequisites:
    - apktool   (apktool.jar in scripts/ or apktool on PATH)
    - apksigner (Android SDK build-tools or PATH)
    - keytool   (JDK)
    - java
    - adb
"""

import argparse
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path


def run(cmd, check=True, capture=False, **kwargs):
    """Run a command, printing it first."""
    if isinstance(cmd, list):
        display = " ".join(str(c) for c in cmd)
    else:
        display = cmd
    print(f"  $ {display}")
    return subprocess.run(
        cmd,
        check=check,
        capture_output=capture,
        text=True if capture else None,
        **kwargs,
    )


def find_tool(name, fallback_paths=None):
    """Find a tool on PATH or in fallback locations."""
    path = shutil.which(name)
    if path:
        return path
    for p in (fallback_paths or []):
        if os.path.isfile(p):
            return p
    return None


def find_apktool(script_dir):
    """Find apktool: jar next to script, or on PATH."""
    jar = script_dir / "apktool.jar"
    if jar.is_file():
        java = find_tool("java")
        if not java:
            sys.exit("ERROR: java not found in PATH (needed for apktool.jar)")
        return [java, "-jar", str(jar)]

    apktool = find_tool("apktool")
    if apktool:
        return [apktool]

    sys.exit(
        "ERROR: apktool not found.\n"
        "  Option 1: put apktool.jar in scripts/\n"
        "  Option 2: install apktool and add to PATH\n"
        "  Download: https://apktool.org"
    )


def find_apksigner():
    """Find apksigner on PATH or in Android SDK build-tools."""
    apksigner = find_tool("apksigner")
    if apksigner:
        return [apksigner]

    android_home = os.environ.get("ANDROID_HOME")
    if not android_home:
        if platform.system() == "Darwin":
            android_home = os.path.expanduser("~/Library/Android/sdk")
        elif platform.system() == "Windows":
            android_home = os.path.join(
                os.environ.get("LOCALAPPDATA", ""), "Android", "Sdk"
            )
        else:
            android_home = os.path.expanduser("~/Android/Sdk")

    bt_dir = os.path.join(android_home, "build-tools")
    if os.path.isdir(bt_dir):
        versions = sorted(os.listdir(bt_dir))
        for ver in reversed(versions):
            for ext in (".bat", ""):
                candidate = os.path.join(bt_dir, ver, f"apksigner{ext}")
                if os.path.isfile(candidate):
                    return [candidate]

    sys.exit(
        "ERROR: apksigner not found.\n"
        "  Install Android SDK build-tools or add apksigner to PATH."
    )



def pull_apk(pkg, work_dir, apk_orig, splits_dir):
    """Pull all APK splits from the device."""
    print(f"[*] Resolving APK paths for {pkg}...")
    result = run(["adb", "shell", f"pm path {pkg}"], capture=True)
    lines = [
        l.strip().removeprefix("package:").strip()
        for l in result.stdout.splitlines()
        if l.strip()
    ]
    if not lines:
        sys.exit(f"ERROR: Could not find APKs for {pkg} -- is it installed?")

    print(f"[*] Pulling {len(lines)} APK split(s)...")
    base_found = False
    for apk_path in lines:
        name = os.path.basename(apk_path)
        print(f"[*]   Pulling {name}...")
        if name == "base.apk":
            run(["adb", "pull", apk_path, str(apk_orig)])
            base_found = True
        else:
            run(["adb", "pull", apk_path, str(splits_dir / name)])

    if not base_found:
        sys.exit("ERROR: base.apk not found in pm path output")


def decode_apk(apktool_cmd, apk_orig, decode_dir):
    """Full decode with apktool (resources + smali)."""
    print("[*] Decoding APK with apktool (full decode)...")
    if decode_dir.exists():
        shutil.rmtree(decode_dir)
    run(apktool_cmd + ["d", str(apk_orig), "-o", str(decode_dir), "-f"])


def patch_manifest(decode_dir):
    """Set android:debuggable='true' in decoded AndroidManifest.xml."""
    manifest = decode_dir / "AndroidManifest.xml"
    if not manifest.is_file():
        sys.exit("ERROR: AndroidManifest.xml not found")

    print('[*] Patching AndroidManifest.xml...')
    text = manifest.read_text(encoding="utf-8")

    # -- debuggable --
    if "android:debuggable" in text:
        text = text.replace('android:debuggable="false"', 'android:debuggable="true"')
        print("[*]   Replaced existing debuggable=false -> true")
    else:
        text = re.sub(r"(<application\b)", r'\1 android:debuggable="true"', text)
        print("[*]   Injected android:debuggable=true into <application>")

    # -- extractNativeLibs: must be true so the agent .so can be loaded --
    if "android:extractNativeLibs" in text:
        text = text.replace('android:extractNativeLibs="false"',
                            'android:extractNativeLibs="true"')
        print("[*]   Replaced extractNativeLibs=false -> true")
    else:
        text = re.sub(r"(<application\b)", r'\1 android:extractNativeLibs="true"', text)
        print("[*]   Injected android:extractNativeLibs=true into <application>")

    manifest.write_text(text, encoding="utf-8")


def inject_agent(agent_so, decode_dir):
    """Copy the agent .so into lib/arm64-v8a in decoded dir."""
    print("[*] Copying libart_jit_tracer.so into lib/arm64-v8a...")
    lib_dir = decode_dir / "lib" / "arm64-v8a"
    lib_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(str(agent_so), str(lib_dir / "libart_jit_tracer.so"))


GATE_CLASS_SMALI = """\
.class public Lcom/dexbgd/GateWait;
.super Ljava/lang/Object;

# Set to true by the agent via JNI when the server sends gate_release.
.field public static released:Z

# Injected into Application.attachBaseContext -- loads the agent only.
# Must NOT block: this runs inside handleBindApplication on the main thread.
.method public static loadAgent()V
    .registers 2

    :try_start
    const-string v0, "art_jit_tracer"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
    :try_end
    .catch Ljava/lang/Exception; {:try_start .. :try_end} :catch_all
    return-void

    :catch_all
    return-void
.end method

# Injected into the main Activity's onCreate -- safe to block here because
# handleBindApplication has already completed by the time an Activity starts.
.method public static enter()V
    .registers 2

    :try_start

    :loop
    sget-boolean v0, Lcom/dexbgd/GateWait;->released:Z
    if-nez v0, :released

    const-wide/16 v0, 500
    invoke-static {v0, v1}, Ljava/lang/Thread;->sleep(J)V

    goto :loop

    :released
    :try_end
    .catch Ljava/lang/Exception; {:try_start .. :try_end} :catch_all

    invoke-static {}, Lcom/dexbgd/GateWait;->gateReleased()V
    return-void

    :catch_all
    invoke-static {}, Lcom/dexbgd/GateWait;->gateReleased()V
    return-void
.end method

# Server sets a breakpoint here before releasing the gate.
# BP fires on the main thread inside Activity.onCreate -- step from here.
.method public static gateReleased()V
    .registers 1
    return-void
.end method
"""

# Injected at the start of Application.attachBaseContext (non-blocking)
GATE_LOAD_LINE = "    invoke-static {}, Lcom/dexbgd/GateWait;->loadAgent()V\n"
# Injected at the start of main Activity.onCreate (blocking gate wait)
GATE_ENTER_LINE = "    invoke-static {}, Lcom/dexbgd/GateWait;->enter()V\n"

GATE_APP_SMALI_TEMPLATE = (
    ".class public L{cls};\n"
    ".super Landroid/app/Application;\n"
    "\n"
    ".method public constructor <init>()V\n"
    "    .registers 1\n"
    "    invoke-direct {p0}, Landroid/app/Application;-><init>()V\n"
    "    return-void\n"
    ".end method\n"
    "\n"
    ".method protected attachBaseContext(Landroid/content/Context;)V\n"
    "    .registers 2\n"
    "    invoke-static {}, Lcom/dexbgd/GateWait;->loadAgent()V\n"
    "    invoke-super {p0, p1}, Landroid/app/Application;->attachBaseContext(Landroid/content/Context;)V\n"
    "    return-void\n"
    ".end method\n"
)


def _get_main_activity(decode_dir):
    """Return android:name of the MAIN/LAUNCHER Activity, or None."""
    manifest = decode_dir / "AndroidManifest.xml"
    text = manifest.read_text(encoding="utf-8")
    # Find <activity ...> blocks that contain both MAIN and LAUNCHER intent filters
    for block in re.findall(r'<activity\b[^>]*(?:>.*?</activity>|/>)', text, re.DOTALL):
        if 'android.intent.action.MAIN' in block and 'android.intent.category.LAUNCHER' in block:
            m = re.search(r'\bandroid:name="([^"]+)"', block)
            if m:
                return m.group(1)
    return None


def _get_manifest_package(decode_dir):
    """Return the package attribute from AndroidManifest.xml."""
    manifest = decode_dir / "AndroidManifest.xml"
    text = manifest.read_text(encoding="utf-8")
    m = re.search(r'<manifest\b[^>]*\bpackage="([^"]+)"', text)
    return m.group(1) if m else None


def _get_application_class(decode_dir):
    """Return the android:name of <application>, or None."""
    manifest = decode_dir / "AndroidManifest.xml"
    text = manifest.read_text(encoding="utf-8")
    m = re.search(r'<application\b[^>]*\bandroid:name="([^"]+)"', text)
    return m.group(1) if m else None


def _resolve_class_name(name, package):
    """Resolve .Relative or full class names to smali path (slashes, no L prefix)."""
    if name.startswith("."):
        return (package + name).replace(".", "/")
    return name.replace(".", "/")


def _find_smali_file(decode_dir, class_path):
    """Find smali file for class_path like com/example/MyApp."""
    for smali_dir in sorted(decode_dir.glob("smali*")):
        candidate = smali_dir / (class_path + ".smali")
        if candidate.is_file():
            return candidate
    return None


def _find_method_body_start(lines, method_idx):
    """Return index of first instruction line after .registers/.locals and annotations."""
    i = method_idx + 1
    in_annotation = False
    while i < len(lines):
        s = lines[i].strip()
        if s.startswith(".end method"):
            return i
        if s.startswith(".annotation"):
            in_annotation = True
        if s.startswith(".end annotation"):
            in_annotation = False
            i += 1
            continue
        if in_annotation or s == "" or s.startswith(".registers") or s.startswith(".locals"):
            i += 1
            continue
        return i
    return i


def _inject_method_call(smali_path, method_sig, inject_line, create_method_smali):
    """Inject inject_line at the start of method_sig in smali_path.
    If the method doesn't exist, appends create_method_smali to the file."""
    lines = smali_path.read_text(encoding="utf-8").splitlines(keepends=True)

    method_idx = None
    for i, line in enumerate(lines):
        if ".method" in line and method_sig in line:
            method_idx = i
            break

    if method_idx is None:
        lines.append(create_method_smali)
        print(f"[*]   Created {method_sig} with injection")
    else:
        body_start = _find_method_body_start(lines, method_idx)
        lines.insert(body_start, inject_line)
        print(f"[*]   Injected into existing {method_sig}")

    smali_path.write_text("".join(lines), encoding="utf-8")


def inject_gate(decode_dir):
    """Inject GateWait smali:
      - attachBaseContext: loadAgent() only (non-blocking, safe during startup)
      - onCreate:          enter() gate loop (safe to block after AMS considers app started)
    """
    package = _get_manifest_package(decode_dir)
    app_name = _get_application_class(decode_dir)

    # Write GateWait.smali into smali/ (first smali dir)
    smali_dirs = sorted(decode_dir.glob("smali*"))
    if not smali_dirs:
        sys.exit("ERROR: no smali* dirs found -- decode the APK first")
    gate_dir = smali_dirs[0] / "com" / "dexbgd"
    gate_dir.mkdir(parents=True, exist_ok=True)
    gate_smali = gate_dir / "GateWait.smali"
    gate_smali.write_text(GATE_CLASS_SMALI, encoding="utf-8")
    print(f"[*] Wrote {gate_smali}")

    # ---- Application.attachBaseContext: inject loadAgent() ----
    if app_name:
        cls_path = _resolve_class_name(app_name, package or "")
        smali_file = _find_smali_file(decode_dir, cls_path)
        if not smali_file:
            sys.exit(f"ERROR: Application class smali not found: {cls_path}")
        print(f"[*] Patching Application.attachBaseContext: {smali_file.name}")
        _inject_method_call(
            smali_file, "attachBaseContext",
            GATE_LOAD_LINE,
            "\n.method protected attachBaseContext(Landroid/content/Context;)V\n"
            "    .registers 2\n"
            + GATE_LOAD_LINE +
            "    invoke-super {p0, p1}, Landroid/app/Application;->attachBaseContext(Landroid/content/Context;)V\n"
            "    return-void\n"
            ".end method\n",
        )
    else:
        # No Application class -- create one and register it in manifest
        if not package:
            sys.exit("ERROR: could not determine package name from manifest")
        cls_path = package.replace(".", "/") + "/DexbgdApp"
        cls_java = package + ".DexbgdApp"   # manifest format: com.example.DexbgdApp
        new_smali = smali_dirs[0] / (cls_path + ".smali")
        new_smali.parent.mkdir(parents=True, exist_ok=True)
        new_smali.write_text(
            GATE_APP_SMALI_TEMPLATE.replace("{cls}", cls_path),
            encoding="utf-8"
        )
        print(f"[*] Created Application class: {new_smali}")
        manifest = decode_dir / "AndroidManifest.xml"
        text = manifest.read_text(encoding="utf-8")
        text = re.sub(r"(<application\b)", rf'\1 android:name="{cls_java}"', text)
        manifest.write_text(text, encoding="utf-8")
        print(f"[*] Registered {cls_java} in AndroidManifest.xml")

    # ---- Main Activity.onCreate: inject enter() ----
    # Activity.onCreate runs after handleBindApplication completes, so blocking
    # here does not trigger AMS/ART kill.
    activity_name = _get_main_activity(decode_dir)
    if not activity_name:
        sys.exit("ERROR: could not find MAIN/LAUNCHER Activity in manifest")
    act_path = _resolve_class_name(activity_name, package or "")
    act_smali = _find_smali_file(decode_dir, act_path)
    if not act_smali:
        sys.exit(f"ERROR: main Activity smali not found: {act_path}")
    print(f"[*] Patching main Activity.onCreate: {act_smali.name}")
    _inject_method_call(
        act_smali, "onCreate(",
        GATE_ENTER_LINE,
        "\n.method public onCreate(Landroid/os/Bundle;)V\n"
        "    .registers 2\n"
        + GATE_ENTER_LINE +
        "    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V\n"
        "    return-void\n"
        ".end method\n",
    )


def build_and_sign(apktool_cmd, apksigner_cmd, decode_dir, apk_patched,
                   apk_signed, keystore, splits_dir):
    """Rebuild APK with apktool, sign everything."""
    # Rebuild (apktool 3.x uses aapt2 by default)
    print("[*] Rebuilding APK with apktool...")
    build_cmd = apktool_cmd + ["b", str(decode_dir), "-o", str(apk_patched)]
    run(build_cmd)

    # Generate debug keystore if needed
    if not keystore.is_file():
        print("[*] Generating debug keystore...")
        keytool = find_tool("keytool")
        if not keytool:
            sys.exit("ERROR: keytool not found in PATH")
        run([
            keytool, "-genkeypair", "-v",
            "-keystore", str(keystore),
            "-alias", "androiddebugkey",
            "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000",
            "-storepass", "android", "-keypass", "android",
            "-dname", "CN=Android Debug,O=Android,C=US",
        ])

    # Sign base APK
    print("[*] Signing patched base APK...")
    run(apksigner_cmd + [
        "sign",
        "--ks", str(keystore), "--ks-pass", "pass:android",
        "--ks-key-alias", "androiddebugkey", "--key-pass", "pass:android",
        "--out", str(apk_signed), str(apk_patched),
    ])

    # Re-sign splits
    signed_marker = splits_dir / ".signed"
    split_apks = list(splits_dir.glob("*.apk"))
    if split_apks:
        if signed_marker.is_file():
            print("[*] Splits already signed -- skipping")
        else:
            print("[*] Re-signing split APKs...")
            for split_apk in split_apks:
                print(f"[*]   Signing {split_apk.name}...")
                run(apksigner_cmd + [
                    "sign",
                    "--ks", str(keystore), "--ks-pass", "pass:android",
                    "--ks-key-alias", "androiddebugkey", "--key-pass", "pass:android",
                    str(split_apk),
                ])
            signed_marker.touch()


def main():
    parser = argparse.ArgumentParser(description="Pull, patch, and repackage an APK for debugging")
    parser.add_argument("package", help="Package name (e.g. com.example.app)")
    parser.add_argument("--skip-pull", action="store_true",
                        help="Skip pulling APK from device (reuse cached)")
    parser.add_argument("--skip-decode", action="store_true",
                        help="Skip decoding (reuse cached smali)")
    parser.add_argument("--no-pause", action="store_true",
                        help="Don't pause for smali editing (batch mode)")
    parser.add_argument("--gate", action="store_true",
                        help="Inject early-attach gate: loads agent in attachBaseContext "
                             "and waits for 'gate' command from server before proceeding")
    args = parser.parse_args()

    script_dir = Path(__file__).resolve().parent
    agent_so = script_dir.parent / "build" / "libart_jit_tracer.so"
    work_dir = script_dir.parent / "build" / "apk_patch" / args.package
    apk_orig = work_dir / "orig.apk"
    apk_patched = work_dir / "patched_unsigned.apk"
    apk_signed = work_dir / "patched.apk"
    decode_dir = work_dir / "decoded"
    keystore = script_dir.parent / "build" / "apk_patch" / "debug.keystore"
    splits_dir = work_dir / "splits"

    # ---- Verify prerequisites ------------------------------------------------
    for tool in ("java", "adb"):
        if not find_tool(tool):
            sys.exit(f"ERROR: {tool} not found in PATH")

    apktool_cmd = find_apktool(script_dir)
    apksigner_cmd = find_apksigner()

    if not agent_so.is_file():
        sys.exit(f"ERROR: {agent_so} not found -- run scripts/build first")

    # ---- Create work dirs ----------------------------------------------------
    work_dir.mkdir(parents=True, exist_ok=True)
    splits_dir.mkdir(parents=True, exist_ok=True)

    # ---- Pull APK from device ------------------------------------------------
    if apk_orig.is_file() or args.skip_pull:
        if apk_orig.is_file():
            print(f"[*] Reusing existing {apk_orig}")
        else:
            sys.exit(f"ERROR: --skip-pull but {apk_orig} does not exist")
    else:
        pull_apk(args.package, work_dir, apk_orig, splits_dir)

    # ---- Decode APK ----------------------------------------------------------
    if (decode_dir / "AndroidManifest.xml").is_file() and not args.skip_decode:
        print(f"[*] Reusing existing decoded dir (delete {decode_dir} to force re-decode)")
    elif args.skip_decode:
        if not decode_dir.is_dir():
            sys.exit(f"ERROR: --skip-decode but {decode_dir} not found")
        print("[*] Skipping decode (--skip-decode)")
    else:
        decode_apk(apktool_cmd, apk_orig, decode_dir)

    # ---- Patch manifest ------------------------------------------------------
    patch_manifest(decode_dir)

    # ---- Inject agent .so ----------------------------------------------------
    inject_agent(agent_so, decode_dir)

    # ---- Inject early-attach gate (optional) ---------------------------------
    if args.gate:
        print("[*] Injecting early-attach gate...")
        inject_gate(decode_dir)

    # ---- Pause for smali editing ---------------------------------------------
    if not args.no_pause:
        print()
        print("=" * 70)
        print(f"  Smali files are in: {decode_dir}")
        print()
        print("  You can now modify smali files as needed.")
        print("  Smali dirs:  smali/ smali_classes2/ smali_classes3/ ...")
        print("  Manifest:    AndroidManifest.xml (already patched)")
        print("=" * 70)
        print()
        try:
            input("  Press ENTER to continue with rebuild and signing... ")
        except (KeyboardInterrupt, EOFError):
            print("\n[!] Aborted by user.")
            sys.exit(1)
        print()

    # ---- Build, sign ---------------------------------------------------------
    build_and_sign(
        apktool_cmd, apksigner_cmd,
        decode_dir, apk_patched, apk_signed,
        keystore, splits_dir,
    )

    # ---- Print install command -----------------------------------------------
    split_apks = sorted(splits_dir.glob("*.apk"))

    print()
    print(f"[+] Patched APK ready: {apk_signed}")
    print()
    print("[+] To install, run:")
    print()
    if split_apks:
        install_args = [str(apk_signed)] + [str(s) for s in split_apks]
        print(f"    adb install-multiple -r -d -t {' '.join(install_args)}")
    else:
        print(f"    adb install -r -d -t {apk_signed}")
    print()
    print("[+] TROUBLESHOOTING -- If you get INSTALL_FAILED_UPDATE_INCOMPATIBLE:")
    print(f"    adb uninstall {args.package}")
    print(f"    Then delete {work_dir} and rerun this script.")
    print()
    print("[+] After installing:")
    print("    1. cd server && cargo run")
    if args.gate:
        print(f"    2. At the prompt:  launch {args.package}")
        print("         (app will pause in gate loop waiting for server)")
        print("    3. Once connected, type:  gate")
        print("         (releases gate, BP fires at GateWait.gateReleased -- step from there)")
    else:
        print(f"    2. At the prompt:  launch {args.package}")


if __name__ == "__main__":
    main()
