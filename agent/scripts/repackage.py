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
    install_args = [str(apk_signed)]
    for split_apk in sorted(splits_dir.glob("*.apk")):
        install_args.append(str(split_apk))

    print()
    print(f"[+] Patched APK ready: {apk_signed}")
    print()
    print("[+] To install, run:")
    print()
    print(f"    adb install-multiple -r -d -t {' '.join(install_args)}")
    print()
    print("[+] TROUBLESHOOTING -- If you get INSTALL_FAILED_UPDATE_INCOMPATIBLE:")
    print(f"    adb uninstall {args.package}")
    print(f"    Then delete {work_dir} and rerun this script.")
    print()
    print("[+] After installing:")
    print("    1. cd server")
    print("    2. cargo run")
    print(f"    3. At the prompt:  launch {args.package}")


if __name__ == "__main__":
    main()
