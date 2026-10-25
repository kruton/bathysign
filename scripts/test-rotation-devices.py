#!/usr/bin/env python3
"""Check RSA-1024 -> RSA-4096 updates preserve app data on disposable API 24/28 emulators."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "net.bathysign.rotationtest"


def run(*args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, capture_output=True, **kwargs).stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", required=True, type=Path)
    parser.add_argument("--java-home", required=True, type=Path)
    parser.add_argument("--reference-tools", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    args.out = args.out.resolve()
    args.out.mkdir(mode=0o700, parents=True)
    for version in (1, 2, 3):
        manifest = args.out / f"manifest-{version}.xml"
        manifest.write_text(f'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{PACKAGE}" android:versionCode="{version}"><uses-sdk android:minSdkVersion="24" android:targetSdkVersion="28"/><application android:hasCode="false" android:debuggable="true" /></manifest>')
        run(args.sdk / "build-tools/36.0.0/aapt2", "link", "-I", args.sdk / "platforms/android-36/android.jar",
            "--manifest", manifest, "-o", args.out / f"unsigned-{version}.apk")
    env = {**os.environ, "BATHYSIGN_ROTATION_FIXTURES": str(args.out),
           "BATHYSIGN_REFERENCE_CLASSES": str(args.reference_tools / "classes"),
           "BATHYSIGN_LEGACY_CLASSES": str(args.reference_tools / "legacy") + os.pathsep + str(args.reference_tools / "apksig-legacy.jar"),
           "BATHYSIGN_JAVA": str(args.java_home / "bin/java")}
    test = run("cargo", "test", "--locked", "--all-features", "--test", "signatures", "export_rotation_device_fixtures", env=env, cwd=ROOT)
    (args.out / "reference-tests.log").write_bytes(test)
    avds = args.out / "avds"
    avds.mkdir()
    env.update(ANDROID_AVD_HOME=str(avds), ANDROID_SDK_ROOT=str(args.sdk))
    adb = args.sdk / "platform-tools/adb"
    existing = run(adb, "devices").decode()
    if "emulator-5580" in existing or "emulator-5582" in existing:
        raise RuntimeError("Test emulator ports already in use")
    checks = []
    def progress(status):
        report = {"status": status, "rotation_min_sdk": 28, "checks": checks,
                  "reference_verified_apis": [24, 27, 28, 32, 33, 36, 37], "keys": "disposable RSA-1024 and RSA-4096"}
        (args.out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        return report
    progress("running")
    for api, image, port in [(24, "default", 5580), (28, "google_apis_playstore", 5582)]:
        name = f"signer-rotation-api{api}"
        run(args.sdk / "cmdline-tools/latest/bin/avdmanager", "create", "avd", "--name", name,
            "--package", f"system-images;android-{api};{image};x86", "--path", avds / (name + ".avd"), input=b"no\n", env=env)
        config = avds / (name + ".avd") / "config.ini"
        settings = re.sub(r"(?m)^disk\.dataPartition\.size\s*=.*\n?", "", config.read_text())
        data_size = 1073741824 if api == 24 else 6442450944
        config.write_text(settings.rstrip() + f"\ndisk.dataPartition.size = {data_size}\n")
        log = (args.out / f"emulator-{api}.log").open("wb")
        process = subprocess.Popen([str(args.sdk / "emulator/emulator"), "-avd", name, "-port", str(port),
                                    "-no-window", "-no-audio", "-no-snapshot", "-no-boot-anim", "-gpu", "swiftshader_indirect",
                                    "-memory", "1024", "-cores", "2", "-show-kernel"], env=env, stdout=log, stderr=log)
        serial = f"emulator-{port}"
        def device(*command):
            return run(adb, "-s", serial, *command, timeout=60).decode().strip()
        try:
            deadline = time.monotonic() + 300
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError(f"API {api} emulator stopped; see its log")
                try:
                    if device("shell", "getprop", "sys.boot_completed") == "1":
                        break
                except (subprocess.SubprocessError, OSError):
                    pass
                time.sleep(2)
            else:
                raise RuntimeError(f"API {api} emulator did not boot")
            assert device("shell", "getprop", "ro.build.version.sdk") == str(api)
            for versions in [(1, 2, 3), (1, 3)]:
                for index, version in enumerate(versions):
                    assert "Success" in device("install", "-r", args.out / f"signed-{version}.apk")
                    if index == 0:
                        device("shell", "run-as", PACKAGE, "sh", "-c", "'echo retained > rotation-marker'")
                    assert device("shell", "run-as", PACKAGE, "cat", "rotation-marker") == "retained"
                    assert f"versionCode={version}" in device("shell", "dumpsys", "package", PACKAGE)
                checks.append({"api": api, "versions": versions, "data_retained": True})
                progress("running")
                assert "Success" in device("uninstall", PACKAGE)
        except Exception:
            progress("failed")
            raise
        finally:
            try:
                device("emu", "kill")
            except subprocess.SubprocessError:
                process.terminate()
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            log.close()
            shutil.rmtree(avds / (name + ".avd"))
    report = progress("passed")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
