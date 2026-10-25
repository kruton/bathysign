#!/usr/bin/env python3
"""Fetch hash-pinned build inputs and compile the single Hermit guest image."""
import argparse, hashlib, json, os, pathlib, shlex, subprocess, sys, tarfile, urllib.request
from hermit_build import verify_kernel_source
ROOT = pathlib.Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser()
p.add_argument("--cache", type=pathlib.Path, default=ROOT / "dist")
a = p.parse_args()
a.cache.mkdir(parents=True, exist_ok=True)
pins = json.loads((ROOT / "config/toolchain-pins.json").read_text())
def download(kind, name):
    out = a.cache / name
    if not out.exists():
        with urllib.request.urlopen(pins[kind + "_url"], timeout=120) as response:
            out.write_bytes(response.read())
    if hashlib.sha256(out.read_bytes()).hexdigest() != pins[kind + "_sha256"]:
        raise SystemExit(f"Hash mismatch: {out}")
    return out
archive = download("hermit_std", "hermit-std.tar.gz")
loader = download("loader", "hermit-loader")
std = a.cache / "std"
sysroot = a.cache / "sysroot"
if not (sysroot / "lib/rustlib/x86_64-unknown-hermit/lib").exists():
    std.mkdir(exist_ok=True)
    with tarfile.open(archive) as tar:
        tar.extractall(std, filter="data")
    install = next(std.glob("*/rust-install.sh"))
    subprocess.run(["bash", str(install), "--prefix=" + str(sysroot.resolve()), "--disable-ldconfig"], check=True)
if not os.environ.get("BATHYSIGN_OFFLINE_BUILD"):
    subprocess.run(["rustup", "toolchain", "install", pins["hermit_kernel_toolchain"], "--component", "rust-src", "--component", "llvm-tools"], check=True)
kernel=a.cache/"kernel"
subprocess.run(["python3",str(ROOT/"scripts/prepare-kernel.py"),"--out",str(kernel)],check=True)
build_env = {**os.environ, "HERMIT_MANIFEST_DIR": str(kernel.resolve())}
release_flags = shlex.split(build_env.pop("RUSTFLAGS", "")) + ["--sysroot=" + str(sysroot.resolve())]
command = ["cargo", "build", "--locked", "--release", "--bin", "bathysign", "--target", "x86_64-unknown-hermit", "--message-format=json-render-diagnostics", "--config", 'target.x86_64-unknown-hermit.rustflags=' + json.dumps(release_flags)]
for attempt in range(2):
    result = subprocess.run(command, cwd=ROOT, env=build_env, stdout=subprocess.PIPE, text=True, check=True)
    messages = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    try:
        verify_kernel_source(messages, kernel)
        break
    except ValueError as error:
        if attempt:
            raise
        # xtask embeds its source path. Invalidate only Hermit's build output;
        # retain the application's dependency cache and retry once.
        print(f"Rebuilding Hermit after kernel source verification failed: {error}", file=sys.stderr)
        subprocess.run(["cargo", "clean", "--release", "--package", "hermit", "--target", "x86_64-unknown-hermit"], cwd=ROOT, env=build_env, check=True)
target = pathlib.Path(build_env.get("CARGO_TARGET_DIR", ROOT / "target"))
if not target.is_absolute():
    target = ROOT / target
image=target / "x86_64-unknown-hermit/release/bathysign"
contents=image.read_bytes()
if b"Fallback to a naive implementation" in contents or b"Bathysign: strict entropy profile v1" not in contents or b"Secure entropy unavailable: RDSEED is required" not in contents:
    raise SystemExit("Image contains stale/unpatched code; clean the Hermit and bathysign target artifacts and rebuild")
print("Image:", image)
print("Loader:", loader)
