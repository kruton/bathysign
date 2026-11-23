#!/usr/bin/env python3
"""Copy the pinned upstream kernel and apply checked signing-appliance fixes."""
import argparse, hashlib, json, os, pathlib, shutil, subprocess, tarfile, tempfile, urllib.request
from hermit_build import verify_network_sources
ROOT=pathlib.Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument("--out",required=True,type=pathlib.Path);a=p.parse_args()
metadata=json.loads(subprocess.check_output(["cargo","metadata","--locked","--format-version","1","--filter-platform","x86_64-unknown-hermit"],cwd=ROOT))
try:
    verify_network_sources(metadata, ROOT)
except ValueError as error:
    raise SystemExit(str(error)) from error
inputs=json.loads((ROOT/"config/toolchain-pins.json").read_text())
archive=a.out.parent / ("kernel-" + inputs["hermit_kernel_revision"] + ".tar.gz")
if not archive.exists():
    if os.environ.get("BATHYSIGN_OFFLINE_BUILD"):
        raise SystemExit("Pinned kernel archive unavailable offline: " + str(archive))
    with urllib.request.urlopen(inputs["hermit_kernel_url"], timeout=120) as response:
        contents=response.read()
    if hashlib.sha256(contents).hexdigest()!=inputs["hermit_kernel_sha256"]:
        raise SystemExit("Pinned kernel archive hash mismatch")
    archive.parent.mkdir(parents=True,exist_ok=True)
    archive.write_bytes(contents)
if hashlib.sha256(archive.read_bytes()).hexdigest()!=inputs["hermit_kernel_sha256"]:
    raise SystemExit("Pinned kernel archive hash mismatch")
# Always prepare from pristine sources, never overlay a previous kernel version.
temporary=tempfile.TemporaryDirectory(prefix="bathysign-kernel-")
with tarfile.open(archive) as tar:
    tar.extractall(temporary.name, filter="data")
roots=list(pathlib.Path(temporary.name).iterdir())
if len(roots)!=1 or not roots[0].is_dir():
    raise SystemExit("Invalid kernel archive layout")
source=roots[0]
pins=json.loads((ROOT/"kernel-patches/upstream-sha256.json").read_text())
for name,expected in pins.items():
    if hashlib.sha256((source/name).read_bytes()).hexdigest()!=expected: raise SystemExit("Upstream kernel differs: "+name)
for change in json.loads((ROOT/"kernel-patches/replacements.json").read_text()):
    file=source/change["file"];text=file.read_text()
    if text.count(change["before"])!=change.get("expected_count",1): raise SystemExit("Patch does not apply exactly: "+str(file))
    file.write_text(text.replace(change["before"],change["after"]))
if a.out.exists(): shutil.rmtree(a.out)
shutil.copytree(source,a.out,ignore=shutil.ignore_patterns("target",".git"))
temporary.cleanup()
print(a.out.resolve())
