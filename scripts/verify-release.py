#!/usr/bin/env python3
"""Verify the complete download set against explicit source and builder identities."""
import argparse
import json
import pathlib
import subprocess
from release import inventory

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('directory', type=pathlib.Path)
p.add_argument('--commit', required=True)
p.add_argument('--ref', required=True)
a = p.parse_args()
expected = {'x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu', 'x86_64-unknown-hermit'}
seen = set()
for directory in sorted(a.directory.iterdir()):
    if not directory.is_dir() or directory.is_symlink():
        raise SystemExit('Unexpected release entry')
    for file in directory.rglob("*"):
        if file.is_dir() and not file.is_symlink():
            continue
        if file.is_symlink() or not file.is_file():
            raise SystemExit('Unexpected artifact type')
        if file.name != 'provenance.json':
            subprocess.run(['gh', 'attestation', 'verify', str(file), '--bundle', str(directory / 'provenance.json'),
                            '--repo', 'kruton/bathysign', '--signer-workflow', 'kruton/bathysign/.github/workflows/release-build.yml',
                            '--signer-digest', a.commit, '--source-digest', a.commit, '--source-ref', a.ref,
                            '--deny-self-hosted-runners'], check=True)
    inputs = json.loads((directory / 'inputs.json').read_text())
    target = inputs['target']
    if target not in expected or target in seen or inputs['source'] != a.commit:
        raise SystemExit('Unexpected target or source')
    seen.add(target)
    report = json.loads((directory / 'reproducibility.json').read_text())
    actual = {k: v for k, v in inventory(directory).items() if not k.startswith('offline/')}
    del actual['provenance.json']
    del actual['sbom.spdx.json']
    del actual['sbom-attestation.json']
    del actual['reproducibility.json']
    if report['matched'] is not True or report['sha256'] != actual:
        raise SystemExit('Rebuild evidence does not match downloads')
if seen != expected:
    raise SystemExit('Incomplete release')
