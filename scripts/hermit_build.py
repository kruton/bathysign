#!/usr/bin/env python3
# Copyright 2026 Kenny Root
"""Validate the source directory used by Hermit's nested kernel build."""
import json
from pathlib import Path
import re
import tomllib


def verify_network_sources(metadata, root):
    """Reject registry replacements that silently bypass Hermit networking patches."""
    root = Path(root)
    patches = tomllib.loads((root / 'Cargo.toml').read_text())['patch']['crates-io']
    active = {node['id'] for node in metadata['resolve']['nodes']}
    packages = [package for package in metadata['packages'] if package['id'] in active]
    for name in ('tokio', 'socket2', 'hyper-util'):
        selected = [package for package in packages if package['name'] == name]
        if len(selected) != 1:
            raise ValueError(f'Hermit requires exactly one patched {name} dependency')
        package, patch = selected[0], patches[name]
        if 'path' in patch:
            expected = (root / patch['path'] / 'Cargo.toml').resolve()
            valid = package['source'] is None and Path(package['manifest_path']).resolve() == expected
        else:
            expected = f"git+{patch['git']}?rev={patch['rev']}#{patch['rev']}"
            valid = package['source'] == expected
        if not valid:
            raise ValueError(f'Hermit networking patch for {name} is not selected; update dependency and patch versions together')
    if any(package['name'] == 'rustls-platform-verifier' for package in packages):
        raise ValueError('Hermit cannot use rustls-platform-verifier; select an HTTP client with bundled certificate roots')


def verify_kernel_source(messages, kernel):
    """Reject xtask binaries whose embedded source path belongs to an old build."""
    builds = [message for message in messages
              if message.get("reason") == "build-script-executed"
              and "#hermit@" in message.get("package_id", "")]
    if len(builds) != 1:
        raise ValueError("Expected exactly one Hermit build-script record")
    log = Path(builds[0]["out_dir"]).parent / "stderr"
    directories = []
    for line in log.read_text().splitlines():
        if '"rustc" "--crate-type=staticlib"' not in line:
            continue
        match = re.match(r'^\$ cd ("(?:[^"\\]|\\.)*") && ', line)
        if not match:
            raise ValueError("Unrecognized Hermit kernel compiler command")
        directories.append(Path(json.loads(match[1])).resolve())
    if directories != [Path(kernel).resolve()]:
        raise ValueError("Hermit cached build helper used a different kernel source directory")
