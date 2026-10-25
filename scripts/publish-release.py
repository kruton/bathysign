#!/usr/bin/env python3
"""Publish verified files; never replace an existing release's bytes."""
import json
import pathlib
import subprocess
import sys
import tempfile
from release import inventory

root, tag, commit = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
with tempfile.TemporaryDirectory() as temporary:
    stage = pathlib.Path(temporary)
    for directory in sorted(root.iterdir()):
        target = json.loads((directory / 'inputs.json').read_text())['target']
        for file in directory.rglob("*"):
            if not file.is_file():
                continue
            name = file.name if file.name.endswith('.tar.gz') else target + '-' + file.name
            (stage / name).write_bytes(file.read_bytes())
    evidence = pathlib.Path(sys.argv[4])
    for file in sorted(evidence.rglob('*')):
        if file.is_file():
            if file.name != 'evidence-provenance.json':
                subprocess.run(['gh', 'attestation', 'verify', str(file), '--bundle', str(evidence / 'evidence-provenance.json'), '--repo', 'kruton/bathysign', '--signer-workflow', 'kruton/bathysign/.github/workflows/release-container.yml', '--source-digest', commit, '--signer-digest', commit, '--source-ref', 'refs/tags/' + tag, '--deny-self-hosted-runners'], check=True)
            name = 'container-' + str(file.relative_to(evidence)).replace('/', '-')
            (stage / name).write_bytes(file.read_bytes())
    files = inventory(stage)
    (stage / 'SHA256SUMS').write_text(''.join(f'{digest}  {name}\n' for name, digest in files.items()))
    result = subprocess.run(['gh', 'release', 'view', tag, '--json', 'targetCommitish,isPrerelease'], capture_output=True, text=True)
    if result.returncode == 0:
        existing = stage / 'existing'
        existing.mkdir()
        subprocess.run(['gh', 'release', 'download', tag, '--dir', str(existing)], check=True)
        expected = inventory(stage)
        expected = {k: v for k, v in expected.items() if not k.startswith('existing/')}
        if inventory(existing) != expected:
            raise SystemExit('Existing release conflicts; refusing replacement')
    else:
        # A read failure is never treated as permission to overwrite existing assets.
        subprocess.run(['gh', 'release', 'create', tag, '--verify-tag', '--target', commit,
                        '--prerelease', '--title', 'Bathysign ' + tag,
                        '--notes', 'Rebuilt twice on fresh GitHub-hosted runners. See verification documentation and per-target provenance bundles.',
                        *map(str, sorted(stage.iterdir()))], check=True)
