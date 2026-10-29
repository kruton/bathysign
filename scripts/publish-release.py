#!/usr/bin/env python3
"""Publish verified files; never replace an existing release's bytes."""
import json
import pathlib
import subprocess
import sys
import tempfile
from release import archive, github_release_api, inventory, validate_release_identity, verify_published_release

root, tag, commit = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
validate_release_identity(tag, commit)
with tempfile.TemporaryDirectory() as temporary:
    stage = pathlib.Path(temporary)
    verification = {'VERIFY.md': pathlib.Path(__file__).resolve().parents[1] / 'docs/releases.md'}
    for directory in sorted(root.iterdir()):
        target = json.loads((directory / 'inputs.json').read_text())['target']
        for file in directory.glob('*.tar.gz'):
            (stage / file.name).write_bytes(file.read_bytes())
        for name in ('inputs.json', 'reproducibility.json', 'sbom.spdx.json', 'sbom-attestation.json', 'provenance.json'):
            verification[target + '/' + name] = directory / name
    evidence = pathlib.Path(sys.argv[4])
    for file in sorted(evidence.rglob('*')):
        if file.is_file():
            if file.name != 'evidence-provenance.json':
                subprocess.run(['gh', 'attestation', 'verify', str(file), '--bundle', str(evidence / 'evidence-provenance.json'), '--repo', 'kruton/bathysign', '--signer-workflow', 'kruton/bathysign/.github/workflows/release-container.yml', '--source-digest', commit, '--signer-digest', commit, '--source-ref', 'refs/tags/' + tag, '--deny-self-hosted-runners'], check=True)
            if file.suffix == '.json':
                verification['containers/' + file.relative_to(evidence).as_posix()] = file
    archive(stage / f'bathysign-{tag.removeprefix("v")}-verification.tar.gz', verification, 0)
    files = inventory(stage)
    (stage / 'SHA256SUMS').write_text(''.join(f'{digest}  {name}\n' for name, digest in files.items()))
    release = github_release_api(f'repos/kruton/bathysign/releases/tags/{tag}', allow_missing=True)
    if release is not None:
        if release.get('draft') is not False:
            raise SystemExit('Incomplete release draft; inspect its assets and finish or remove the draft before retrying')
        verify_published_release(tag, commit)
        existing = stage / 'existing'
        existing.mkdir()
        subprocess.run(['gh', 'release', 'download', tag, '--dir', str(existing)], check=True)
        expected = inventory(stage)
        expected = {k: v for k, v in expected.items() if not k.startswith('existing/')}
        if inventory(existing) != expected:
            raise SystemExit('Existing release conflicts; refusing replacement')
    else:
        # Only an explicit 404 permits creating a new release.
        subprocess.run(['gh', 'release', 'create', tag, '--verify-tag', '--target', commit,
                        '--prerelease', '--title', 'Bathysign ' + tag,
                        '--notes', f'''Choose your downloads:

| Download | Use |
| --- | --- |
| `bathysign-{tag.removeprefix('v')}-x86_64-unknown-hermit.tar.gz` | Signing appliance and boot loader for an x86_64 virtual machine. |
| `bathysign-{tag.removeprefix('v')}-x86_64-unknown-linux-gnu.tar.gz` | Administration tool and collector for AMD64 Linux. |
| `bathysign-{tag.removeprefix('v')}-aarch64-unknown-linux-gnu.tar.gz` | Administration tool and collector for ARM64 Linux. |
| `bathysign-{tag.removeprefix('v')}-verification.tar.gz` | Optional attestations, SBOMs, source-input metadata and reproducibility reports. |
| `SHA256SUMS` | Download integrity checks; authenticate binaries with GitHub attestations before use. |

For a typical installation, download the appliance and the tools for your host architecture. Host tools require Debian 13 or a compatible glibc environment.

The collector is also available for AMD64 and ARM64 as `ghcr.io/kruton/bathysign-collector:{tag}`. Use the registry image rather than downloading an OCI archive; verify its attestation and deploy by digest.

[Installation](https://github.com/kruton/bathysign/blob/{commit}/deploy/proxmox/README.md) · [Collector container](https://github.com/kruton/bathysign/blob/{commit}/deploy/collector/README.md) · [Verification and rebuilding](https://github.com/kruton/bathysign/blob/{commit}/docs/releases.md)

Binary archives were rebuilt twice on fresh GitHub-hosted runners and compared byte for byte. Source commit: `{commit}`. Offline builder images and fetched dependency caches are retained as Actions artifacts, subject to retention limits, and are unnecessary for installation.
''',
                        *map(str, sorted(stage.iterdir()))], check=True)

    verify_published_release(tag, commit)
