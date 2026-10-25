#!/usr/bin/env python3
"""Deterministic release packaging and independent build comparison."""
import argparse
import gzip
import hashlib
import io
import json
import pathlib
import re
import subprocess
import tarfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


def run(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def inventory(directory):
    files = sorted(directory.rglob('*'))
    if any(p.is_symlink() for p in files):
        raise ValueError('Symlinks are forbidden in release artifacts')
    return {str(p.relative_to(directory)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in files if p.is_file()}


def archive(output, entries, epoch):
    with output.open('wb') as stream, gzip.GzipFile(filename='', mode='wb', fileobj=stream, mtime=epoch) as zipped:
        with tarfile.open(fileobj=zipped, mode='w') as tar:
            for name, source in sorted(entries.items()):
                data = source.read_bytes()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mtime = epoch
                info.mode = 0o755 if name.startswith('bin/') else 0o644
                tar.addfile(info, io.BytesIO(data))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    package = sub.add_parser('package')
    package.add_argument('target', choices=['x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu', 'x86_64-unknown-hermit'])
    package.add_argument('--out', type=pathlib.Path, required=True)
    compare = sub.add_parser('compare')
    compare.add_argument('first', type=pathlib.Path)
    compare.add_argument('second', type=pathlib.Path)
    compare.add_argument('--report', type=pathlib.Path, required=True)
    args = parser.parse_args()
    if args.command == 'compare':
        left, right = inventory(args.first), inventory(args.second)
        if not left or left != right:
            raise SystemExit('Independent rebuild mismatch: ' + ', '.join(k for k in sorted(left.keys() | right.keys()) if left.get(k) != right.get(k)))
        args.report.write_text(json.dumps({'schema': 1, 'matched': True, 'sha256': left}, sort_keys=True, indent=2) + '\n')
        return
    import tomllib
    version = tomllib.loads((ROOT / 'Cargo.toml').read_text())['package']['version']
    revision = run('git', 'rev-parse', 'HEAD')
    epoch = int(run('git', 'show', '-s', '--format=%ct', 'HEAD'))
    entries = {'LICENSE': ROOT / 'LICENSE', 'Cargo.lock': ROOT / 'Cargo.lock', 'Cargo.toml': ROOT / 'Cargo.toml', 'README.md': ROOT / 'README.md', 'docs/releases.md': ROOT / 'docs/releases.md'}
    if args.target.endswith('hermit'):
        entries['scripts/run-qemu.py'] = ROOT / 'scripts/run-qemu.py'
    binaries = ['bathysign', 'hermit-loader'] if args.target.endswith('hermit') else ['bathysign-admin', 'bathysign-collector']
    for binary in binaries:
        entries['bin/' + binary] = ROOT / ('dist/hermit-loader' if binary == 'hermit-loader' else f'target/{args.target}/release/{binary}')
    for p in sorted((ROOT / 'config').glob('*example*')):
        entries['config/' + p.name] = p
    args.out.mkdir(parents=True, exist_ok=True)
    archive(args.out / f'bathysign-{version}-{args.target}.tar.gz', entries, epoch)
    metadata = {'schema': 1, 'source': revision, 'target': args.target, 'epoch': epoch,
                'source_files': {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in run('git', 'ls-files').splitlines() if (ROOT / name).is_file()},
                'toolchain_pins': json.loads((ROOT / 'config/toolchain-pins.json').read_text()),
                'upstream_trust': ['Rust compiler', 'Hermit standard library', 'builder image', 'runtime base image']}
    (args.out / 'inputs.json').write_text(json.dumps(metadata, sort_keys=True, indent=2) + '\n')


if __name__ == '__main__':
    main()
