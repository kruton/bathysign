#!/usr/bin/env python3
"""Assemble a deterministic OCI index from the compared architecture outputs."""
import hashlib
import json
import pathlib
import shutil
import sys
import tarfile
import tempfile

root, output = map(pathlib.Path, sys.argv[1:])
output.mkdir()
(output / 'blobs/sha256').mkdir(parents=True)
children = []
for arch in ['amd64', 'arm64']:
    archive = list(root.glob(f'container-{arch}-*/collector.oci.tar'))
    if len(archive) != 1:
        raise SystemExit('Missing or duplicate architecture')
    with tempfile.TemporaryDirectory() as temporary:
        directory = pathlib.Path(temporary)
        with tarfile.open(archive[0]) as tar:
            tar.extractall(directory, filter='data')
        index = json.loads((directory / 'index.json').read_text())
        if len(index['manifests']) != 1:
            raise SystemExit('Unexpected OCI layout')
        descriptor = index['manifests'][0]
        descriptor.pop('annotations', None)
        descriptor['platform'] = {'os': 'linux', 'architecture': arch}
        children.append(descriptor)
        for blob in (directory / 'blobs/sha256').iterdir():
            if hashlib.sha256(blob.read_bytes()).hexdigest() != blob.name:
                raise SystemExit('Corrupt OCI blob')
            shutil.copyfile(blob, output / 'blobs/sha256' / blob.name)
index = {'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.index.v1+json', 'manifests': children}
data = json.dumps(index, sort_keys=True, separators=(',', ':')).encode()
digest = hashlib.sha256(data).hexdigest()
(output / 'blobs/sha256' / digest).write_bytes(data)
(output / 'oci-layout').write_text('{"imageLayoutVersion":"1.0.0"}')
(output / 'index.json').write_text(json.dumps({'schemaVersion': 2, 'manifests': [{'mediaType': index['mediaType'], 'digest': 'sha256:' + digest, 'size': len(data), 'annotations': {'org.opencontainers.image.ref.name': 'release'}}]}, sort_keys=True))
print('sha256:' + digest)
