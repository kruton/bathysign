#!/usr/bin/env python3
"""Run as root on the authorized Proxmox host; installs provisioning TLS only."""
import json
import os
from pathlib import Path
import subprocess

import argparse
import re
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--base', type=Path, default=Path('/var/lib/bathysign'))
parser.add_argument('--server-name', required=True)
args = parser.parse_args()
if not args.base.is_absolute() or re.search(r'[^A-Za-z0-9_./-]', str(args.base)):
    parser.error('Base must be an absolute service-safe path')
if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}', args.server_name):
    parser.error('Invalid TLS server name')
BASE = args.base
ROOT = BASE / 'root'
ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
BASE.chmod(0o700)
ROOT.chmod(0o700)
os.umask(0o077)


def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


# Keep the CA key outside the VM export. The leaf is not a CA certificate.
if not (BASE / 'ca.key.pem').exists():
    run('openssl', 'req', '-new', '-x509', '-newkey', 'rsa:3072', '-nodes',
        '-keyout', str(BASE / 'ca.key.pem'), '-out', str(BASE / 'ca.pem'),
        '-days', '365', '-subj', '/CN=Bathysign-CA',
        '-addext', 'basicConstraints=critical,CA:TRUE',
        '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
    if not (ROOT / 'tls.key.pem').exists():
        run('openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:3072',
            '-out', str(ROOT / 'tls.key.pem'))
    run('openssl', 'req', '-new', '-key', str(ROOT / 'tls.key.pem'),
        '-out', str(BASE / 'tls.csr'), '-subj', f'/CN={args.server_name}')
    (BASE / 'tls.ext').write_text(f'subjectAltName=DNS:{args.server_name}\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
    run('openssl', 'x509', '-req', '-in', str(BASE / 'tls.csr'), '-CA', str(BASE / 'ca.pem'),
        '-CAkey', str(BASE / 'ca.key.pem'), '-CAcreateserial', '-out', str(ROOT / 'tls.pem'),
        '-days', '90', '-extfile', str(BASE / 'tls.ext'))
if not (ROOT / 'config.json').exists():
    (ROOT / 'bootstrap.json').write_text(json.dumps({'listen': '0.0.0.0:443',
        'tls_certificate': '/root/tls.pem', 'tls_private_key': '/root/tls.key.pem'}) + '\n')
for path in ROOT.iterdir():
    if path.is_file():
        path.chmod(0o600)
Path('/etc/systemd/system/bathysign-virtiofs.service').write_text(f'''[Unit]
Description=Read-only Bathysign root export
After=local-fs.target
Before=pve-guests.service

[Service]
Type=simple
RuntimeDirectory=bathysign
RuntimeDirectoryMode=0700
ExecStart=/usr/libexec/virtiofsd --socket-path=/run/bathysign/fs.sock --shared-dir={ROOT} --readonly --sandbox=namespace
Restart=always
RestartSec=1
UMask=0077

[Install]
WantedBy=multi-user.target
''')
run('systemctl', 'daemon-reload')
run('systemctl', 'enable', '--now', 'bathysign-virtiofs.service')
print((BASE / 'ca.pem').read_text())
