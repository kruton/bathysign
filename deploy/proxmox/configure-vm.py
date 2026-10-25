#!/usr/bin/env python3
"""Configure the reserved signer VM without altering host bridge/firewall/DHCP."""
import argparse
import subprocess
import time
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--vmid', required=True, type=int)
parser.add_argument('--name', required=True, help='Expected existing VM name')
parser.add_argument('--bridge', required=True)
parser.add_argument('--mac', required=True)
parser.add_argument('--vlan', type=int)
parser.add_argument('--mtu', type=int, default=1500)
parser.add_argument('--base', type=Path, default=Path('/var/lib/bathysign'))
parser.add_argument('--socket', type=Path, default=Path('/run/bathysign/fs.sock'))
options = parser.parse_args()
import re
if options.vmid <= 0 or not re.fullmatch(r'[A-Za-z0-9_.-]+', options.name) or not re.fullmatch(r'[A-Za-z0-9_.-]+', options.bridge):
    parser.error('Invalid VM identity or bridge')
if not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', options.mac) or not 576 <= options.mtu <= 9000:
    parser.error('Invalid MAC address or MTU')
if options.vlan is not None and not 1 <= options.vlan <= 4094:
    parser.error('Invalid VLAN')
if any(not path.is_absolute() or re.search(r'[^A-Za-z0-9_./-]', str(path)) for path in (options.base, options.socket)):
    parser.error('Paths must be absolute and contain no QEMU delimiters')
VMID = str(options.vmid)
configuration = subprocess.check_output(['qm', 'config', VMID], text=True)
if f'name: {options.name}\n' not in configuration:
    raise SystemExit('VM ID belongs to another machine')
if subprocess.check_output(['qm', 'status', VMID], text=True).strip() != 'status: stopped':
    raise SystemExit('Stop the signer VM before changing boot and network settings')
for name in ['hermit-loader', 'bathysign']:
    if not (options.base / name).is_file():
        raise SystemExit('Missing boot image: ' + name)
args = (f'-kernel {options.base}/hermit-loader -initrd {options.base}/bathysign '
        '-object memory-backend-memfd,id=signer-ram,size=2147483648,share=on '
        '-numa node,memdev=signer-ram '
        f'-chardev socket,id=signerfs,path={options.socket} '
        '-device vhost-user-fs-pci,chardev=signerfs,tag=root '
        '-global virtio-net-pci.disable-legacy=on')
subprocess.run(['qm', 'set', VMID, '--args', args], check=True)
network = f'virtio={options.mac},bridge={options.bridge},mtu={options.mtu}'
if options.vlan is not None:
    network += f',tag={options.vlan}'
subprocess.run(['qm', 'set', VMID, '--net0', network], check=True)
for _ in range(100):
    if options.socket.exists():
        break
    time.sleep(0.1)
else:
    raise SystemExit('Read-only filesystem socket unavailable')
subprocess.run(['qm', 'start', VMID], check=True)
