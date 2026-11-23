#!/usr/bin/env python3
"""Execute upstream frame sizing for negotiated and fallback MTUs."""
import argparse
from pathlib import Path
import subprocess
import tempfile
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--kernel', type=Path, required=True)
a = p.parse_args()
s = (a.kernel / 'src/drivers/net/virtio.rs').read_text()
start = s.index('fn ethernet_frame_size(')
end = s.index('\nfn determine_rx_buf_size', start)
method = s[start:end]
code = r'''
const ETHERNET_HEADER_LEN: usize = 14;
mod virtio { pub mod net { pub struct F; impl F { pub const MTU: u8 = 1; } } }
struct Features(bool); impl Features { fn contains(&self, _: u8) -> bool { self.0 } }
struct Le(u16); impl Le { fn to_ne(&self) -> u16 { u16::from_le(self.0) } }
struct Raw(u16); impl Raw { fn as_ptr(&self) -> &Self { self } fn mtu(&self) -> &Self { self } fn read(&self) -> Le { Le(self.0) } }
struct NetDevCfg { features: Features, raw: Raw }
fn mtu() -> u16 { 1514 }
__METHOD__
#[test] fn frame_limits_include_exactly_one_ethernet_header() {
 for ip in [1500u16, 9000] {
  assert_eq!(ethernet_frame_size(&NetDevCfg { features: Features(true), raw: Raw(ip.to_le()) }), ip + 14);
 }
 assert_eq!(ethernet_frame_size(&NetDevCfg { features: Features(false), raw: Raw(0) }), 1514);
}
'''.replace('__METHOD__', method)
with tempfile.TemporaryDirectory() as tmp:
    source, binary = Path(tmp) / 'mtu.rs', Path(tmp) / 'mtu'
    source.write_text(code)
    subprocess.run(['rustc', '--edition=2024', '--test', str(source), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
