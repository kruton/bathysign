#!/usr/bin/env python3
# Copyright 2026 Kenny Root
"""Exercise prepared kernel PCI IRQ discovery with recorded IOAPIC writes."""
import argparse
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--kernel", required=True, type=Path)
args = parser.parse_args()


def method(source, signature):
    start = source.index(signature)
    opening = source.index("{", start)
    depth, end = 1, opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


apic = (args.kernel / "src/arch/x86_64/kernel/apic.rs").read_text()
pci = (args.kernel / "src/drivers/pci.rs").read_text()
code = r'''
#![allow(dead_code)]
macro_rules! info { ($($arg:tt)*) => {{}}; }
macro_rules! debug { ($($arg:tt)*) => {{}}; }
macro_rules! warn { ($($arg:tt)*) => {{}}; }
macro_rules! error { ($($arg:tt)*) => {{}}; }
mod arch { pub mod kernel { pub mod apic {
    use std::{collections::BTreeMap, sync::Mutex};
    const IOAPIC_REG_TABLE: u32 = 0x10;
    static REGISTERS: Mutex<BTreeMap<u32, u32>> = Mutex::new(BTreeMap::new());
    fn ioapic_write(register: u32, value: u32) {
        REGISTERS.lock().unwrap().insert(register, value);
    }
    const LOCAL_APIC_VECTORS_START: u32 = 0xe0;
    struct Ioapic { addr: &'static u8, gsis: std::ops::Range<u32> }
    impl Ioapic {
        fn version(&self) -> u8 { 1 }
        fn set_redirection(&self, gsi: u32, lower: u32, upper: u32) {
            assert!(self.gsis.contains(&gsi));
            ioapic_write(IOAPIC_REG_TABLE + 2*gsi, lower);
            ioapic_write(IOAPIC_REG_TABLE + 2*gsi + 1, upper);
        }
    }
    struct ControllerLock(Mutex<Vec<Ioapic>>);
    impl ControllerLock { fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Ioapic>> { self.0.lock().unwrap() } }
    static IOAPICS: ControllerLock = ControllerLock(Mutex::new(Vec::new()));
    __ISA__
    __REDIRECTION__
    __PCI__
    pub fn reset() { REGISTERS.lock().unwrap().clear(); *IOAPICS.lock() = vec![Ioapic { addr: &0, gsis: 0..24 }]; }
    pub fn registers() -> BTreeMap<u32, u32> { REGISTERS.lock().unwrap().clone() }
    pub fn initialize_isa() { init_ioapic(); }
}}}
type InterruptLine = u8;
#[derive(Clone, Copy)] struct EndpointHeader { pin: u8, line: u8 }
impl EndpointHeader {
    fn from_header(header: Option<Self>, _: &()) -> Option<Self> { header }
    fn interrupt(&self, _: &()) -> (u8, u8) { (self.pin, self.line) }
}
struct PciDevice { endpoint: Option<EndpointHeader>, access: () }
impl PciDevice {
    fn header(&self) -> Option<EndpointHeader> { self.endpoint }
    __DISCOVERY__
}
fn device(pin: u8, line: u8) -> PciDevice {
    PciDevice { endpoint: Some(EndpointHeader { pin, line }), access: () }
}
use arch::kernel::apic;
#[test] fn shared_pci_irq_is_level_low_and_keeps_vector_and_destination() {
    apic::reset(); apic::initialize_isa();
    let isa = apic::registers();
    assert_eq!(isa[&0x24], 0x2a);
    assert_eq!(device(1, 10).get_irq(), Some(10)); // virtiofs
    assert_eq!(device(1, 10).get_irq(), Some(10)); // network, same IRQ
    let configured = apic::registers();
    assert_eq!(configured[&0x24], 0xa02a); // level, low, unmasked, vector 42
    assert_eq!(configured[&0x25], 0);
    for (register, value) in isa {
        if !matches!(register, 0x24 | 0x25) { assert_eq!(configured[&register], value); }
    }
    apic::ioapic_set_pci_interrupt(11, 3);
    let configured = apic::registers();
    assert_eq!(configured[&0x26], 0xa02b);
    assert_eq!(configured[&0x27], 3 << 24);
}
#[test] fn missing_invalid_or_unrouted_pci_interrupts_do_not_touch_ioapic() {
    apic::reset();
    for (pin, line) in [(0, 10), (5, 10), (255, 10), (1, 16), (1, 254), (1, 255)] {
        assert_eq!(device(pin, line).get_irq(), None);
        assert!(apic::registers().is_empty());
    }
    assert_eq!(PciDevice { endpoint: None, access: () }.get_irq(), None);
    assert!(apic::registers().is_empty());
}
'''
code = code.replace("__ISA__", method(apic, "fn init_ioapic("))
code = code.replace("__REDIRECTION__", method(apic, "fn ioapic_set_redirection("))
code = code.replace("__PCI__", method(apic, "pub(crate) fn ioapic_set_pci_interrupt("))
code = code.replace("__DISCOVERY__", method(pci, "pub fn get_irq("))
with tempfile.TemporaryDirectory(prefix="signer-pci-test-") as tmp:
    source, binary = Path(tmp) / "pci.rs", Path(tmp) / "pci-tests"
    source.write_text(code)
    subprocess.run(["rustc", "--edition=2024", "--test", str(source), "-o", str(binary)], check=True)
    subprocess.run([str(binary), "--test-threads=1"], check=True)
