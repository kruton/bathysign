#!/usr/bin/env python3
# Copyright 2026 Kenny Root
"""Exercise the prepared kernel's real readv/writev code under backpressure."""
import argparse
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--kernel", required=True, type=Path)
args = parser.parse_args()
source = (args.kernel / "src/syscalls/mod.rs").read_text()


def function(name):
    start = source.index("pub unsafe extern \"C\" fn " + name + "(")
    opening = source.index("{", start)
    depth, end = 1, opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


code = r'''
#![allow(non_camel_case_types, dead_code)]
use std::{collections::VecDeque, slice, sync::Mutex};
type RawFd = i32;
const IOV_MAX: usize = 1024;
#[derive(Clone, Copy, Debug)] enum Errno { Again, Intr, Io, Inval }
impl From<Errno> for i32 {
    fn from(error: Errno) -> i32 { match error { Errno::Again => 11, Errno::Intr => 4, Errno::Io => 5, Errno::Inval => 22 } }
}
pub struct iovec { iov_base: *mut u8, iov_len: usize }
#[derive(Default)] struct State { results: VecDeque<Result<usize, Errno>>, transferred: usize, calls: usize }
static STATE: Mutex<State> = Mutex::new(State { results: VecDeque::new(), transferred: 0, calls: 0 });
mod fd {
    use super::*;
    fn operation(len: usize) -> Result<usize, Errno> {
        let mut state = STATE.lock().unwrap(); state.calls += 1;
        let result = state.results.pop_front().expect("Unexpected extra I/O");
        if let Ok(count) = result { assert!(count <= len); state.transferred += count; }
        result
    }
    pub fn read(_: RawFd, buffer: &mut [u8]) -> Result<usize, Errno> {
        let result = operation(buffer.len()); if let Ok(count) = result { buffer[..count].fill(0x42); } result
    }
    pub fn write(_: RawFd, buffer: &[u8]) -> Result<usize, Errno> { operation(buffer.len()) }
}
__READV__
__WRITEV__
fn invoke(read: bool, results: Vec<Result<usize, Errno>>) -> (isize, usize, usize) {
    *STATE.lock().unwrap() = State { results: results.into(), ..State::default() };
    let mut first = [0u8; 4]; let mut second = [0u8; 4];
    let vectors = [iovec { iov_base: first.as_mut_ptr().cast(), iov_len: 4 }, iovec { iov_base: second.as_mut_ptr().cast(), iov_len: 4 }];
    let count = unsafe { if read { sys_readv(1, vectors.as_ptr(), vectors.len()) } else { sys_writev(1, vectors.as_ptr(), vectors.len()) } };
    let state = STATE.lock().unwrap(); (count, state.transferred, state.calls)
}
#[test] fn later_error_cannot_hide_already_transferred_bytes() {
    for read in [false, true] {
        for error in [Errno::Again, Errno::Intr, Errno::Io] {
            let (reported, transferred, calls) = invoke(read, vec![Ok(4), Err(error)]);
            assert_eq!(transferred, 4); assert_eq!(calls, 2);
            assert_eq!(reported, 4, "read={read}, error={error:?}: progress was hidden");
        }
    }
}
#[test] fn error_before_progress_is_preserved() {
    for read in [false, true] {
        for error in [Errno::Again, Errno::Intr, Errno::Io] {
            let (reported, transferred, calls) = invoke(read, vec![Err(error)]);
            assert_eq!(reported, -isize::try_from(i32::from(error)).unwrap());
            assert_eq!(transferred, 0); assert_eq!(calls, 1);
        }
    }
}
#[test] fn short_vector_and_full_vector_counts_remain_exact() {
    for read in [false, true] {
        assert_eq!(invoke(read, vec![Ok(2)]), (2, 2, 1));
        assert_eq!(invoke(read, vec![Ok(4), Ok(4)]), (8, 8, 2));
        assert_eq!(invoke(read, vec![Ok(4), Ok(2)]), (6, 6, 2));
        assert_eq!(invoke(read, vec![Ok(0)]), (0, 0, 1));
    }
}
'''
code = code.replace("__READV__", function("sys_readv")).replace("__WRITEV__", function("sys_writev"))
with tempfile.TemporaryDirectory(prefix="signer-vectored-io-test-") as tmp:
    root = Path(tmp)
    (root / "vectored.rs").write_text(code)
    subprocess.run(["rustc", "--edition=2024", "--test", str(root / "vectored.rs"), "-o", str(root / "tests")], check=True)
    subprocess.run([str(root / "tests"), "--test-threads=1"], check=True)
