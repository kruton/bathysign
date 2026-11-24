#!/usr/bin/env python3
"""Execute upstream block_on and futex deadline forwarding with a recorded clock."""
import argparse
from pathlib import Path
import subprocess
import tempfile
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--kernel', required=True, type=Path)
a = p.parse_args()
source = (a.kernel / 'src/executor/mod.rs').read_text()

def method(signature):
    start = source.index(signature)
    opening = source.index('{', start)
    end, depth = opening + 1, 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]

code = r'''
#![allow(dead_code)]
use std::{future::Future, pin::pin, sync::{Arc, atomic::{AtomicU32, AtomicU64, Ordering}}, task::{Wake, Context, Poll}, time::Duration};
#[derive(Debug, PartialEq)] enum Errno { Time }
mod io { pub type Result<T> = std::result::Result<T, super::Errno>; }
static NOW: AtomicU64 = AtomicU64::new(100);
static DEADLINE: AtomicU64 = AtomicU64::new(0);
fn get_timer_ticks() -> u64 { NOW.load(Ordering::SeqCst) }
struct Flags(u32); impl Flags { fn empty() -> Self { Self(0) } }
fn futex_wait_and_set(_: &AtomicU32, _: u32, deadline: Option<u64>, flags: Flags, _: u32) -> i32 {
 assert_eq!(flags.0, 0, "deadline must be absolute");
 let deadline = deadline.expect("timed future must arm its deadline");
 DEADLINE.store(deadline, Ordering::SeqCst);
 NOW.store(deadline, Ordering::SeqCst);
 0
}
struct TaskNotify { futex: AtomicU32 }
impl TaskNotify { fn new() -> Self { Self { futex: AtomicU32::new(0) } } __WAIT__ }
impl Wake for TaskNotify { fn wake(self: Arc<Self>) {} }
struct Backoff; impl Backoff {
 fn new() -> Self { Self }
 fn is_completed(&self) -> bool { true }
 fn reset(&self) {}
 fn snooze(&self) {}
}
fn run() -> bool { false }
__BLOCK_ON__
#[test] fn deadline_uses_timer_ticks_and_expires_without_external_traffic() {
 NOW.store(100, Ordering::SeqCst);
 let pending = std::future::pending::<io::Result<()>>();
 assert_eq!(block_on(pending, Some(Duration::from_millis(100))), Err(Errno::Time));
 assert_eq!(DEADLINE.load(Ordering::SeqCst), 100_100);
}
#[test] fn ready_future_does_not_wait() {
 assert_eq!(block_on(std::future::ready(Ok(42)), None), Ok(42));
}
'''.replace('__WAIT__', method('pub fn wait(')).replace('__BLOCK_ON__', method('pub(crate) fn block_on'))
with tempfile.TemporaryDirectory() as tmp:
    rust, binary = Path(tmp) / 'executor.rs', Path(tmp) / 'executor'
    rust.write_text(code)
    subprocess.run(['rustc', '--edition=2024', '--test', str(rust), '-o', str(binary)], check=True)
    subprocess.run([str(binary), '--test-threads=1'], check=True)
