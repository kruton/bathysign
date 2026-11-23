#!/usr/bin/env python3
"""Exercise the actual kernel TCP write method after a peer half-close."""
import argparse
from pathlib import Path
import subprocess
import tempfile
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--kernel', type=Path, required=True)
a = p.parse_args()
s = (a.kernel / 'src/fd/socket/tcp.rs').read_text()
start = s.index('async fn write(')
end = s.index('\n\tasync fn bind(', start)
code = r'''
#![allow(dead_code)]
use std::{future::{self, Future}, task::{Poll, Context, Waker}, pin::pin, sync::Mutex};
#[derive(Debug)] enum Errno { Io, Again }
mod io { pub type Result<T> = std::result::Result<T, super::Errno>; }
mod tcp { #[derive(Clone, Copy)] pub enum State { Closed, Closing, FinWait1, FinWait2, Listen, TimeWait, CloseWait, Established } }
struct Transport { state: tcp::State, sent: Vec<u8> }
impl Transport {
 fn state(&self) -> tcp::State { self.state }
 fn can_send(&self) -> bool { true }
 fn send_slice(&mut self, buf: &[u8]) -> Result<usize, ()> { self.sent.extend_from_slice(buf); Ok(buf.len()) }
 fn register_send_waker(&self, _: &Waker) {}
}
struct Socket { is_nonblocking: bool, inner: Mutex<Transport> }
impl Socket {
 fn with<T>(&self, f: impl FnOnce(&mut Transport) -> T) -> T { f(&mut self.inner.lock().unwrap()) }
 __METHOD__
}
#[test] fn peer_half_close_preserves_response_writes() {
 for state in [tcp::State::Established, tcp::State::CloseWait] {
  let socket = Socket { is_nonblocking: true, inner: Mutex::new(Transport { state, sent: vec![] }) };
  let mut future = pin!(socket.write(b"response"));
  assert!(matches!(future.as_mut().poll(&mut Context::from_waker(Waker::noop())), Poll::Ready(Ok(8))));
  assert_eq!(socket.inner.lock().unwrap().sent, b"response");
 }
}
'''.replace('__METHOD__', s[start:end])
with tempfile.TemporaryDirectory() as tmp:
    source, binary = Path(tmp) / 'tcp.rs', Path(tmp) / 'tcp'
    source.write_text(code)
    subprocess.run(['rustc', '--edition=2024', '--test', str(source), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
