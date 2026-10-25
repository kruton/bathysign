#!/usr/bin/env python3
# Copyright 2026 Kenny Root
"""Run the actual kernel queue insertion code against a recorded one-shot timer."""
import argparse
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--kernel', required=True, type=Path)
args = parser.parse_args()
source = (args.kernel / 'src/scheduler/task/mod.rs').read_text()

def method(signature):
    start = source.index(signature)
    opening = source.index('{', start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]

code = r'''
#![allow(dead_code)]
use std::{cell::RefCell, rc::Rc};
macro_rules! debug { ($($arg:tt)*) => {}; }
mod arch {
    pub static TIMER: std::sync::Mutex<Option<u64>> = std::sync::Mutex::new(None);
    pub fn set_oneshot_timer(time: Option<u64>) { *TIMER.lock().unwrap() = time; }
}
#[derive(Debug, PartialEq)] enum TaskStatus { Running, Blocked }
struct Task { id: u64, status: TaskStatus }
struct BlockedTask { task: Rc<RefCell<Task>>, wakeup_time: Option<u64> }
impl BlockedTask {
    fn new(task: Rc<RefCell<Task>>, wakeup_time: Option<u64>) -> Self { Self { task, wakeup_time } }
}
#[derive(Default)] struct List(Vec<BlockedTask>);
impl List {
    fn front(&self) -> Option<&BlockedTask> { self.0.first() }
    fn push_back(&mut self, task: BlockedTask) { self.0.push(task); }
    fn cursor_front_mut(&mut self) -> Cursor<'_> { Cursor { list: self, index: 0 } }
}
struct Cursor<'a> { list: &'a mut List, index: usize }
impl Cursor<'_> {
    fn current(&self) -> Option<&BlockedTask> { self.list.0.get(self.index) }
    fn move_next(&mut self) { self.index += 1; }
    fn insert_before(&mut self, task: BlockedTask) { self.list.0.insert(self.index, task); }
}
#[derive(Default)] struct BlockedTaskQueue { list: List, network_wakeup_time: Option<u64> }
impl BlockedTaskQueue {
__METHODS__
}
fn add(queue: &mut BlockedTaskQueue, deadline: Option<u64>) {
    queue.add(Rc::new(RefCell::new(Task { id: 1, status: TaskStatus::Running })), deadline);
}
fn armed() -> Option<u64> { *arch::TIMER.lock().unwrap() }
#[test] fn later_thread_deadline_cannot_delay_an_earlier_waiter() {
    let mut q = BlockedTaskQueue::default();
    add(&mut q, Some(200_000)); assert_eq!(armed(), Some(200_000));
    add(&mut q, Some(5_000_000)); assert_eq!(armed(), Some(200_000));
    add(&mut q, Some(1_000_000)); assert_eq!(armed(), Some(200_000));
    add(&mut q, Some(100_000)); assert_eq!(armed(), Some(100_000));
    assert_eq!(q.list.0.iter().map(|n| n.wakeup_time).collect::<Vec<_>>(), vec![Some(100_000),Some(200_000),Some(1_000_000),Some(5_000_000)]);
}
#[test] fn indefinite_wait_does_not_disarm_a_deadline() {
    let mut q = BlockedTaskQueue::default();
    add(&mut q, Some(200_000)); add(&mut q, None); assert_eq!(armed(), Some(200_000));
    add(&mut q, Some(1_000_000)); assert_eq!(armed(), Some(200_000));
}
#[cfg(feature="net")]
#[test] fn timer_is_earliest_of_existing_new_and_network_deadlines() {
    for network in [50_000, 500_000, 50_000_000] {
        let mut q = BlockedTaskQueue::default();
        add(&mut q, Some(200_000)); q.add_network_timer(Some(network));
        assert_eq!(armed(), Some(network.min(200_000)));
        add(&mut q, Some(5_000_000)); assert_eq!(armed(), Some(network.min(200_000)));
        add(&mut q, Some(100_000)); assert_eq!(armed(), Some(network.min(100_000)));
        q.add_network_timer(Some(80_000_000)); assert_eq!(armed(), Some(100_000));
        q.add_network_timer(None); assert_eq!(armed(), Some(100_000));
    }
}
'''
methods = method('pub fn add(') + '\n#[cfg(feature="net")]\n' + method('pub fn add_network_timer(')
with tempfile.TemporaryDirectory(prefix='signer-timer-test-') as tmp:
    root = Path(tmp)
    rust = root / 'timers.rs'
    rust.write_text(code.replace('__METHODS__', methods))
    for networking in (False, True):
        binary = root / ('net' if networking else 'no-net')
        command = ['rustc', '--edition=2024', '--test', str(rust), '-o', str(binary)]
        if networking:
            command += ['--cfg', 'feature="net"']
        subprocess.run(command, check=True)
        subprocess.run([str(binary), '--test-threads=1'], check=True)
