# Checked Hermit 0.13 compatibility fixes

The build helper copies the kernel from the exact Hermit dependency in Cargo.lock.
It checks upstream file hashes before applying replacements; it does not edit the
Cargo checkout. `upstream-sha256.json` and `replacements.json` are the patch inputs.
The guest build refuses an unpatched entropy implementation, and the build helper
also checks the linked binary for the strict entropy diagnostic and absence of
the old fallback warning.

- Entropy: fail stop if secure entropy cannot be read. The upstream syscall
  substituted a predictable Park-Miller generator. The application also checks
  real CPUID because the Rust Hermit target assumes RDSEED at compile time.
- TCP connect: bound the kernel's synchronous connect to 15 seconds. Hyper's
  Hermit connector performs it in a Tokio blocking task and propagates errors.
- TCP drop: abort nonblocking connections rather than waiting for the peer from
  their destructor. This avoids blocking the async executor; a client interrupted
  during close may need to retry. Poll the NIC before removing the socket so its
  reset reaches the peer immediately; otherwise a proxy retains a dead idle
  connection and its next request fails. Exercise with the QEMU smoke test's
  `--idle-close-check` option.
- Executor timeout: convert Unix-epoch deadlines to remaining relative durations
  before waiting on a futex. The original passed an epoch deadline as a duration,
  causing requests to stall until another packet woke the guest.
- Scheduler wake: ignore a second wake notification for a task already made ready
  by its timer. The futex registration may remain briefly after timer expiry;
  the original assumed the task still appeared in the blocked queue and panicked.
- VirtIO network MTU: add the Ethernet header to receive/transmit buffer sizes
  and smoltcp's Ethernet frame limit. VirtIO advertises the IP MTU; smoltcp's
  Ethernet device limit includes the 14-byte link header. The original dropped
  packets above 8986 bytes with an advertised IP MTU of 9000.
- DNS: preserve a usable address family when the other family has no record.
  Upstream returned immediately after an unsuccessful AAAA lookup, so IPv4-only
  names never reached their A lookup. The live VM's DNS packet capture confirmed
  this failure against the auditor; single-family lookup failures still fail.
- Eventfd: wake all registered readers after a write, including when cancelled
  poll futures left stale registrations. Waking only one stale registration
  stranded Tokio's active reactor until unrelated network traffic arrived.
  Recheck readiness and register under one lock, deduplicate poll waiters, and
  notify blocked writers when a read frees counter capacity. Run
  `python3 tests/kernel-eventfd.py --kernel <prepared-kernel>` for the native
  regression tests against the actual prepared kernel module.
- PCI interrupts: backport upstream [#2611](https://github.com/hermit-os/kernel/pull/2611)
  to configure legacy PCI IRQs as level triggered and active low when discovering
  their interrupt lines. The default ISA edge/high configuration can lose PCI
  notifications, particularly when devices share an IRQ. The test VM's network
  and virtiofs devices share IRQ 10. Keep its IP MTU at 9000; changing MTU did not
  eliminate the observed stalls. Run `python3 tests/kernel-pci-interrupts.py
  --kernel <prepared-kernel>` to check actual register programming and PCI IRQ
  discovery against a simulated interrupt controller.
- Vectored I/O: preserve bytes already transferred when a subsequent buffer in
  `readv` or `writev` fails. Returning `EAGAIN` after a successful earlier buffer
  makes callers retry bytes already sent, which can corrupt a TLS stream. The
  regression harness reproduces the incorrect negative return after transferring
  four bytes, and tests the actual patched syscall bodies with backpressure,
  interruption, and I/O errors: `python3 tests/kernel-vectored-io.py --kernel
  <prepared-kernel>`.

These fixes were exercised with a real Hermit guest under QEMU TCG, including an
external collector outage without extra traffic to wake the guest. The negative
boot test without RDSEED halts before loading signing keys. Re-evaluate these
patches against upstream when upgrading the kernel; changed upstream files fail
the hash check deliberately.
