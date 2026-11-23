# Checked pinned-main Hermit compatibility fixes

The kernel is pinned independently to `b87f9336543ac965dd2b2bb7b5951de752aebb9d`
(November 2, 2026), with `hermit-rs` pinned to
`2545b3dae3deb0ce70d12836ed432b26e573dcd4`. Its older kernel submodule is
not used. The compiler is `nightly-2026-11-01`; the application and Hermit
standard library remain on Rust 1.99.0. The wrapper explicitly enables the
`loader` feature because upstream no longer includes a boot entry point without it. The source archive revision, URL and
SHA-256 are recorded in `config/toolchain-pins.json` and cached for offline builds.

Upstream now supplies Ethernet frame sizing, TCP_NODELAY, VirtIO queue barriers,
PCI interrupt polarity/trigger configuration, earliest-deadline timer arbitration,
and TCP CLOSE-WAIT writes. Those backports have been removed. The reserved PCI
IRQ range correction remains local. The regression harnesses test upstream frame sizing (`tests/kernel-mtu.py`), timer
and PCI implementations together with the remaining patches.

The build helper verifies and extracts the independently pinned kernel archive.
It checks upstream file hashes before applying replacements; it does not edit the
Cargo checkout. `upstream-sha256.json` and `replacements.json` are the patch inputs.
The guest build refuses an unpatched entropy implementation, and the build helper
also checks the linked binary for the strict entropy diagnostic and absence of
the old fallback warning.

- Entropy: fail stop if secure entropy cannot be read. The upstream syscall
  substituted a predictable Park-Miller generator. The application also checks
  real CPUID because the Rust Hermit target assumes RDSEED at compile time.
- Build timestamp: use the kernel's existing `built_info::BUILT_TIME_UTC` for
  `/proc/version`, matching the startup banner. This metadata honors
  `SOURCE_DATE_EPOCH`; upstream's separate `build_time_utc!()` macro embeds the
  wall-clock compilation time and makes otherwise identical binaries differ.
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
- PCI reserved IRQs: reject the entire reserved range, including IRQ 254,
  before upstream's IOAPIC programming. Run `python3 tests/kernel-pci-interrupts.py
  --kernel <prepared-kernel>`.
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

Validation of the pinned-main kernel includes native MTU/frame-size and TCP
CLOSE-WAIT write harnesses (`tests/kernel-mtu.py`, `tests/kernel-half-close.py`).
The QEMU smoke test covers read-only secrets, TLS, collector policy activation,
authenticated webhooks, collector outage, and idle close. Booting without RDSEED
halts in the strict kernel entropy path before configuration or signing keys load.

Two builds with separate target directories, identical source revision and
`SOURCE_DATE_EPOCH=1793721600` produced the same guest SHA-256:
`48bb20cc7226ccce7aac616070bd0b2aa3b1dd6c397d6da4b0220fdca1613858`.
They shared downloaded compiler/dependency caches; full network-isolated rebuild
validation requires a host permitting network namespaces or the release container.
