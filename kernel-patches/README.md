# Hermit kernel configuration and compatibility fixes

The kernel revision is `5ed2a2fc0f0275e5efd9c9ff31db5539b96986cf`, paired with
`hermit-rs` revision `1301e2f3e640adab61446aef2c7ced25432b9a48`. The kernel pin
matches the wrapper's submodule. The kernel compiler is `nightly-2026-11-01`;
the application and Hermit standard library use Rust 1.99.0. The wrapper
enables `loader` to provide the boot entry point.

`config/toolchain-pins.json` records the kernel source revision, archive URL
and SHA-256. The build helper verifies the archive, extracts a pristine source
tree, checks file hashes, and applies the replacements in `replacements.json`.
`upstream-sha256.json` pins the files being patched. The archive is cached for
offline builds. Hash mismatches and unexpected replacement counts stop the
build.  The shared Cargo checkout is not modified.

## Local fixes

Six replacements implement these behaviors:

- **Entropy:** halt if secure entropy cannot be read. The application checks
  actual CPUID for RDSEED because the Rust Hermit target assumes its
  availability at compile time. The build checks the linked image for the
  strict entropy diagnostic and rejects the insecure fallback warning.
- **TCP connect:** bound the synchronous kernel connect to 15 seconds. Hyper's
  Hermit connector runs connect in a Tokio blocking task and propagates
  errors.
- **TCP drop:** abort nonblocking connections and poll the NIC before removing
  the socket, delivering the reset promptly without blocking the async
  executor.  Clients interrupted during close may need to retry.
- **DNS:** preserve a usable address family when the other family has no record.
  Two replacements handle IPv4 and IPv6 lookup results. Single-family lookup
  failures propagate to the caller.
- **PCI IRQs:** reject the full reserved IRQ range, including IRQ 254, before
  programming the IOAPIC.

The pinned kernel supplies Ethernet frame sizing, TCP_NODELAY, VirtIO memory
barriers, PCI interrupt polarity and trigger configuration, and TCP CLOSE-WAIT
writes. Its executor uses monotonic absolute futex deadlines, and its scheduler
ignores wakeups for tasks that are not blocked. Eventfd operations recheck
readiness, deduplicate waiters, and notify readers and writers outside the
interrupt-safe state lock. Vectored I/O reports partial progress after a later
error. Procfs and the startup banner share `built_info::BUILT_TIME_UTC`, which
honors `SOURCE_DATE_EPOCH`.

## Validation

Run each native regression with `python3 tests/<harness> --kernel
<prepared-kernel>`:

| Harness | Coverage |
| --- | --- |
| `kernel-executor.py` | Actual `block_on` and futex deadline forwarding with a recorded monotonic clock |
| `kernel-timers.py` | Queue insertion, duplicate wakeups, and absolute timer arbitration |
| `kernel-eventfd.py` | Cancelled poll waiters, readiness rechecks, and writer notifications |
| `kernel-vectored-io.py` | Partial progress, backpressure, interruption, and I/O errors |
| `kernel-pci-interrupts.py` | Shared IRQ programming, IOAPIC routing, and reserved IRQ rejection |
| `kernel-mtu.py` | Ethernet frame limits for negotiated and fallback MTUs |
| `kernel-half-close.py` | TCP response writes after a peer half-close |

The eventfd host harness substitutes a standard mutex for the privileged kernel
interrupt-mask and lock primitive; its operation bodies use the kernel source.

The QEMU TCG smoke test covers read-only secrets, VirtIO networking, TLS,
collector policy activation, authenticated webhooks, and collector outage
handling. Use `--idle-close-check` to check delivery of idle connection resets.
A boot without RDSEED halts in the strict kernel entropy path before loading
configuration or signing keys.
