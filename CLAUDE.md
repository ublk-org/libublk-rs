# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

libublk-rs is a Rust library for building Linux ublk (userspace block) target devices. It provides a high-level API for creating custom block devices that run in userspace while interfacing with the Linux kernel's ublk driver. The library uses io_uring for high-performance asynchronous I/O operations.

## Build Commands

- `cargo build` - Build the library
- `cargo test` - Run tests
- `cargo test --test basic <name>` - Run a single integration test by name (e.g. `cargo test --test basic test_ublk_null`)
- `cargo test -- --nocapture` - Show stdout/stderr from tests (useful when device creation fails silently)
- `cargo run --example null help` - Run the null target example with help
- `cargo run --example loop help` - Run the loop target example with help
- `cargo run --example ramdisk` - Run the ramdisk example
- `cargo run --example batch help` - Run the batch-completion example

This is a Cargo **workspace**: the top-level `libublk` crate depends on the
`libublk-rs-sys` subcrate (path dep) for the bindgen-generated kernel bindings.
The `build.rs` lives in `libublk-rs-sys/`, not the root.

## Core Architecture

### Main Components

1. **Control Layer (`src/ctrl.rs`, `src/ctrl_async.rs`)**:
   - `UblkCtrl` / `UblkCtrlBuilder` - synchronous device creation and management
   - `UblkCtrlAsync` (in `ctrl_async.rs`) - async/await variant; enforces `UBLK_CTRL_ASYNC_AWAIT`
   - Handles device lifecycle (add, start, stop, delete) via `/dev/ublk-control`
   - CPU affinity management for queues
   - Control-ring helpers: `ublk_init_ctrl_task_ring`, `with_ctrl_ring`, `with_ctrl_ring_mut`

2. **I/O Layer (`src/io.rs`)**:
   - `UblkDev` - Device representation
   - `UblkQueue` - Per-queue I/O handling
   - `UblkIOCtx` - I/O context management
   - Raw SQE (Submission Queue Entry) manipulation via `RawSqe`
   - **Unified buffer API**: `BufDesc` / `BufDescList` describe per-IO buffers
     across the various ublk buffer modes (slice, user-copy, auto-buf-reg,
     zero-copy). These are re-exported from the crate root — prefer them over
     raw pointers in new code.

3. **Async Support (`src/op.rs`, `src/ops.rs`, `src/reactor.rs`, `src/runtime.rs`)**:
   - `op.rs` - Slab-keyed single-shot op futures (SQE `user_data` = slab key)
   - `ops.rs` - Typed async operation catalog (file/socket/timer/raw SQE)
   - `reactor.rs` - Executor-agnostic ring driving (`reap_events`, `wait_and_reap_events`)
   - `runtime.rs` - `UblkRuntime`: Tokio current-thread glue over the reactor (`tokio` feature)

4. **System Bindings (`src/sys.rs`, `src/bindings.rs`, `libublk-rs-sys/`)**:
   - Low-level kernel interface definitions
   - The `-sys` crate generates Rust bindings from `ublk_cmd.h` via bindgen at
     build time; the high-level crate stays free of build-script complexity.

5. **Helpers (`src/helpers.rs`)**:
   - `IoBuf<T>` - aligned I/O buffer management utility

6. **Shared-memory zero copy (`src/shmem.rs`)**:
   - `UBLK_F_SHMEM_ZC` is opportunistic and per request, *not* a buffer
     mode: `BufDesc` is unchanged, FETCH/COMMIT are unchanged
   - `ShmemBuf` owns one `MAP_SHARED` mapping (hugetlbfs file, memfd);
     `UblkCtrl::register_shmem_buf()` / `unregister_shmem_buf()` issue
     `UBLK_U_CMD_REG_BUF` / `UNREG_BUF`; `ShmemBufs` keeps registered
     mappings by driver index
   - A request with `UBLK_IO_F_SHMEM_ZC` carries `(index << 32) | offset`
     in `iod.addr` (`ShmemZcAddr`); the kernel copies nothing, the handler
     uses `ShmemBufs::resolve(iod)` and must check this flag *before* its
     auto-buf-reg / user-copy / slice logic

### Key Patterns

- **Async/Await Model**: The library is built around async/await with io_uring for high-performance I/O
- **Queue-per-Core**: Each device has multiple queues (typically one per CPU core)
- **io threads per queue** (`UblkCtrlBuilder::io_threads_per_queue(n)`,
  driver flag `UBLK_F_PER_IO_DAEMON`): `run_target` spawns `n` threads per
  queue, each `UblkQueue` owns the *interleaved* tag partition from
  `UblkQueue::tags()` (tags `k, k+n, k+2n, …`; FETCH, buffer registration
  and `run_io_tasks` all iterate it), and device start waits for
  `nr_queues * n` registrations. Interleaved, not contiguous: sbitmap
  hands out tags sequentially, so with submitter QD < depth the live tags
  are a rotating contiguous window and contiguous partitions idle most
  threads (d256 -T4 at QD128: 753K, no thread above 55%; interleaved:
  1.04M, all ~85%). `UblkFlags::UBLK_DEV_F_SEQ_TAG_PARTITION` (loop `-S`)
  opts into contiguous blocks anyway, as an experiment knob: measured
  2026-08-29 on tomsrv it was slower for one submitter even with the
  queue full (d128 T4 QD128: 893K vs 1.03M — a submitted batch gets
  contiguous tags, so one thread takes the whole batch) and only parity
  with four submitters on one queue (q1 d128 T4: 271K vs 274K, 6 rounds);
  see the README table. Do not recommend it without a measurement.
  Both layouts are `(first, step, count)` inside `UblkQueue`; everything
  iterates `tags()` / `owns_tag()` / `nr_tags()`, so nothing else knows
  which layout is in use.
  All `n` threads get the queue's CPU affinity — keep them there: the mask
  contains the submitter's CPU and threads outside its L3 domain roughly
  halve their IPC. Why it exists: blk-mq maps a request to the hctx of the
  *issuing* CPU, so a single submitter whose QD fits in the ublk queue
  drives one hctx → one thread → ~450K 4k IOPS cap (loop example). Naïve
  per-io threading (e.g. kublk's interleaved tags, unpinned) gets slower;
  2 threads inside the mask measured 795K vs 495K.
- **Zero-Copy**: Uses memory mapping and buffer registration for efficient data transfer
- **RAII**: Device cleanup happens automatically when `UblkCtrl` is dropped

### Build System

`libublk-rs-sys/build.rs` (not a root-level build script):
- Generates Rust bindings from `libublk-rs-sys/ublk_cmd.h` using bindgen
- Post-processes the output to add `Serialize`/`Deserialize` derives via a regex
  rewrite of every `pub struct`/`pub enum` (so device params can round-trip
  through `serde_json`)
- Handles kernel version compatibility for `UBLK_F_CMD_IOCTL_ENCODE` via the
  `Fix753` callback, which strips a `Fix753_` prefix used to coerce bindgen
  into emitting macro-defined constants

**Rule: every change to `libublk-rs-sys/ublk_cmd.h` (or `build.rs`) that adds
or changes generated items must bump `libublk-rs-sys`'s version, in its own
commit, moving `version` in `libublk-rs-sys/Cargo.toml` and the
`libublk-rs-sys = { path = ..., version = ... }` requirement in the root
`Cargo.toml` together.** Local builds resolve the `-sys` crate through the
path and never notice a stale registry copy; `cargo publish` verifies against
the registry and fails with `E0425` on the new constants. Release order is
`cargo publish --manifest-path libublk-rs-sys/Cargo.toml` first (there is no
`[workspace]`, so `-p` does not work), then `cargo publish --dry-run` at the
root, then the root crate.

### Features

- `tokio` (default) - Built-in Tokio current-thread executor integration (`UblkRuntime`).
  Disable to bring your own executor driven via `libublk::reactor`
  (`reap_events` / `wait_and_reap_events` from the executor's idle hook)

### Device Flags

- `UBLK_DEV_F_MLOCK_IO_BUFFER` - Locks I/O buffer pages in memory to prevent swapping
  - Requires `CAP_IPC_LOCK` capability
  - Incompatible with `UBLK_F_USER_COPY`, `UBLK_F_AUTO_BUF_REG`, and `UBLK_F_SUPPORT_ZERO_COPY`
  - Use when predictable I/O latency is critical and swapping must be avoided

### Examples Structure

All examples follow the pattern:
1. Create `UblkCtrl` with `UblkCtrlBuilder`
2. Define target initialization function
3. Define per-queue I/O handling function 
4. Call `ctrl.run_target()` with these functions
5. Handle graceful shutdown (Ctrl+C)

The examples demonstrate different target types:
- `null.rs` - Null device (discards writes, returns zeros)
- `loop.rs` - Loop device (file-backed); real async/await + io_uring usage
- `ramdisk.rs` - RAM-based storage; single-thread async for *both* ctrl and IO
- `batch.rs` - Task-driven write batching on the typed ops catalog

### Dependencies

Key external dependencies:
- `io-uring` - Linux io_uring interface
- `tokio` - Optional (default `tokio` feature): current-thread executor behind `UblkRuntime`
- `serde` - Serialization for device parameters
- `bindgen` - C header binding generation (build-time)

## Development Notes

### Testing Requirements

- Tests require Linux kernel 6.0+ with `CONFIG_BLK_DEV_UBLK` enabled
- `tests/basic.rs` creates real `/dev/ublkbN` devices — needs either
  `CAP_SYS_ADMIN` (run as root / `sudo cargo test`) **or** the unprivileged-mode
  udev rules + `ublk_user_id` helper installed (see "Unprivileged Mode" below)
- CI uses an mkosi-built VM image (`ci/mkosi.*`) so a real kernel is available;
  plain GitHub Action runners can't create ublk devices without it
- CI runs on both stable and nightly Rust toolchains

### Mount namespace caveat (operational landmine)

**The ublk daemon must not share a mount namespace with any process that
mounts a filesystem on `/dev/ublkbN` or otherwise consumes the device.**
The daemon serves I/O for its own device, so when it exits, any in-flight
unmount/flush triggered in the same mount ns will wait for I/O that the
exiting daemon can no longer serve → self-deadlock. Run the daemon under
`unshare --mount` or call `unshare(CLONE_NEWNS)` at startup. This bites
hardest in container/Kubernetes-pod deployments. Tracked in
[libublk-rs#50](https://github.com/ublk-org/libublk-rs/issues/50); minimal
repro in `vmtest/tests/ublk-mntns-min.sh`.

### Memory Locking (mlock) Support

When using `UBLK_DEV_F_MLOCK_IO_BUFFER`, the application requires `CAP_IPC_LOCK` capability:

```bash
# Grant capability to your ublk executable
sudo setcap cap_ipc_lock=eip /path/to/your/ublk_executable

# Or run with elevated privileges
sudo ./your_ublk_executable

# Check current capabilities
getcap /path/to/your/ublk_executable
```

This feature locks I/O buffer pages in physical memory to prevent them from being swapped to disk, ensuring consistent I/O performance but increasing memory pressure.

### Unprivileged Mode Support

The library supports unprivileged device creation via `UBLK_F_UNPRIVILEGED_DEV` flag, but requires:
- Proper udev rules installation
- `ublk_chown.sh` script in `/usr/local/sbin/`
- `ublk_user_id` binary installation