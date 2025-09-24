# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

libublk-rs is a Rust library for building Linux ublk (userspace block) target devices. It provides a high-level API for creating custom block devices that run in userspace while interfacing with the Linux kernel's ublk driver. The library uses io_uring for high-performance asynchronous I/O operations.

## Build Commands

- `cargo build` - Build the library
- `cargo build --features=fat_complete` - Build with fat completion feature
- `cargo test` - Run tests
- `cargo run --example null help` - Run the null target example with help
- `cargo run --example loop help` - Run the loop target example with help
- `cargo run --example ramdisk` - Run the ramdisk example

## Core Architecture

### Main Components

1. **Control Layer (`src/ctrl.rs`)**: 
   - `UblkCtrl` and `UblkCtrlBuilder` - Device creation and management
   - Handles device lifecycle (add, start, stop, delete)
   - CPU affinity management for queues
   - Uses `/dev/ublk-control` for kernel communication

2. **I/O Layer (`src/io.rs`)**:
   - `UblkDev` - Device representation
   - `UblkQueue` - Per-queue I/O handling
   - `UblkIOCtx` - I/O context management
   - Raw SQE (Submission Queue Entry) manipulation via `RawSqe`

3. **Async Support (`src/uring_async.rs`)**:
   - `UblkUringOpFuture` - io_uring integration
   - `wait_and_handle_io_events()` - Main event loop driver

4. **System Bindings (`src/sys.rs`, `src/bindings.rs`)**:
   - Low-level kernel interface definitions
   - Generated from C headers via build.rs

5. **Helpers (`src/helpers.rs`)**:
   - `IoBuf` - I/O buffer management utilities

### Key Patterns

- **Async/Await Model**: The library is built around async/await with io_uring for high-performance I/O
- **Queue-per-Core**: Each device has multiple queues (typically one per CPU core)
- **Zero-Copy**: Uses memory mapping and buffer registration for efficient data transfer
- **RAII**: Device cleanup happens automatically when `UblkCtrl` is dropped

### Build System

The project uses a custom `build.rs` that:
- Generates Rust bindings from `ublk_cmd.h` using bindgen
- Adds serde serialization support to generated structs
- Handles kernel version compatibility issues (Fix753 workaround)

### Features

- `fat_complete` - Enables batch completion and zoned append operations
- Default build includes basic functionality

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
- `loop.rs` - Loop device (file-backed)
- `ramdisk.rs` - RAM-based storage

### Dependencies

Key external dependencies:
- `io-uring` - Linux io_uring interface
- `smol` - Async runtime used in examples
- `serde` - Serialization for device parameters
- `bindgen` - C header binding generation (build-time)

## Development Notes

### Testing Requirements

- Tests require Linux kernel 6.0+ with CONFIG_BLK_DEV_UBLK enabled
- Some tests may require root privileges for device creation
- CI runs on both stable and nightly Rust toolchains

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