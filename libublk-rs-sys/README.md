# libublk-rs-sys

Low-level FFI bindings for the Linux ublk (userspace block device) kernel interface.

## Overview

This crate provides raw, unsafe bindings to the Linux ublk kernel API. These bindings are automatically generated from the kernel headers using bindgen and include serialization support via serde.

`libublk-rs-sys` is a `-sys` crate, which means it provides low-level FFI bindings without safe wrappers. If you're looking for a safe, high-level API, consider using the [`libublk`](https://crates.io/crates/libublk) crate instead.

## Use Cases

This crate is ideal when you need:

- **Custom io_uring management**: Handle ublk operations on your own io_uring instance instead of using libublk's thread-local ring
- **Direct kernel API access**: Work directly with the ublk kernel interface without abstractions
- **Custom block device implementations**: Build your own high-level wrappers around the ublk API
- **Integration with existing io_uring code**: Integrate ublk operations into your existing async I/O architecture

## Features

- Auto-generated bindings from Linux kernel headers
- Serde serialization support for all structs
- No runtime dependencies except `libc` and `serde`
- Support for all ublk features including:
  - Zero-copy operations
  - Automatic buffer registration
  - Zoned block device support
  - Unprivileged device creation
  - User recovery

## Requirements

- Linux kernel 6.0+ with `CONFIG_BLK_DEV_UBLK` enabled
- Rust 1.80 or later

## Example

```rust
use libublk_rs_sys::*;
use std::os::fd::AsRawFd;

// Open the ublk control device
let ctrl_fd = unsafe {
    libc::open(
        b"/dev/ublk-control\0".as_ptr() as *const i8,
        libc::O_RDWR,
    )
};

if ctrl_fd < 0 {
    panic!("Failed to open /dev/ublk-control");
}

// Create a control command structure
let mut cmd = ublksrv_ctrl_cmd {
    dev_id: 0,
    queue_id: !0u16, // -1 for device-level commands
    len: 0,
    addr: 0,
    data: [0; 1],
    dev_path_len: 0,
    pad: 0,
    reserved: 0,
};

// Use with your own io_uring instance for async operations...
```

## Safety

⚠️ **All functions and types in this crate are unsafe to use.** ⚠️

Improper use can lead to:
- Undefined behavior
- Kernel panics
- Data corruption
- System instability

Always refer to the [Linux kernel ublk documentation](https://docs.kernel.org/block/ublk.html) when using these bindings.

## Comparison with libublk

| Feature | libublk-rs-sys | libublk |
|---------|----------------|---------|
| Safety | Unsafe, raw FFI | Safe Rust API |
| io_uring | Bring your own | Managed thread-local |
| Abstraction | None | High-level builder patterns |
| Use case | Custom integrations | Quick ublk device creation |

## Documentation

- [Linux kernel ublk documentation](https://docs.kernel.org/block/ublk.html)
- [ublk introduction PDF](https://github.com/ming1/ubdsrv/blob/master/doc/ublk_intro.pdf)
- [Kernel header file](ublk_cmd.h)

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](../LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](../LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing

Contributions are welcome! Please see the main [libublk-rs repository](https://github.com/ublk-org/libublk-rs) for contribution guidelines.
