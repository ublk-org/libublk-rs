# Libublk

[![license](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/ming1/libublk-rs/blob/master/LICENSE-MIT)
[![license](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/ming1/libublk-rs/blob/master/LICENSE-APACHE)

Rust library for building linux ublk target device, which talks with
linux `ublk driver`[^1] for exposing standard linux block device,
meantime all target IO logic can be moved to userspace.

Linux kernel 6.0 starts to support ublk covered by config option of
CONFIG_BLK_DEV_UBLK.

## Documentations

[ublk doc
links](https://github.com/ming1/ubdsrv/blob/master/doc/external_links.rst)

[ublk
introduction](https://github.com/ming1/ubdsrv/blob/master/doc/ublk_intro.pdf)

## Quick Start

Follows one totally working 2-queue ublk-null target which is built over
libublk 0.1, and each queue depth is 64, and each IO\'s max buffer size
is 512KB.

To use `libublk` crate, first add this to your `Cargo.toml`:

```toml
[dependencies]
libublk = "0.1"
```

Next we can start using `libublk` crate.
The following is quick introduction for adding ublk-null block device, which
is built over libublk high level APIs.

``` rust
use libublk::io::{UblkDev, UblkIOCtx, UblkQueue};
use libublk::{ctrl::UblkCtrl, UblkIORes};
use libublk::dev_flags::*;

fn main() {
    let sess = libublk::UblkSessionBuilder::default()
        .name("null")
        .depth(64_u32)
        .nr_queues(2_u32)
        .dev_flags(UBLK_DEV_F_ADD_DEV)
        .build()
        .unwrap();
    let tgt_init = |dev: &mut UblkDev| {
        dev.set_default_params(250_u64 << 30);
        Ok(serde_json::json!({}))
    };
    let wh = {
        let (mut ctrl, dev) = sess.create_devices(tgt_init).unwrap();
        let handle_io = move |q: &UblkQueue, tag: u16, _io: &UblkIOCtx| {
            let iod = q.get_iod(tag);
            let res = Ok(UblkIORes::Result(
                (unsafe { (*iod).nr_sectors << 9 } as i32),
            ));
            q.complete_io_cmd(tag, res);
        };

        sess.run(&mut ctrl, &dev, handle_io, |dev_id| {
            let mut d_ctrl = UblkCtrl::new_simple(dev_id, 0).unwrap();
            d_ctrl.dump();
        })
        .unwrap()
    };
    wh.join().unwrap();
}
```

## Test

You can run the test of the library with ```cargo test```

## Performance

When running fio `t/io_uring /dev/ublkb0`[^2], IOPS is basically same with
running same test over ublk device created by blktests `miniublk`[^3], which
is written by pure C. And the ublk device is null, which has 2 queues, each
queue's depth is 64.

## Example

### loop

-   add one loop ublk device

    cargo run \--example loop \-- add \${backing_file_path}

-   del one loop ublk device

    cargo run \--example loop \-- del \[dev_id\]

## License

This project is licensed under either of Apache License, Version 2.0 or
MIT license at your option.

## Contributing

Any kinds of contributions are welcome!

## References

[^1]: <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/block/ublk_drv.c?h=v6.0>
[^2]: <https://github.com/axboe/fio/blob/master/t/io_uring.c>
[^3]: <https://github.com/osandov/blktests/blob/master/src/miniublk.c>
