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
The following is quick introduction for adding ublk-null block device.

``` rust
use libublk::ctrl::UblkCtrl;
use libublk::io::{UblkDev, UblkIOCtx, UblkQueue};
use std::sync::Arc;

fn main() {
    let nr_queues = 2; //two queues
                       //io depth: 64, max buf size: 512KB
    let mut ctrl = UblkCtrl::new(-1, nr_queues, 64, 512 << 10, 0, true).unwrap();

    // target specific initialization by tgt_init closure, which is flexible
    // for customizing target with captured environment
    let tgt_init = |dev: &mut UblkDev| {
        dev.set_default_params(250_u64 << 30);
        Ok(serde_json::json!({}))
    };
    let ublk_dev =
        Arc::new(UblkDev::new("null".to_string(), tgt_init, &mut ctrl, 0).unwrap());
    let mut threads = Vec::new();

    for q in 0..nr_queues {
        let dev = Arc::clone(&ublk_dev);
        threads.push(std::thread::spawn(move || {
            let mut queue = UblkQueue::new(q as u16, &dev).unwrap();
            let ctx = queue.make_queue_ctx();

            //IO handling closure(FnMut), we are driven by io_uring
            //CQE, and this closure is called for every incoming CQE
            //(IO command or target io completion)
            let io_handler = move |io: &mut UblkIOCtx| {
                let iod = ctx.get_iod(io.get_tag());
                let bytes = unsafe { (*iod).nr_sectors << 9 } as i32;

                io.complete_io(bytes);
                Ok(0)
            };
            queue.wait_and_handle_io(io_handler);
        }));
    }
    ctrl.start_dev(&ublk_dev).unwrap();
    ctrl.dump();
    for qh in threads {
        qh.join().unwrap();
    }
    ctrl.stop_dev(&ublk_dev).unwrap();
}
```

## Test

You can run the test of the library with the following command.

```
# cargo test
```

## Performance

When running fio `t/io_uring /dev/ublkb0`[^2], IOPS is basically same with
running same test over ublk device created by blktests `miniublk`[^3], which
is written by pure C. And the ublk device is null, which has 2 queues, each
queue's depth is 64.

## Examples

### null

-   add one null ublk device

    cargo run \--example null \-- add

-   del one null ublk device

    cargo run \--example null \-- del \[dev_id\]

### loop

-   add one loop ublk device

    cargo run \--example loop \-- add \${backing_file_path}

-   del one loop ublk device

    cargo run \--example loop \-- del \[dev_id\]

## License

This project is licensed under either of Apache License, Version 2.0 or
MIT license at your option.

## Contribution

Any kinds of contributions are welcome!

## References

[^1]: <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/block/ublk_drv.c?h=v6.0>
[^2]: <https://github.com/axboe/fio/blob/master/t/io_uring.c>
[^3]: <https://github.com/osandov/blktests/blob/master/src/miniublk.c>
