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
libublk = "0.2"
```

Next we can start using `libublk` crate.
The following is quick introduction for creating one ublk-null target,
and ublk block device(/dev/ublkbN) will be created after the code is
run. And the device will be deleted after terminating this process
by ctrl+C.

``` rust
use libublk::{ctrl::UblkCtrl, io::UblkDev, io::UblkQueue};

fn main() {
    // Kill ublk device by handling "Ctrl + c"
    let g_dev_id = std::sync::Arc::new(std::sync::Mutex::new(-1));
    let dev_id_sig = g_dev_id.clone();
    let _ = ctrlc::set_handler(move || {
        let dev_id = *dev_id_sig.lock().unwrap();
        if dev_id >= 0 {
            UblkCtrl::new_simple(dev_id, 0).unwrap().kill_dev().unwrap();
        }
    });

    // Create ublk device
    let sess = libublk::UblkSessionBuilder::default()
        .name("async_null")
        .depth(64_u32)
        .nr_queues(2_u32)
        .dev_flags(libublk::dev_flags::UBLK_DEV_F_ADD_DEV)
        .build()
        .unwrap();
    let tgt_init = |dev: &mut UblkDev| {
        dev.set_default_params(250_u64 << 30);
        Ok(0)
    };
    let (mut ctrl, dev) = sess.create_devices(tgt_init).unwrap();

    // Queue handler implements whole IO logic
    let q_handler = move |qid: u16, dev: &UblkDev| {
        let q_rc = std::rc::Rc::new(UblkQueue::new(qid as u16, &dev).unwrap());
        let exe = smol::LocalExecutor::new();
        let mut f_vec = Vec::new();

        // async/.await IO handling
        async fn handle_io_cmd(q: &UblkQueue<'_>, tag: u16) -> i32 {
            (q.get_iod(tag).nr_sectors << 9) as i32
        }

        for tag in 0..dev.dev_info.queue_depth {
            let q = q_rc.clone();
            let buf_bytes = q.dev.dev_info.max_io_buf_bytes as usize;

            f_vec.push(exe.spawn(async move {
                // IO buffer for exchange data with /dev/ublkbN
                let buf = libublk::helpers::IoBuf::<u8>::new(buf_bytes);
                let mut cmd_op = libublk::sys::UBLK_IO_FETCH_REQ;
                let mut res = 0;

                // Register IO buffer, so that buffer pages can be discarded
                // when queue becomes idle
                q.register_io_buf(tag, &buf);
                loop {
                    // Complete previous command with result and re-submit
                    // IO command for fetching new IO request from /dev/ublkbN
                    res = q.submit_io_cmd(tag, cmd_op, buf.as_mut_ptr(), res).await;
                    if res == libublk::sys::UBLK_IO_RES_ABORT {
                        break;
                    }

                    // Handle this incoming IO command
                    res = handle_io_cmd(&q, tag).await;
                    cmd_op = libublk::sys::UBLK_IO_COMMIT_AND_FETCH_REQ;
                }
            }));
        }

        // Drive smol executor, won't exit until queue is dead
        libublk::uring_async::ublk_wait_and_handle_ios(&q_rc, &exe);
        smol::block_on(async { futures::future::join_all(f_vec).await });
    };

    // Now start this ublk target
    let dev_id_wh = g_dev_id.clone();
    sess.run_target(&mut ctrl, &dev, q_handler, move |dev_id| {
        UblkCtrl::new_simple(dev_id, 0).unwrap().dump();
        *dev_id_wh.lock().unwrap() = dev_id;
    })
    .unwrap();
}
```

With Rust async/.await, each io command is handled in one standalone io task.
Both io command submission and its handling can be written via .await, it looks
like sync programming, but everything is run in async actually. .await can
be nested inside handle_io_cmd(), futures::join!() is supported too.

Device wide data can be shared in each queue/io handler by
Arc::new(Mutex::new(Data)) and the queue handler closure supports Clone(),
see [`test_ublk_null_async():tests/basic.rs`](tests/basic.rs)

Queue wide data is per-thread and can be shared in io handler by
Rc() & RefCell().


 * [`examples/loop.rs`](examples/loop.rs): real example using async/await & io_uring.


## unprivileged ublk support

In unprivileged mode(`UBLK_F_UNPRIVILEGED_DEV`), ublk device can be created
in non-admin user session. For supporting this feature:

- install udev rules

```
KERNEL=="ublk-control", MODE="0666", OPTIONS+="static_node=ublk-control"
ACTION=="add",KERNEL=="ublk[bc]*",RUN+="/usr/local/sbin/ublk_chown.sh %k 'add' '%M' '%m'"
ACTION=="remove",KERNEL=="ublk[bc]*",RUN+="/usr/local/sbin/ublk_chown.sh %k 'remove' '%M' '%m'"
```

- install utility and script

`utils/ublk_chown.sh` and binary of `utils/ublk_user_id.rs` needs to be
installed under /usr/local/sbin or other directory which has to match
with the udev rules.


## Test

You can run the test of the library with ```cargo test```

## Performance

When running fio `t/io_uring /dev/ublkb0`[^2], IOPS is basically same with
running same test over ublk device created by blktests `miniublk`[^3], which
is written by pure C. And the ublk device is null, which has 2 queues, each
queue's depth is 64.

## Example

### loop

  cargo run \--example loop help

### null

  cargo run \--example null help

## License

This project is licensed under either of Apache License, Version 2.0 or
MIT license at your option.

## Contributing

Any kinds of contributions are welcome!

## References

[^1]: <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/block/ublk_drv.c?h=v6.0>
[^2]: <https://github.com/axboe/fio/blob/master/t/io_uring.c>
[^3]: <https://github.com/osandov/blktests/blob/master/src/miniublk.c>
