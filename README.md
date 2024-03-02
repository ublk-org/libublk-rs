# Libublk

[![license](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/ming1/libublk-rs/blob/master/LICENSE-MIT)
[![license](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/ming1/libublk-rs/blob/master/LICENSE-APACHE)

Rust library for building linux ublk target device, which talks with
linux `ublk driver`[^1] for exposing standard linux block device,
meantime all target IO logic is implemented in userspace.

Linux kernel 6.0 starts to support ublk covered by config option of
CONFIG_BLK_DEV_UBLK.

## Documentations

[ublk doc
links](https://github.com/ming1/ubdsrv/blob/master/doc/external_links.rst)

[ublk
introduction](https://github.com/ming1/ubdsrv/blob/master/doc/ublk_intro.pdf)

## Quick Start

Follows one 2-queue ublk-null target which is built over libublk, ublk block
device(/dev/ublkbN) is created after the code is run. And the device will be
deleted after terminating this process by ctrl+C.

``` rust
use libublk::{ctrl::UblkCtrlBuilder, io::UblkDev, io::UblkQueue};

// async/.await IO handling
async fn handle_io_cmd(q: &UblkQueue<'_>, tag: u16) -> i32 {
    (q.get_iod(tag).nr_sectors << 9) as i32
}

// implement whole ublk IO level protocol
async fn io_task(q: &UblkQueue<'_>, tag: u16) {
    // IO buffer for exchange data with /dev/ublkbN
    let buf_bytes = q.dev.dev_info.max_io_buf_bytes as usize;
    let buf = libublk::helpers::IoBuf::<u8>::new(buf_bytes);
    let mut cmd_op = libublk::sys::UBLK_U_IO_FETCH_REQ;
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
        cmd_op = libublk::sys::UBLK_U_IO_COMMIT_AND_FETCH_REQ;
    }
}

fn q_fn(qid: u16, dev: &UblkDev) {
    let q_rc = std::rc::Rc::new(UblkQueue::new(qid as u16, &dev).unwrap());
    let exe = smol::LocalExecutor::new();
    let mut f_vec = Vec::new();

    for tag in 0..dev.dev_info.queue_depth {
        let q = q_rc.clone();

        f_vec.push(exe.spawn(async move { io_task(&q, tag).await }));
    }

    // Drive smol executor, won't exit until queue is dead
    libublk::uring_async::ublk_wait_and_handle_ios(&exe, &q_rc);
    smol::block_on(async { futures::future::join_all(f_vec).await });
}

fn main() {
    // Create ublk device
    let ctrl = std::sync::Arc::new(
        UblkCtrlBuilder::default()
            .name("async_null")
            .nr_queues(2)
            .dev_flags(libublk::UblkFlags::UBLK_DEV_F_ADD_DEV)
            .build()
            .unwrap(),
    );
    // Kill ublk device by handling "Ctrl + C"
    let ctrl_sig = ctrl.clone();
    let _ = ctrlc::set_handler(move || {
        ctrl_sig.kill_dev().unwrap();
    });

    // Now start this ublk target
    ctrl.run_target(
        // target initialization
        |dev| {
            dev.set_default_params(250_u64 << 30);
            Ok(())
        },
        // queue IO logic
        |tag, dev| q_fn(tag, dev),
        // dump device after it is started
        |dev| dev.dump(),
    )
    .unwrap();

    // Usually device is deleted automatically when `ctrl` drops, but
    // here `ctrl` is leaked by the global sig handler closure actually,
    // so we have to delete it explicitly
    ctrl.del_dev().unwrap();
}
```

 * [`examples/loop.rs`](examples/loop.rs): real example using
   async/await & io_uring.

 * [`examples/ramdisk.rs`](examples/ramdisk.rs): single thread &
   async/.await for both ctrl and IO, this technique will be extended to
   create multiple devices from single thread in future

`rublk`[^4] is based on libublk, and supports null, loop, zoned & qcow2 targets so
far.

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
[^4]: <https://github.com/ublk-org/rublk>
