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
deleted after terminating this process by ctrl+C. Besides libublk, the
sample needs the `ctrlc` crate for the signal handler.

``` rust
use libublk::io::{UblkDev, UblkQueue};
use libublk::{ctrl::UblkCtrlBuilder, BufDesc, UblkRuntime};

// async/.await IO handling
async fn handle_io_cmd(q: &UblkQueue, tag: u16) -> i32 {
    (q.get_iod(tag).nr_sectors << 9) as i32
}

async fn io_task(q: &UblkQueue, tag: u16) -> Result<(), libublk::UblkError> {
    // IO buffer for exchange data with /dev/ublkbN
    let buf_bytes = q.dev().dev_info.max_io_buf_bytes as usize;
    let buf = libublk::helpers::IoBuf::<u8>::new(buf_bytes);

    // Submit initial prep command for setup IO forward
    q.submit_io_prep_cmd(tag, BufDesc::Slice(buf.as_slice()), 0, Some(&buf)).await?;

    loop {
        // Handle this incoming IO command, whole IO logic
        let res = handle_io_cmd(&q, tag).await;

        // Commit result and fetch next IO request
        q.submit_io_commit_cmd(tag, BufDesc::Slice(buf.as_slice()), res).await?;
    }
}

fn q_fn(qid: u16, dev: &std::sync::Arc<UblkDev>) {
    // Tokio current-thread runtime parked inside io_uring_enter: CQEs
    // wake the io tasks, and this returns once every task is done
    UblkRuntime::run_io_tasks(dev, qid, |q, tag| async move { io_task(&q, tag).await }).unwrap();
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
   async/await & io_uring, with target IO going through the typed
   operation catalog in [`libublk::ops`](src/ops.rs) (`read_at_raw`,
   `write_at_raw`, `sync_file_range`, ...).

 * [`examples/ramdisk.rs`](examples/ramdisk.rs): single thread &
   async/.await for both ctrl and IO, this technique will be extended to
   create multiple devices from single thread in future

`rublk`[^4] is based on libublk, and supports null, loop, zoned, qcow2,
compress & vram targets so far.

## Shared-memory zero copy (`UBLK_F_SHMEM_ZC`)

With `UBLK_F_SHMEM_ZC` in `ctrl_flags`, the server registers page-aligned
shared mappings — a hugetlbfs file, a memfd — with the driver
(`UblkCtrl::register_shmem_buf()`, or the `libublk::ShmemBufs` table that
keeps them by index). Whenever an application issues a block request whose
pages all lie inside a registered buffer, e.g. `fio --mem=mmaphuge:<file>`
over the same hugetlbfs file, the driver delivers it with
`UBLK_IO_F_SHMEM_ZC` set and `(index, offset)` encoded in `iod.addr`
instead of a buffer address, and copies nothing in either direction. The
queue handler resolves that to a pointer into its own mapping
(`ShmemBufs::resolve()`) and moves the data itself.

The match is per request and opportunistic: requests from other memory
keep taking whatever buffer path the handler passes in FETCH/COMMIT, so a
target checks `UBLK_IO_F_SHMEM_ZC` first and otherwise behaves as before.
See the `libublk::shmem` module docs and the `shmem_zc` tests in
[`tests/basic.rs`](tests/basic.rs).

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


## Mount namespace caveat (container / Kubernetes pod)

**The ublk daemon must not share a mount namespace with any process that
uses the ublk block device** (mounts a filesystem on `/dev/ublkbN`,
opens it for I/O, etc.).

Reason: the ublk daemon serves I/O for `/dev/ublkbN`, so I/O on that
device only makes forward progress while the daemon is alive. When the
daemon shares a mount namespace with a client of its own device (e.g. a
filesystem mounted on `/dev/ublkbN`), the daemon's exit can trigger an
unmount that flushes I/O to the device — but the daemon is exiting and
can no longer serve that I/O, so it self-deadlocks.

Run the daemon in its own mount namespace, e.g. by calling
`unshare(CLONE_NEWNS)` at startup or launching it under `unshare --mount`.
See
[`vmtest/tests/ublk-mntns-min.sh`](https://github.com/ming1/vmtest/blob/main/tests/ublk-mntns-min.sh)
for a minimal reproducer of what goes wrong otherwise. Tracked at
[libublk-rs#50](https://github.com/ublk-org/libublk-rs/issues/50).

## Test

You can run the test of the library with ```cargo test```

## Performance

When running fio `t/io_uring /dev/ublkb0`[^2], IOPS is basically same with
running same test over ublk device created by blktests `miniublk`[^3], which
is written by pure C. And the ublk device is null, which has 2 queues, each
queue's depth is 64.

### Benchmarking caveat: one submitter measures one queue

blk-mq maps a request to the hw queue of the *submitting* CPU, so a single
fio/`t/io_uring` thread drives exactly one ublk queue thread, and IOPS is
capped by that one thread's per-IO CPU cost (roughly 450K 4k-IOPS for the
copy-based `loop` example) regardless of `-q`.

The cap moves in a counter-intuitive way with `-d`: when the submitter's
queue depth *exceeds* the ublk queue depth, the excess requests fail tag
allocation with `-EAGAIN`, io_uring punts them to `iou-wrk` threads on other
CPUs, and those land on *other* ublk queues. So `t/io_uring -d 128` against
a `-d 64` device quietly uses several queue threads and reports higher IOPS
than the same test against a `-d 128` device, where all 128 IOs fit in one
queue. That is the benchmark spreading itself out, not a slower daemon.

To measure the device rather than one queue, use several submitters
(`t/io_uring -n 8 ...`, or fio `numjobs=`) so every queue is loaded. Under
that load a deeper queue wins as expected (`-d 128` ≈ 3M vs `-d 64` ≈ 1.9M
4k-IOPS on the same NVMe with 8 queues).

When one hw queue really is the bottleneck — one submitter, or a workload
that concentrates on a few queues — give the queue more threads instead of
relying on that accident: `UblkCtrlBuilder::io_threads_per_queue(n)`
(loop example: `-T n`) splits every queue's tags across `n` io threads
(`UBLK_F_PER_IO_DAEMON`, Linux 6.16+), interleaved (`k, k+n, …`) so that
whatever window of tags blk-mq has in flight lands on all `n` threads, all
bound to the queue's CPU affinity. On the machine above `-d 128 -T 2` with
one submitter reaches ~800K 4k-IOPS and `-T 4` about 1M, independent of
`-d`, beating the `-d 64` number by a wide margin; keeping the
threads inside the queue's affinity mask is what makes it work (the mask
contains the submitter's CPU; a thread outside that L3 domain halves its
IPC on this workload).

> **⚠️ Only for batched workloads.** Enable `io_threads_per_queue` only
> when the workload keeps many requests in flight per queue — **batched
> submission** or high queue depth. **Otherwise leave it at the default
> of 1.** The extra threads get parallel work only when several requests
> reach the queue at once; each request still costs the same, and a
> request now lands on whichever thread owns its tag, so a QD-1 or
> one-IO-per-submit workload gains nothing and pays for the extra wakeups
> and the split cache footprint. Measured on the same setup (`-d 128`,
> one submitter, `-T 1` → `-T 4`):
>
> | submitter | `-T 1` | `-T 4` |
> |---|---|---|
> | QD 1, one IO per submit | 29.1K | 28.4K (≈1 µs more latency) |
> | QD 8, one IO per submit | 210K | 214K |
> | QD 32, one IO per submit | 360K | 510K |
> | QD 128, batches of 32 | 420K | **990K** |

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
