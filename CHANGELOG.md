# Changelog

Notable changes to the `libublk` crate. The FFI crate `libublk-rs-sys`
is versioned separately (currently 0.1.2) and only changes when
`ublk_cmd.h` does.

## 0.5.0 (2026-11-19)

0.5 replaces the executor-coupled `uring_async` layer of 0.4 with an
executor-agnostic core:

- `libublk::ops`: a typed catalog of io_uring operations (file, socket,
  timer, raw SQE) returning plain futures keyed by an internal op slab, so
  `user_data` no longer carries tag/op bit fields.
- `libublk::reactor`: drives the thread-local rings from any executor's
  idle hook (`reap_events`, `wait_and_reap_events`, `has_pending_ops`).
- `libublk::executor`: the contract a custom executor implements
  (`UblkExecutor`, `UblkSpawner`, `UblkTask`) plus the runtime-agnostic
  `spawn_local` / `TaskHandle` that target code uses.
- `libublk::runtime::UblkRuntime` (default feature `tokio`): a Tokio
  current-thread runtime parked inside `io_uring_enter`.

The device/control API (`UblkCtrl`, `UblkCtrlBuilder`, `UblkDev`) and the
per-IO command API (`submit_io_prep_cmd`, `submit_io_commit_cmd`,
`complete_io_cmd_unified`, `BufDesc`) keep their shape, apart from the
signature changes in sections 8 onwards. Most porting work is in the
per-queue event loop and in how target IO is submitted.
`rublk` ported its event loop and target IO in one commit; see
[rublk `c4bdde5`](https://github.com/ublk-org/rublk/commit/c4bdde59888d5d70b6192d163bc8b25a6fca9575)
for a complete, real-world diff (null, loop, zoned, qcow2, compress,
vram targets). It predates the `unsafe` on `ublk_submit_sqe_sync`
(section 4) and the signature changes in sections 8 to 11.

See [docs/framework.md](docs/framework.md) for how the new pieces fit
together.

### Migrating from 0.4

#### 1. The per-queue event loop

0.4 targets built their own loop around a `smol::LocalExecutor` and
`wait_and_handle_io_events` / `run_uring_tasks`. 0.5 provides it:

```rust
// 0.4
fn q_fn(qid: u16, dev: &UblkDev) {
    let q = Rc::new(UblkQueue::new(qid, dev).unwrap());
    let exe = Rc::new(smol::LocalExecutor::new());
    let tasks: Vec<_> = (0..dev.dev_info.queue_depth)
        .map(|tag| exe.spawn(io_task(q.clone(), tag)))
        .collect();
    smol::block_on(exe.run(async {
        libublk::wait_and_handle_io_events(&q, Some(20),
            || while exe.try_tick() {},
            || tasks.iter().all(|t| t.is_finished())).await.unwrap();
    }));
}

// 0.5
fn q_fn(qid: u16, dev: &Arc<UblkDev>) {
    UblkRuntime::run_io_tasks(dev, qid, |q, tag| io_task(q, tag)).unwrap();
}
```

`run_io_tasks` creates the queue, spawns one task per tag the queue
serves (`UblkQueue::tags()`, so it also covers
`io_threads_per_queue(n)` partitions), and returns once every task has
ended. A task returning `Err(UblkError::QueueIsDown)` is the normal exit.
Any other error is logged, fails the device's buffer-registration
handshake so `run_target()` returns an error instead of hanging, and is
returned once all tasks ended.

Threads that run more than io tasks (control commands, timers) use
`UblkRuntime::new()` + `block_on()` directly; `examples/ramdisk.rs` runs
control and IO on one thread this way. Inside `block_on`, spawn with
`libublk::spawn_local` (executor-agnostic) or `tokio::task::spawn_local`.

To use another executor, disable the `tokio` feature and either call
`libublk::reactor::wait_and_reap_events()` from the executor's idle
hook, or implement `UblkExecutor` (rublk's `smol_rt.rs` is a 100-line
example on smol). The `executor` module docs state the liveness rules a
`block_on` implementation must follow; `ParkOutcome::SafetyTimeout` must
make the executor re-enter its scheduler loop rather than park on a
primitive a CQE cannot wake.

#### 2. `UblkQueue` owns `Arc<UblkDev>` and has no lifetime

| 0.4 | 0.5 |
|---|---|
| `UblkQueue<'a>`, `Rc<UblkQueue<'_>>` | `UblkQueue`, `Rc<UblkQueue>` |
| `UblkQueue::new(qid, dev: &UblkDev)` | `UblkQueue::new(qid, dev: &Arc<UblkDev>)` |
| `q.dev.dev_info` (public field) | `q.dev().dev_info` |
| `run_target(.., \|qid, dev: &UblkDev\| .., ..)` | `run_target(.., \|qid, dev: &Arc<UblkDev>\| .., ..)` |
| `UblkBatchQueue<'queue, 'dev>` | `UblkBatchQueue<'queue>` |

`UblkBatchQueue::queue()` returns `&UblkQueue`.

#### 3. Completion results are a plain `i32`

`UblkIORes`, `UblkFatRes` and the `fat_complete` feature are gone. The
io result is the `i32` the kernel gets (`nr_sectors << 9`, or a negative
errno):

```rust
// 0.4
q.complete_io_cmd_unified(tag, buf_desc, Ok(UblkIORes::Result(res)))?;
// 0.5
q.complete_io_cmd_unified(tag, buf_desc, res)?;
```

A zone-append LBA travels in the buffer descriptor,
`BufDesc::ZonedAppendLba(lba)`, with both `submit_io_commit_cmd` and
`complete_io_cmd_unified` (this was already the unified-API form in 0.4;
`UblkFatRes::ZonedAppendRes` was the legacy one). Batch completion
(`UblkFatRes::BatchRes`, `UBLK_DEV_F_COMP_BATCH`) is gone too; the
`UBLK_F_BATCH_IO` transport (`UblkBatchQueue`) is the replacement.

#### 4. Target IO goes through the typed `ops` catalog

`UblkUringOpFuture` and the bit-encoded `user_data` for async IO are
gone; `UblkIOCtx::build_user_data_async` and `UblkUringData::NonAsync`
with them. Target IO is submitted through `libublk::ops`:

```rust
// 0.4
let sqe = opcode::Read::new(types::Fixed(1), buf.as_mut_ptr(), len)
    .offset(off).build().user_data(UblkIOCtx::build_user_data_async(tag, op, 0));
let res = q.ublk_submit_sqe(sqe).await;

// 0.5
use libublk::ops::{self, TgtFd};
const BACK_FILE: TgtFd = TgtFd::Fixed(1);
// SAFETY: `buf` outlives the await
let res = unsafe { ops::read_at_raw(BACK_FILE, buf.as_mut_ptr(), len, off) }?.await;
```

Every catalog function returns `Result<impl Future, UblkError>`: the
`Err` is a submission failure (no thread-local ring, bad argument), the
future resolves to the CQE result. `TgtFd::Fixed(index)` addresses a
file registered in `UblkTgt::fds`, `TgtFd::Raw(fd)` any other fd.
Buffer-carrying ops come in three forms: owned `Box<[u8]>` (`read_at`,
returns `(res, buf)`), `_raw` pointer (caller keeps the buffer alive
across the await), and `_fixed` registered buffer (`UBLK_F_AUTO_BUF_REG`
zero copy: buffer index = tag and `addr` is the byte offset into the
request's data, see `examples/loop.rs -z`). Sockets add
`send_zc` / `send_zc_fixed` / `sendmsg_zc` (returning `SendZcOp`:
`sent()` resolves with the send result, `into_notif()` yields the
future that gates buffer reuse), `accept`, `poll_add`, `poll_multi` and
`recv*`. The pointer and registered-buffer send ops (`send_raw`,
`send_fixed`, `send_zc`, `send_zc_fixed`, `sendmsg_raw`, `sendmsg_zc`)
take a trailing `linked: bool` that sets `IOSQE_IO_LINK`, for
header-before-payload chains; the owned-buffer `send` does not.
`send_fixed` documents the rules a chain must follow.

A hand-built SQE still works: `unsafe { q.ublk_submit_sqe(sqe) }?.await`
or `ops::submit_sqe(sqe)`. Do not set `user_data` on it; the library
keys the SQE itself, and the handle is single-shot: multishot opcodes
and two-CQE opcodes (`SendZc`, `SendMsgZc`) must go through the typed
ops (`poll_multi`, `timeout_multi`, `send_zc`, `sendmsg_zc`) that fold
their completions.

The sync event loop (`wait_and_handle_io`, `flush_and_wake_io_tasks`)
is unchanged except that `ublk_submit_sqe_sync` now takes the
target-owned `user_data` word as a parameter instead of reading it from
the SQE, and is `unsafe` like `ublk_submit_sqe` and `ops::submit_sqe`:
the memory the SQE references must outlive its CQE.

```rust
// 0.4
q.ublk_submit_sqe_sync(sqe.user_data(data))?;
// 0.5
// SAFETY: the SQE references this tag's queue-slot buffer
unsafe { q.ublk_submit_sqe_sync(sqe, data) }?;
```

#### 5. Removed items and their replacements

| Removed | Use instead |
|---|---|
| module `uring_async`; root re-exports `run_uring_tasks`, `wait_and_handle_io_events`, `ublk_reap_events_with_handler`, `uring_poll_io_fn` | `UblkRuntime::run_io_tasks`, `UblkExecutor`, `libublk::reactor` |
| `with_queue_ring`, `with_queue_ring_mut` | `with_task_io_ring`, `with_task_io_ring_mut` (thread-local, no queue argument) |
| `UblkQueue::{complete_io_cmd, complete_io_cmd_with_auto_buf_reg}` | `complete_io_cmd_unified(tag, BufDesc, i32)` |
| `UblkQueue::{submit_io_cmd, submit_io_cmd_with_auto_buf_reg}` | `submit_io_prep_cmd` / `submit_io_commit_cmd` |
| `UblkQueue::{submit_fetch_commands, submit_fetch_commands_with_auto_buf_reg, regiser_io_bufs}` | `submit_fetch_commands_unified(BufDescList)` (returns `Result<Self, _>`) |
| `UblkQueue::register_io_buf` | `submit_io_prep_cmd(tag, BufDesc::Slice(buf.as_slice()))` registers the buffer |
| `BufDesc::RawAddress(*const u8)` | `BufDesc::Slice(unsafe { std::slice::from_raw_parts(ptr, len) })`, which puts the `unsafe` where the pointer is made; the prep command registers it as the tag's buffer (section 10) |
| `UblkQueue::{uring_op, uring_op_mut}` | `with_task_io_ring(_mut)` |
| `UblkQueue::get_inflight_nr_io` | `is_idle()` |
| `UblkQueue::submit_register_io_buf` / `submit_unregister_io_buf` returning `UblkUringOpFuture` | same names, now `Result<ops::RawOp, UblkError>` |
| `UblkError::UringTimeout`, `UblkError::UringIoQueued` | never produced; match `_` |
| `UblkUringData::NonAsync` | gone; async ops carry no bit-encoded metadata |
| `UblkFlags::UBLK_DEV_F_COMP_BATCH` | `UBLK_F_BATCH_IO` transport |
| feature `fat_complete` | gone |
| `with_*_internal!` macros | were never meant to be public |
| `UblkDev::{wait_for_buffer_registration, notify_buffer_registration_complete}`, `UblkQueueAffinity::{buf_len, addr}`, `helpers::type_of_this` | crate-private now: the queue/ctrl startup handshake, the affinity command's buffer, and `IoBuf`'s `Debug` helper |

#### 6. Non-exhaustive types

`UblkError`, `BufDesc`, `BufDescList`, `UblkUringData`, `ops::TgtFd` and
`reactor::ParkOutcome` are `#[non_exhaustive]`: matches need a `_` arm.
`UblkError::errno()` maps any error to the negative errno a ublk server
completes a failed io command with. `UblkTgt` is a `#[non_exhaustive]`
struct: a target sets fields on `dev.tgt` in its init closure instead
of building the struct with a literal.

#### 7. Dependencies and features

- `smol` is no longer a dependency.
- `tokio >= 1.52` (`rt` feature) is an optional dependency behind the
  default feature `tokio`; `--no-default-features` leaves only the
  reactor and the `executor` contract.
- `io-uring ^0.7.12` is re-exported as `libublk::io_uring` and `tokio`
  as `libublk::tokio`, since `squeue::Entry` and the Tokio runtime appear
  in the public API. Use the re-exports instead of declaring a separate
  version.
- `IoBuf<T>` is `Send`/`Sync` only when `T` is (it used to claim both
  unconditionally).
- `UBLK_F_NEED_GET_DATA` is rejected with `UblkError::InvalidVal` at
  build time: nothing in the crate answers `UBLK_IO_RES_NEED_GET_DATA`,
  so a device created with it hung every write.

#### 8. Control commands return `Result<(), UblkError>`

The `UblkCtrl` methods that send a control command or wrap one
(`read_dev_info`, `get_params`, `set_params`, `get_queue_affinity`,
`get_queue_effective_affinity`, `configure_queue`, `start_dev`,
`start_dev_async`, `start_user_recover`, `stop_dev`, `kill_dev`,
`quiesce_dev`, `update_size`, `del_dev`, `del_dev_async`, `run_target`,
`flush_json`, `reload_json`)
and their `UblkCtrlAsync` counterparts returned `Result<i32, UblkError>`
whose `Ok` value was always `0`, except that a command failing with
`-EBUSY` came back as `Ok(-EBUSY)`. They return `Result<(), UblkError>`
now, and `-EBUSY` is `Err(UblkError::UringIOError(-EBUSY))` like every
other errno; `start_user_recover` keeps retrying it internally. Code
that tested the `Ok` value for `-EBUSY` (`quiesce_dev` on timeout)
needs an `Err` arm instead.

#### 9. Tags, queue ids, queue counts and depths are `u16`

`UblkIOCtx::get_tag()` and `UblkIOCtx::user_data_to_tag()` return `u16`
(was `u32`); `get_queue_tid(qid)` and `get_queue_affinity(qid, ..)` on
`UblkCtrl` and `UblkCtrlAsync` take `u16` (was `u32`); `UblkCtrl::new`
and `UblkCtrlAsync::new` take `nr_queues` and `depth` as `u16`
(was `u32`); `UblkQueue::get_depth()` and `nr_tags()` return `u16`
(was `u32`). That is the width of `ublksrv_ctrl_dev_info` and of every
other tag and queue-id parameter in the crate (`get_iod(tag: u16)`,
`configure_queue(qid: u16)`, `UblkCtrlBuilder::nr_queues(u16)`), so
the `as u32` / `as u16` casts around them can go.

#### 10. `submit_io_prep_cmd(tag, buf_desc)`

The prep command took `(tag, buf_desc, result, io_buf)`. The kernel
ignores `result` for `FETCH_REQ` and every caller passed `0`;
`io_buf: Option<&IoBuf<u8>>` had to alias `buf_desc` and existed only
so the queue could register the buffer. Both are gone, and the buffer
descriptor is unchanged: porting a call means deleting its last two
arguments.

```rust
// 0.4
q.submit_io_prep_cmd(tag, BufDesc::Slice(buf.as_slice()), 0, Some(&buf)).await?;
q.submit_io_prep_cmd(tag, BufDesc::AutoReg(reg), 0, None).await?;
// 0.5
q.submit_io_prep_cmd(tag, BufDesc::Slice(buf.as_slice())).await?;
q.submit_io_prep_cmd(tag, BufDesc::AutoReg(reg)).await?;
```

The prep command registers a non-empty `BufDesc::Slice` as the tag's
copy-mode buffer itself: it records the address, so device start counts
the tag, and under `UBLK_DEV_F_MLOCK_IO_BUFFER` it locks the slice's
range and unlocks it when a prep or commit command for the tag returns
`Err` (`QueueIsDown` at teardown; a negative `Ok` value is a result,
not a failure). The slice need not be an `IoBuf`: a piece
of a pool, an mmap or memory from another allocator works the same way,
as long as the target keeps it valid until such a command has returned `Err`,
which is when an io task returns anyway. 0.4 accepted such a buffer only as
`BufDesc::RawAddress`, and without registering it, so device start
never completed on a plain copy-mode device. One visible difference
under mlock: the queue holds the lock, so `IoBuf::is_mlocked()` stays
`false` for a buffer registered this way.

```rust
// 0.5, target-owned buffer: a slice of the target's pool
q.submit_io_prep_cmd(tag, BufDesc::Slice(&pool[off..off + io_size])).await?;
```

#### 11. `UblkCtrlAsync` methods drop the `_async` suffix

`UblkCtrlAsync` is the `.await` form of `UblkCtrl`, so its methods now
carry the names of their `UblkCtrl` counterparts: `new`, `new_simple`,
`configure_queue`, `dump`, `read_dev_info`, `get_params`,
`set_params`, `get_queue_affinity`, `start_user_recover`, `start_dev`,
`stop_dev`, `kill_dev`, `quiesce_dev`, `update_size`,
`register_shmem_buf`, `unregister_shmem_buf`, `set_thread_affinity`,
and `del_dev` in place of `del_dev_async_await`. Nothing moves on
`UblkCtrl`: `UblkCtrl::start_dev_async` is still the one awaitable
call on the sync handle, and `UblkCtrl::del_dev_async` still issues
the kernel's deferred `UBLK_U_CMD_DEL_DEV_ASYNC`.
`UblkCtrlBuilder::build_async` and `UblkDev::new_async` keep their
names, since each sits beside the sync form on the same type.

### Added

- `executor` module: `UblkExecutor`, `UblkSpawner`, `UblkTask`,
  `TaskHandle`, `spawn_local`, `with_ambient_spawner` (also re-exported
  from the crate root).
- `reactor` module: `reap_events`, `wait_and_reap_events`,
  `has_pending_ops`, `ParkOutcome`.
- `runtime::UblkRuntime` (`tokio` feature), re-exported as
  `libublk::UblkRuntime`.
- `ops` module: `read_at`, `write_at`, `read_at_raw`, `write_at_raw`,
  `read_at_fixed`, `write_at_fixed`, `fsync`, `fallocate`,
  `sync_file_range`, `send`, `recv`, `send_raw`, `recv_raw`,
  `send_fixed`, `recv_fixed`, `send_zc`, `send_zc_fixed`, `sendmsg_raw`,
  `sendmsg_zc`, `accept`, `poll_add`, `poll_multi`, `sleep`,
  `timeout_multi`, `nop`, `submit_sqe`, `uring_cmd16`, `uring_cmd80`,
  `uring_cmd80_buf`; types `TgtFd`, `RawOp`, `BufOp`, `Accept`, `Sleep`,
  `SendZcOp`, `ZcNotif`, `PollMulti`, `TimeoutMulti`, `MultishotItem`.
- Shared-memory zero copy (`UBLK_F_SHMEM_ZC`): `shmem::{ShmemBuf,
  ShmemBufs, ShmemZcAddr}`, `UblkCtrl::register_shmem_buf` /
  `unregister_shmem_buf` and their `UblkCtrlAsync` counterparts. See the
  README section and the `shmem` module docs.
- `UblkCtrlBuilder` accepts `UBLK_F_USER_RECOVERY_FAIL_IO` (and
  `run_target` recovers a device that is in `UBLK_S_DEV_FAIL_IO`) and
  `UBLK_F_NO_AUTO_PART_SCAN`.
- `UblkIOCtx::cqe_flags()` and `has_more()`.
- `io::RawSqe` mirrors `io_uring_sqe` (checked by a layout test) and
  `io::AsRawSqe` gives mutable access to it from `squeue::Entry` /
  `Entry128`.
- `UblkError::errno()`.
- `docs/framework.md`: framework and core design document.
- `tests/examples.rs` runs every example binary against a real device;
  `examples/loop.rs` gained `-z` (`UBLK_F_AUTO_BUF_REG` zero copy);
  `examples/batch.rs` was redesigned around task-driven write batching.

### Fixed

- ctrl: a control command that failed with `-ENODEV` is no longer
  retried with the legacy opcode (the retry turned the error into
  `-EOPNOTSUPP` on kernels without `CONFIG_BLKDEV_UBLK_LEGACY_OPCODES`).
- ctrl: async control commands keep their buffer payload alive for the
  whole op.
- io: the FETCH command is armed only after buffer registration
  succeeds; registrations are unwound when `UblkQueue::new` fails
  partway; stale ABORT results from orphaned commands are ignored;
  `cmd_inflight` saturates instead of underflowing on stale completions;
  deferred CQEs are delivered even when the ring wait fails.
- io: an io task that fails before registering its buffer unparks its
  sibling tasks and fails the device handshake, so `run_target` returns
  an error instead of hanging.
- io: `UblkIOCtx::build_user_data` no longer silently truncates
  `tgt_data` to 8 bits.
- op: in-flight resources are leaked rather than freed at thread exit;
  the fd carried by a discarded `accept` completion is closed.
- executor: `UblkRuntime` spawns onto its own `LocalSet`, so a nested
  `LocalSet::run_until` in target code cannot capture and destroy
  library tasks; a task spawned before `block_on` starts once it runs.
- reactor: the park-safety timeout returns to the executor so deferred
  runnable work cannot deadlock startup on deep queues.

## 0.4.8 and earlier

See the git history; releases before 0.5.0 had no changelog.
