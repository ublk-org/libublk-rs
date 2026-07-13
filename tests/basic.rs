#[cfg(test)]
mod integration {
    use io_uring::opcode;
    use libublk::helpers::IoBuf;
    use libublk::io::{
        BufDescList, UblkBatchBuffers, UblkBatchCompletion, UblkBatchConfig, UblkBatchQueue,
        UblkDev, UblkIOCtx, UblkQueue,
    };
    use libublk::override_sqe;
    use libublk::{
        ctrl::UblkCtrl, ctrl::UblkCtrlBuilder, sys, BufDesc, UblkError, UblkFlags, UblkIORes,
    };
    use std::env;
    use std::io::{BufRead, BufReader};
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::rc::Rc;
    use std::sync::{Arc, Mutex};

    #[ctor::ctor]
    fn init_logger() {
        let _ = env_logger::builder()
            .format_target(false)
            .format_timestamp(None)
            .is_test(true)
            .try_init();
    }
    fn run_ublk_disk_sanity_test(ctrl: &UblkCtrl, dev_flags: UblkFlags) {
        use std::os::unix::fs::PermissionsExt;
        let dev_path = ctrl.get_cdev_path();

        std::thread::sleep(std::time::Duration::from_millis(500));

        let tgt_flags = ctrl.get_target_flags_from_json().unwrap();
        assert!(UblkFlags::from_bits(tgt_flags).unwrap() == dev_flags);

        //ublk block device should be observed now
        assert!(Path::new(&dev_path).exists() == true);

        //ublk exported json file should be observed
        let run_path = ctrl.run_path();
        let json_path = Path::new(&run_path);
        assert!(json_path.exists() == true);

        let metadata = std::fs::metadata(json_path).unwrap();
        let permissions = metadata.permissions();
        assert!((permissions.mode() & 0o777) == 0o700);
    }

    fn read_ublk_disk(ctrl: &UblkCtrl, success: bool) {
        let dev_path = ctrl.get_bdev_path();
        let mut arg_list: Vec<String> = Vec::new();
        let if_dev = format!("if={}", &dev_path);

        arg_list.push(if_dev);
        arg_list.push("of=/dev/null".to_string());
        arg_list.push("bs=4096".to_string());
        arg_list.push("count=10k".to_string());
        let out = Command::new("dd")
            .args(arg_list)
            .output()
            .expect("fail to run dd");

        assert!(out.status.success() == success);
    }

    fn __test_ublk_null(dev_flags: UblkFlags, q_handler: fn(u16, &Arc<UblkDev>)) {
        let ctrl = UblkCtrlBuilder::default()
            .name("null")
            .nr_queues(2)
            .dev_flags(dev_flags)
            .ctrl_flags(libublk::sys::UBLK_F_USER_COPY.into())
            .build()
            .unwrap();
        let tgt_init = |dev: &mut UblkDev| {
            dev.set_default_params(250_u64 << 30);
            Ok(())
        };

        let q_fn = move |qid: u16, _dev: &Arc<UblkDev>| {
            q_handler(qid, _dev);
        };

        ctrl.run_target(tgt_init, q_fn, move |ctrl: &UblkCtrl| {
            run_ublk_disk_sanity_test(ctrl, dev_flags);
            read_ublk_disk(ctrl, true);

            ctrl.kill_dev().unwrap();
        })
        .unwrap();
    }

    /// make one ublk-null and test if /dev/ublkbN can be created successfully
    #[test]
    fn test_ublk_null() {
        /// called from queue_handler closure(), which supports Clone(),
        fn null_handle_queue(qid: u16, dev: &Arc<UblkDev>) {
            let bufs_rc = Rc::new(dev.alloc_queue_io_bufs());
            let user_copy = (dev.dev_info.flags & libublk::sys::UBLK_F_USER_COPY as u64) != 0;
            let bufs = bufs_rc.clone();

            let io_handler = move |q: &UblkQueue, tag: u16, _io: &UblkIOCtx| {
                let iod = q.get_iod(tag);
                let bytes = (iod.nr_sectors << 9) as i32;

                let buf_desc = if user_copy {
                    BufDesc::Slice(&[]) // Empty slice for user_copy mode
                } else {
                    BufDesc::Slice(bufs[tag as usize].as_slice())
                };
                q.complete_io_cmd_unified(tag, buf_desc, Ok(UblkIORes::Result(bytes)))
                    .unwrap();
            };

            let queue = match UblkQueue::new(qid, dev)
                .unwrap()
                .submit_fetch_commands_unified(BufDescList::Slices(if user_copy {
                    None
                } else {
                    Some(&bufs_rc)
                })) {
                Ok(q) => q,
                Err(e) => {
                    log::error!("submit_fetch_commands_unified failed: {}", e);
                    return;
                }
            };

            queue.wait_and_handle_io(io_handler);
        }

        __test_ublk_null(UblkFlags::UBLK_DEV_F_ADD_DEV, null_handle_queue);
    }

    /// Make one batch-IO ublk-null device and exercise the high-level batch transport.
    #[test]
    fn test_ublk_null_batch_io() {
        if UblkCtrl::get_features().unwrap_or_default() & sys::UBLK_F_BATCH_IO as u64 == 0 {
            println!(
                "skipping batch IO integration test: kernel does not advertise UBLK_F_BATCH_IO"
            );
            return;
        }

        let ctrl = UblkCtrlBuilder::default()
            .name("batch_null")
            .nr_queues(2)
            .depth(64)
            .dev_flags(UblkFlags::UBLK_DEV_F_ADD_DEV)
            .ctrl_flags(sys::UBLK_F_BATCH_IO as u64)
            .build()
            .unwrap();
        let tgt_init = |dev: &mut UblkDev| {
            dev.set_default_params(250_u64 << 30);
            Ok(())
        };

        let q_fn = |qid: u16, dev: &UblkDev| {
            let queue = UblkQueue::new(qid, dev).unwrap();
            let buffers = dev.alloc_queue_io_bufs();
            let config = UblkBatchConfig::new()
                .with_fetch_buffer_count(2)
                .with_fetch_command_count(2)
                .with_max_inflight_commits(1)
                .with_tags_per_fetch_buffer(8);
            let mut batch =
                UblkBatchQueue::new(&queue, UblkBatchBuffers::IoBufs(buffers), config).unwrap();
            assert!(batch.try_submit_completions(&[]).unwrap());
            let mut pending = Vec::new();

            loop {
                let mut batch_error = None;
                queue
                    .flush_and_wake_io_tasks(
                        |_user_data, cqe, _is_last| match batch.handle_cqe(cqe, |batch, tags| {
                            for &tag in tags {
                                let iod = queue.get_iod(tag);
                                let bytes = (iod.nr_sectors << 9) as i32;
                                let result = match iod.op_flags & 0xff {
                                    sys::UBLK_IO_OP_READ => {
                                        batch.io_buf_mut(tag).unwrap().zero_buf();
                                        bytes
                                    }
                                    sys::UBLK_IO_OP_WRITE => bytes,
                                    sys::UBLK_IO_OP_FLUSH => 0,
                                    _ => -libc::EOPNOTSUPP,
                                };
                                pending.push(UblkBatchCompletion::new(tag, result));
                            }
                            Ok(())
                        }) {
                            Ok(true) | Ok(false) => {}
                            Err(error) => batch_error = Some(error),
                        },
                        1,
                    )
                    .unwrap();
                if let Some(error) = batch_error {
                    panic!("batch queue failed: {error}");
                }
                if !pending.is_empty() {
                    match batch.try_submit_completions(&pending) {
                        Ok(true) => pending.clear(),
                        Ok(false) => {}
                        Err(error) => panic!("batch commit failed: {error}"),
                    }
                }
                if batch.try_begin_shutdown().unwrap() && batch.is_shutdown_complete() {
                    break;
                }
            }
        };

        ctrl.run_target(tgt_init, q_fn, move |ctrl: &UblkCtrl| {
            run_ublk_disk_sanity_test(ctrl, UblkFlags::UBLK_DEV_F_ADD_DEV);
            read_ublk_disk(ctrl, true);
            ctrl.kill_dev().unwrap();
        })
        .unwrap();
    }

    /// Drive UBLK_F_BATCH_IO with a target that actually carries data.
    ///
    /// [`test_ublk_null_batch_io`] proves the transport starts, fetches and
    /// completes commands, but its null target discards writes and returns
    /// zeroes -- a batch that handed a tag the wrong buffer, or mixed up two
    /// tags in one fetch, would still pass. Back the device with RAM and put a
    /// filesystem on it instead: mkfs and mount only survive if every write
    /// landed where it was addressed and every read came back from the same
    /// place.
    #[test]
    fn test_ublk_ramdisk_batch_io() {
        if UblkCtrl::get_features().unwrap_or_default() & sys::UBLK_F_BATCH_IO as u64 == 0 {
            println!("skipping batch ramdisk test: kernel does not advertise UBLK_F_BATCH_IO");
            return;
        }

        let size = 32_u64 << 20;
        // Kept alive until run_target() returns; the queue only sees its address.
        let ramdisk_buf = IoBuf::<u8>::new(size as usize);
        let ramdisk_addr = ramdisk_buf.as_mut_ptr() as usize;

        // One queue, so the backing store has a single writer.
        let ctrl = UblkCtrlBuilder::default()
            .name("batch_rd")
            .nr_queues(1)
            .depth(64)
            .dev_flags(UblkFlags::UBLK_DEV_F_ADD_DEV)
            .ctrl_flags(sys::UBLK_F_BATCH_IO as u64)
            .build()
            .unwrap();

        let tgt_init = move |dev: &mut UblkDev| {
            dev.set_default_params(size);
            Ok(())
        };

        let q_fn = move |qid: u16, dev: &UblkDev| {
            let queue = UblkQueue::new(qid, dev).unwrap();
            let buffers = dev.alloc_queue_io_bufs();
            let config = UblkBatchConfig::new()
                .with_fetch_buffer_count(2)
                .with_fetch_command_count(2)
                .with_max_inflight_commits(1)
                .with_tags_per_fetch_buffer(8);
            let mut batch =
                UblkBatchQueue::new(&queue, UblkBatchBuffers::IoBufs(buffers), config).unwrap();
            assert!(batch.try_submit_completions(&[]).unwrap());
            let mut pending = Vec::new();

            loop {
                let mut batch_error = None;
                queue
                    .flush_and_wake_io_tasks(
                        |_user_data, cqe, _is_last| match batch.handle_cqe(cqe, |batch, tags| {
                            for &tag in tags {
                                let iod = queue.get_iod(tag);
                                let off = (iod.start_sector << 9) as usize;
                                let bytes = (iod.nr_sectors << 9) as usize;
                                let oob = off + bytes > size as usize;

                                let result = match iod.op_flags & 0xff {
                                    sys::UBLK_IO_OP_READ => {
                                        let buf = batch.io_buf_mut(tag).unwrap();
                                        if oob || bytes > buf.len() {
                                            -libc::EINVAL
                                        } else {
                                            // SAFETY: single queue, and the
                                            // range is bounds-checked above.
                                            unsafe {
                                                let rd = std::slice::from_raw_parts(
                                                    (ramdisk_addr + off) as *const u8,
                                                    bytes,
                                                );
                                                buf.as_mut_slice()[..bytes].copy_from_slice(rd);
                                            }
                                            bytes as i32
                                        }
                                    }
                                    sys::UBLK_IO_OP_WRITE => {
                                        let buf = batch.io_buf(tag).unwrap();
                                        if oob || bytes > buf.len() {
                                            -libc::EINVAL
                                        } else {
                                            // SAFETY: as above.
                                            unsafe {
                                                let rd = std::slice::from_raw_parts_mut(
                                                    (ramdisk_addr + off) as *mut u8,
                                                    bytes,
                                                );
                                                rd.copy_from_slice(&buf.as_slice()[..bytes]);
                                            }
                                            bytes as i32
                                        }
                                    }
                                    sys::UBLK_IO_OP_FLUSH => 0,
                                    _ => -libc::EOPNOTSUPP,
                                };
                                pending.push(UblkBatchCompletion::new(tag, result));
                            }
                            Ok(())
                        }) {
                            Ok(true) | Ok(false) => {}
                            Err(error) => batch_error = Some(error),
                        },
                        1,
                    )
                    .unwrap();
                if let Some(error) = batch_error {
                    panic!("batch queue failed: {error}");
                }
                if !pending.is_empty() {
                    match batch.try_submit_completions(&pending) {
                        Ok(true) => pending.clear(),
                        Ok(false) => {}
                        Err(error) => panic!("batch commit failed: {error}"),
                    }
                }
                if batch.try_begin_shutdown().unwrap() && batch.is_shutdown_complete() {
                    break;
                }
            }
        };

        ctrl.run_target(tgt_init, q_fn, move |ctrl: &UblkCtrl| {
            ublk_ramdisk_tester(ctrl, UblkFlags::UBLK_DEV_F_ADD_DEV);
        })
        .unwrap();

        drop(ramdisk_buf);
    }

    #[test]
    fn test_ublk_null_async() {
        // submit one io_uring Nop as a target IO: the op future is keyed
        // by the op slab, no user_data encoding needed
        async fn handle_io_cmd(q: &UblkQueue, tag: u16) -> i32 {
            let iod = q.get_iod(tag);
            let bytes = (iod.nr_sectors << 9) as i32;

            // SAFETY: NOP references no memory.
            let res = match unsafe { q.ublk_submit_sqe(opcode::Nop::new().build()) } {
                Ok(f) => f.await,
                Err(_) => 0,
            };
            bytes + res
        }

        async fn test_io_task(
            q: &UblkQueue,
            tag: u16,
            dev_data: &Arc<Mutex<DevData>>,
        ) -> Result<(), UblkError> {
            let buf = IoBuf::<u8>::new(q.dev.dev_info.max_io_buf_bytes as usize);

            // Submit initial prep command - any error will exit the function
            q.submit_io_prep_cmd(tag, BufDesc::Slice(buf.as_slice()), 0, Some(&buf))
                .await?;

            loop {
                let res = handle_io_cmd(&q, tag).await;
                {
                    let mut guard = dev_data.lock().unwrap();
                    (*guard).done += 1;
                }
                // Any error (including QueueIsDown) will break the loop by exiting the function
                q.submit_io_commit_cmd(tag, BufDesc::Slice(buf.as_slice()), res)
                    .await?;
            }
        }

        //Device wide data shared among all queue context
        struct DevData {
            done: u64,
        }

        let dev_flags = UblkFlags::UBLK_DEV_F_ADD_DEV;
        let depth = 64_u16;
        let ctrl = UblkCtrlBuilder::default()
            .name("null")
            .nr_queues(2)
            .depth(depth)
            .id(-1)
            .dev_flags(dev_flags)
            .build()
            .unwrap();

        let tgt_init = |dev: &mut UblkDev| {
            dev.set_default_params(250_u64 << 30);
            Ok(())
        };
        // device data is shared among all queue contexts
        let dev_data = Arc::new(Mutex::new(DevData { done: 0 }));
        let wh_dev_data = dev_data.clone();

        // queue handler supports Clone(), so will be cloned in each
        // queue pthread context
        let q_fn = move |qid: u16, dev: &Arc<UblkDev>| {
            // `q_fn` closure implements Clone() Trait, so the captured
            // `dev_data` is cloned to `q_fn` context.
            let dev_data = dev_data.clone();
            libublk::UblkRuntime::run_io_tasks(dev, qid, move |q, tag| {
                let dev_data = dev_data.clone();
                async move { test_io_task(&q, tag, &dev_data).await }
            })
            .unwrap();
        };

        // kick off our targets
        ctrl.run_target(tgt_init, q_fn, move |ctrl: &UblkCtrl| {
            // run sanity and disk IO test after ublk disk is ready
            run_ublk_disk_sanity_test(ctrl, dev_flags);
            read_ublk_disk(ctrl, true);

            {
                let guard = wh_dev_data.lock().unwrap();
                assert!((*guard).done > 0);
            }

            ctrl.kill_dev().unwrap();
        })
        .unwrap();
    }

    fn __test_ublk_null_zc(bad_buf_idx: bool, fallback: bool) {
        const IORING_NOP_INJECT_RESULT: u32 = 1u32 << 0;
        const IORING_NOP_FIXED_BUFFER: u32 = 1u32 << 3;
        async fn handle_io_cmd(q: &UblkQueue, tag: u16) -> i32 {
            let iod = q.get_iod(tag);
            let bytes = (iod.nr_sectors << 9) as i32;

            // The UBLK_AUTO_BUF_REG_FALLBACK contract: when auto
            // registration fails, the kernel delivers the io with
            // UBLK_IO_F_NEED_REG_BUF set and no buffer registered, and
            // the server must not touch the fixed-buffer slot.
            if (iod.op_flags & sys::UBLK_IO_F_NEED_REG_BUF) != 0 {
                return bytes;
            }

            let mut sqe = opcode::Nop::new()
                .build()
                .flags(io_uring::squeue::Flags::FIXED_FILE);
            override_sqe!(
                &mut sqe,
                rw_flags,
                |=,
                IORING_NOP_FIXED_BUFFER | IORING_NOP_INJECT_RESULT
            );
            override_sqe!(&mut sqe, len, bytes as u32);
            override_sqe!(&mut sqe, buf_index, tag);

            // SAFETY: the NOP references no caller memory (the fixed
            // buffer is registered with the ring).
            let res = match unsafe { q.ublk_submit_sqe(sqe) } {
                Ok(f) => f.await,
                Err(_) => 0,
            };
            res
        }

        async fn test_auto_reg_io_task(
            q: &UblkQueue,
            tag: u16,
            depth: u16,
            bad_buf_idx: bool,
            fallback: bool,
        ) -> Result<(), UblkError> {
            let buf_index = if !bad_buf_idx { tag } else { depth + 1 };

            // Create auto buffer registration data with fallback support
            let auto_buf_reg = sys::ublk_auto_buf_reg {
                index: buf_index,
                flags: if fallback {
                    sys::UBLK_AUTO_BUF_REG_FALLBACK as u8
                } else {
                    0
                },
                ..Default::default()
            };

            // Submit initial prep command - any error will exit the function
            // AutoReg doesn't use IoBuf, so pass None
            q.submit_io_prep_cmd(tag, BufDesc::AutoReg(auto_buf_reg), 0, None)
                .await?;

            loop {
                let res = handle_io_cmd(&q, tag).await;

                // Any error (including QueueIsDown) will break the loop by exiting the function
                q.submit_io_commit_cmd(tag, BufDesc::AutoReg(auto_buf_reg), res)
                    .await?;
            }
        }

        let dev_flags = UblkFlags::UBLK_DEV_F_ADD_DEV;
        let depth = 64_u16;
        let ctrl = UblkCtrlBuilder::default()
            .name("null")
            .nr_queues(2)
            .depth(depth)
            .id(-1)
            .dev_flags(dev_flags)
            .ctrl_flags((sys::UBLK_F_AUTO_BUF_REG | sys::UBLK_F_SUPPORT_ZERO_COPY) as u64)
            .build()
            .unwrap();

        let tgt_init = |dev: &mut UblkDev| {
            dev.set_default_params(250_u64 << 30);
            Ok(())
        };

        // queue handler supports Clone(), so will be cloned in each
        // queue pthread context
        let q_fn = move |qid: u16, dev: &Arc<UblkDev>| {
            libublk::UblkRuntime::run_io_tasks(dev, qid, move |q, tag| async move {
                test_auto_reg_io_task(&q, tag, depth, bad_buf_idx, fallback).await
            })
            .unwrap();
        };

        // kick off our targets
        ctrl.run_target(tgt_init, q_fn, move |ctrl: &UblkCtrl| {
            let success = fallback || !bad_buf_idx;

            // run sanity and disk IO test after ublk disk is ready
            run_ublk_disk_sanity_test(ctrl, dev_flags);
            read_ublk_disk(ctrl, success);

            ctrl.kill_dev().unwrap();
        })
        .unwrap();
    }

    #[test]
    fn test_ublk_null_zc() {
        __test_ublk_null_zc(false, false);
    }

    #[test]
    fn test_ublk_null_zc_bad_idx_fallback() {
        __test_ublk_null_zc(true, true);
    }

    #[test]
    fn test_ublk_null_zc_fallback() {
        __test_ublk_null_zc(false, true);
    }

    #[test]
    fn test_ublk_null_zc_bad_idx_no_fallback() {
        __test_ublk_null_zc(true, false); //io failure in case that bad buf idx and no fallback
    }

    fn ublk_ramdisk_tester(ctrl: &UblkCtrl, dev_flags: UblkFlags) {
        let dev_path = ctrl.get_bdev_path();

        run_ublk_disk_sanity_test(&ctrl, dev_flags);

        //format as ext4 and mount over the created ublk-ramdisk
        {
            let run = |cmd: &str, args: &[&str]| {
                let status = std::process::Command::new(cmd).args(args).status().unwrap();
                assert!(status.success(), "{} {:?} failed", cmd, args);
            };
            run("mkfs.ext4", &["-q", "-F", "-I", "512", "-E", "stride=2", &dev_path]);

            let tmp_dir = tempfile::TempDir::new().unwrap();
            let mnt = tmp_dir.path().to_str().unwrap();
            run("mount", &[dev_path.as_str(), mnt]);
            run("umount", &[mnt]);
        }
        ctrl.kill_dev().unwrap();
    }

    fn __test_ublk_ramdisk(dev_flags: UblkFlags) {
        // async function to handle individual I/O commands using slice operations for safe buffer access
        async fn handle_io_cmd(
            q: &UblkQueue,
            tag: u16,
            ramdisk_addr: usize,
            io_buf: &mut [u8],
        ) -> i32 {
            let iod = q.get_iod(tag);
            let off = (iod.start_sector << 9) as usize;
            let bytes = (iod.nr_sectors << 9) as usize;
            let op = iod.op_flags & 0xff;

            // Ensure we don't read/write beyond buffer boundaries
            if bytes > io_buf.len() {
                return -libc::EINVAL;
            }

            match op {
                sys::UBLK_IO_OP_FLUSH => {
                    // For flush, we just return success
                    bytes as i32
                }
                sys::UBLK_IO_OP_READ => {
                    // For read operations, copy data from ramdisk to I/O buffer using safe slice operations
                    // Create a safe slice from the ramdisk memory for the read operation
                    unsafe {
                        let ramdisk_slice =
                            std::slice::from_raw_parts((ramdisk_addr + off) as *const u8, bytes);
                        io_buf[..bytes].copy_from_slice(ramdisk_slice);
                    }
                    bytes as i32
                }
                sys::UBLK_IO_OP_WRITE => {
                    // For write operations, copy data from I/O buffer to ramdisk using safe slice operations
                    // Create a safe slice from the ramdisk memory for the write operation
                    unsafe {
                        let ramdisk_slice =
                            std::slice::from_raw_parts_mut((ramdisk_addr + off) as *mut u8, bytes);
                        ramdisk_slice.copy_from_slice(&io_buf[..bytes]);
                    }
                    bytes as i32
                }
                _ => {
                    // Invalid operation
                    -libc::EINVAL
                }
            }
        }

        async fn test_ramdisk_io_task(
            q: &UblkQueue,
            tag: u16,
            ramdisk_addr: usize,
            mlock_enabled: bool,
        ) -> Result<(), UblkError> {
            let mut buf = IoBuf::<u8>::new(q.dev.dev_info.max_io_buf_bytes as usize);

            // Submit initial prep command - any error will exit the function
            // The IoBuf is automatically registered
            q.submit_io_prep_cmd(tag, BufDesc::Slice(buf.as_slice()), 0, Some(&buf))
                .await?;

            // If mlock is enabled, verify the buffer is mlocked after registration
            if mlock_enabled {
                assert!(
                    buf.is_mlocked(),
                    "Buffer should be mlocked when UBLK_DEV_F_MLOCK_IO_BUFFER is set"
                );
            }

            loop {
                let res = handle_io_cmd(&q, tag, ramdisk_addr, buf.as_mut_slice()).await;
                // Any error (including QueueIsDown) will break the loop by exiting the function
                q.submit_io_commit_cmd(tag, BufDesc::Slice(buf.as_slice()), res)
                    .await?;
            }
        }

        let size = 32_u64 << 20;
        let ramdisk_buf = libublk::helpers::IoBuf::<u8>::new(size as usize);
        let ramdisk_addr = ramdisk_buf.as_mut_ptr() as usize;
        let depth = 128;
        let ctrl = UblkCtrlBuilder::default()
            .name("ramdisk")
            .id(-1)
            .nr_queues(1)
            .depth(depth)
            .dev_flags(dev_flags)
            .build()
            .unwrap();
        let tgt_init = |dev: &mut UblkDev| {
            dev.set_default_params(size);
            Ok(())
        };

        let q_fn = move |qid: u16, dev: &Arc<UblkDev>| {
            let mlock_enabled = dev.flags.intersects(UblkFlags::UBLK_DEV_F_MLOCK_IO_BUFFER);

            libublk::UblkRuntime::run_io_tasks(dev, qid, move |q, tag| async move {
                test_ramdisk_io_task(&q, tag, ramdisk_addr, mlock_enabled).await
            })
            .unwrap();
        };

        ctrl.run_target(tgt_init, q_fn, move |ctrl: &UblkCtrl| {
            ublk_ramdisk_tester(ctrl, dev_flags);
        })
        .unwrap();
    }

    /// make one ublk-ramdisk and test:
    /// - if /dev/ublkbN can be created successfully
    /// - if yes, then test format/mount/umount over this ublk-ramdisk
    #[test]
    fn test_ublk_ramdisk() {
        __test_ublk_ramdisk(UblkFlags::UBLK_DEV_F_ADD_DEV);
    }

    /// make FnMut closure for IO handling
    #[test]
    fn test_fn_mut_io_closure() {
        /// called from queue_handler closure(), which supports Clone(),
        fn null_queue_mut_io(qid: u16, dev: &Arc<UblkDev>) {
            let bufs_rc = Rc::new(dev.alloc_queue_io_bufs());
            let user_copy = (dev.dev_info.flags & libublk::sys::UBLK_F_USER_COPY as u64) != 0;
            let bufs = bufs_rc.clone();

            // modify this vector in io handling closure
            let mut q_vec = Vec::<i32>::new();
            let io_handler = move |q: &UblkQueue, tag: u16, _io: &UblkIOCtx| {
                let iod = q.get_iod(tag);
                let res = Ok(UblkIORes::Result((iod.nr_sectors << 9) as i32));

                {
                    q_vec.push(tag as i32);
                    if q_vec.len() >= 64 {
                        q_vec.clear();
                    }
                }

                let buf_desc = if user_copy {
                    BufDesc::Slice(&[]) // Empty slice for user_copy mode
                } else {
                    BufDesc::Slice(bufs_rc[tag as usize].as_slice())
                };
                q.complete_io_cmd_unified(tag, buf_desc, res).unwrap();
            };

            UblkQueue::new(qid, dev)
                .unwrap()
                .submit_fetch_commands_unified(BufDescList::Slices(if user_copy {
                    None
                } else {
                    Some(&bufs)
                }))
                .unwrap()
                .wait_and_handle_io(io_handler);
        }

        __test_ublk_null(UblkFlags::UBLK_DEV_F_ADD_DEV, null_queue_mut_io);
    }

    fn get_curr_bin_dir() -> Option<std::path::PathBuf> {
        if let Err(_current_exe) = env::current_exe() {
            None
        } else {
            env::current_exe().ok().map(|mut path| {
                path.pop();
                if path.ends_with("deps") {
                    path.pop();
                }
                path
            })
        }
    }

    fn ublk_state_wait_until(ctrl: &UblkCtrl, state: u16, timeout: u32) {
        let mut count = 0;
        let unit = 100_u32;
        loop {
            std::thread::sleep(std::time::Duration::from_millis(unit as u64));

            ctrl.read_dev_info().unwrap();
            if ctrl.dev_info().state == state {
                std::thread::sleep(std::time::Duration::from_millis(20));
                break;
            }
            count += unit;
            assert!(count < timeout);
        }
    }

    /// Spawn `examples/ramdisk <cmd> ...` and return its (dev_id, queue tid).
    fn ramdisk_spawn(rd_path: &str, args: &[&str]) -> (i32, libc::pid_t) {
        let mut cmd = Command::new(rd_path)
            .args(args)
            .stdout(Stdio::piped())
            .spawn()
            .expect("fail to run ublk ramdisk");
        let stdout = cmd.stdout.take().expect("Failed to capture stdout");
        let _ = cmd.wait().expect("Failed to wait on child");

        let mut id = -1_i32;
        let mut tid = 0;
        let id_regx = regex::Regex::new(r"dev id (\d+)").unwrap();
        let tid_regx = regex::Regex::new(r"queue 0 tid: (\d+)").unwrap();
        for line in BufReader::new(stdout).lines() {
            match line {
                Ok(content) => {
                    if let Some(c) = id_regx.captures(&content.as_str()) {
                        id = c.get(1).unwrap().as_str().parse().unwrap();
                    }
                    if let Some(c) = tid_regx.captures(&content.as_str()) {
                        tid = c.get(1).unwrap().as_str().parse().unwrap();
                    }
                }
                Err(e) => eprintln!("Error reading line: {}", e), // Handle error
            }
        }
        (id, tid)
    }

    /// A disowned control must leave its device behind, and the device must
    /// still be removable afterwards.
    ///
    /// This is what makes the quiesce handoff possible: without it the
    /// outgoing server deletes the device its successor is meant to recover.
    #[test]
    fn test_ublk_ctrl_disown() {
        fn wait_for_path(path: &str, want: bool) -> bool {
            for _ in 0..20 {
                if Path::new(path).exists() == want {
                    return true;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            false
        }

        // Take the id from dev_info rather than parsing it back out of the
        // path: the name is system policy and udev may rename it.
        let (id, cdev) = {
            let ctrl = UblkCtrlBuilder::default()
                .name("disown")
                .nr_queues(1)
                .depth(16)
                .dev_flags(UblkFlags::UBLK_DEV_F_ADD_DEV)
                .build()
                .unwrap();
            let id = ctrl.dev_info().dev_id as i32;
            let cdev = ctrl.get_cdev_path();
            assert!(
                wait_for_path(&cdev, true),
                "char device {} never appeared",
                cdev
            );

            ctrl.disown();
            (id, cdev)
        };

        // The control is gone; UBLK_DEV_F_ADD_DEV would normally have taken
        // the device with it. This test switches that cleanup off, so from
        // here on nothing removes the device for us -- delete it first and
        // assert afterwards, so a later failure cannot strand it.
        let survived = Path::new(&cdev).exists();
        let removed = UblkCtrl::new_simple(id).and_then(|c| c.del_dev());

        assert!(survived, "disowned device was deleted on drop");
        // disown() must not disarm an explicit removal.
        removed.expect("del_dev() failed on a disowned device");
        assert!(
            wait_for_path(&cdev, false),
            "del_dev() did not remove disowned device {}",
            cdev
        );
    }

    /// `UBLK_U_CMD_UPDATE_SIZE` must resize the live disk in place.
    ///
    /// The driver assigns `data[0]` straight into `params.basic.dev_sectors`
    /// and calls `set_capacity_and_notify()`, so the new capacity has to be
    /// visible in sysfs without the device being recreated.  This also pins
    /// the byte/sector conversion: a unit slip here resizes by 512x.
    #[test]
    fn test_ublk_update_size() {
        if UblkCtrl::get_features().unwrap_or_default() & sys::UBLK_F_UPDATE_SIZE as u64 == 0 {
            println!("skipping: kernel lacks UBLK_F_UPDATE_SIZE");
            return;
        }

        const INIT_SIZE: u64 = 8_u64 << 30;
        const GROWN_SIZE: u64 = 16_u64 << 30;
        const SHRUNK_SIZE: u64 = 2_u64 << 30;

        let ctrl = UblkCtrlBuilder::default()
            .name("null")
            .nr_queues(1)
            .depth(16)
            .dev_flags(UblkFlags::UBLK_DEV_F_ADD_DEV)
            .ctrl_flags(sys::UBLK_F_UPDATE_SIZE as u64)
            .build()
            .unwrap();

        // ENODEV before START_DEV. This is assertable only because the library
        // checks the device state and refuses on its own: kernels before
        // 25966fc09769 ("ublk: fix NULL pointer dereference in
        // ublk_ctrl_set_size()", v7.0-rc4) do not check ub->ub_disk here, so
        // the command must not be allowed to reach them.
        match ctrl.update_size(GROWN_SIZE) {
            Err(UblkError::OtherError(e)) => assert_eq!(e, -libc::ENODEV),
            other => panic!("expected ENODEV before START_DEV, got {:?}", other),
        }

        let tgt_init = |dev: &mut UblkDev| {
            dev.set_default_params(INIT_SIZE);
            Ok(())
        };

        let q_fn = move |qid: u16, dev: &UblkDev| {
            let bufs_rc = Rc::new(dev.alloc_queue_io_bufs());
            let bufs = bufs_rc.clone();

            let io_handler = move |q: &UblkQueue, tag: u16, _io: &UblkIOCtx| {
                let iod = q.get_iod(tag);
                let bytes = (iod.nr_sectors << 9) as i32;
                q.complete_io_cmd_unified(
                    tag,
                    BufDesc::Slice(bufs[tag as usize].as_slice()),
                    Ok(UblkIORes::Result(bytes)),
                )
                .unwrap();
            };

            let queue = match UblkQueue::new(qid, dev)
                .unwrap()
                .submit_fetch_commands_unified(BufDescList::Slices(Some(&bufs_rc)))
            {
                Ok(q) => q,
                Err(e) => {
                    log::error!("submit_fetch_commands_unified failed: {}", e);
                    return;
                }
            };

            queue.wait_and_handle_io(io_handler);
        };

        ctrl.run_target(tgt_init, q_fn, move |ctrl: &UblkCtrl| {
            let sysfs = format!("/sys/block/ublkb{}/size", ctrl.dev_info().dev_id);
            let sectors = || -> u64 {
                std::fs::read_to_string(&sysfs)
                    .expect("read capacity")
                    .trim()
                    .parse()
                    .expect("parse capacity")
            };

            assert_eq!(sectors(), INIT_SIZE >> 9, "unexpected initial capacity");

            // Misaligned sizes are refused client-side, against the device's
            // logical block size, so the capacity must be untouched after.
            assert!(matches!(
                ctrl.update_size(INIT_SIZE + 1),
                Err(UblkError::InvalidVal)
            ));
            assert_eq!(sectors(), INIT_SIZE >> 9, "refused resize still applied");

            ctrl.update_size(GROWN_SIZE).expect("grow failed");
            assert_eq!(sectors(), GROWN_SIZE >> 9, "device did not grow");

            ctrl.update_size(SHRUNK_SIZE).expect("shrink failed");
            assert_eq!(sectors(), SHRUNK_SIZE >> 9, "device did not shrink");

            // the driver keeps its own copy of the params in step
            let mut p = sys::ublk_params {
                ..Default::default()
            };
            ctrl.get_params(&mut p).expect("get_params failed");
            assert_eq!(p.basic.dev_sectors, SHRUNK_SIZE >> 9);

            ctrl.kill_dev().unwrap();
        })
        .unwrap();
    }

    /// Drive the graceful quiesce path end to end.
    ///
    /// [`test_ublk_ramdisk_recovery`] reaches `UBLK_S_DEV_QUIESCED` by killing
    /// the queue thread, i.e. the crash path. This does it the intended way:
    /// `UBLK_U_CMD_QUIESCE_DEV` cancels the server's pending `uring_cmd`s, the
    /// server unwinds on `UBLK_IO_RES_ABORT` and exits, and the device settles
    /// in `UBLK_S_DEV_QUIESCED` ready for `START_USER_RECOVERY`.
    #[test]
    fn test_ublk_ramdisk_quiesce() {
        if UblkCtrl::get_features().unwrap_or_default() & sys::UBLK_F_QUIESCE as u64 == 0 {
            println!("skipping: kernel lacks UBLK_F_QUIESCE");
            return;
        }

        let tgt_dir = get_curr_bin_dir().unwrap();
        let rd_path = tgt_dir.display().to_string() + &"/examples/ramdisk".to_string();
        let (id, tid) = ramdisk_spawn(&rd_path, &["add", "-1", "32"]);
        assert!(tid != 0 && id >= 0);

        let ctrl = UblkCtrl::new_simple(id).unwrap();
        ublk_state_wait_until(&ctrl, sys::UBLK_S_DEV_LIVE as u16, 2000);
        assert!(Path::new(&ctrl.get_bdev_path()).exists() == true);

        // Graceful quiesce, in place of the recovery test's SIGKILL.
        // On EBUSY the driver leaves the device canceling, so say so here
        // rather than letting the next wait fail with no explanation.
        ctrl.quiesce_dev(3000)
            .expect("quiesce failed; device is left canceling, not quiesced");
        ublk_state_wait_until(&ctrl, sys::UBLK_S_DEV_QUIESCED as u16, 6000);

        // A quiesced device is still recoverable, and the bdev never went away.
        assert!(Path::new(&ctrl.get_bdev_path()).exists() == true);
        let (rid, rtid) = ramdisk_spawn(&rd_path, &["recover", &id.to_string()]);
        assert!(rtid != 0 && rid == id);
        ublk_state_wait_until(&ctrl, sys::UBLK_S_DEV_LIVE as u16, 20000);

        ctrl.del_dev().unwrap();
    }

    /// run examples/ramdisk recovery test
    #[test]
    fn test_ublk_ramdisk_recovery() {
        let tgt_dir = get_curr_bin_dir().unwrap();
        //println!("top dir: path {:?} {:?}", &tgt_dir, &file);
        let rd_path = tgt_dir.display().to_string() + &"/examples/ramdisk".to_string();
        let (id, tid) = ramdisk_spawn(&rd_path, &["add", "-1", "32"]);
        assert!(tid != 0 && id >= 0);

        let ctrl = UblkCtrl::new_simple(id).unwrap();
        ublk_state_wait_until(&ctrl, sys::UBLK_S_DEV_LIVE as u16, 2000);

        //ublk block device should be observed now
        let dev_path = ctrl.get_bdev_path();
        assert!(Path::new(&dev_path).exists() == true);

        //simulate one panic by sending KILL to queue pthread
        unsafe {
            libc::kill(tid, libc::SIGKILL);
        }

        //wait device becomes quiesced
        ublk_state_wait_until(&ctrl, sys::UBLK_S_DEV_QUIESCED as u16, 6000);

        //recover device
        let mut cmd = Command::new(&rd_path)
            .args(["recover", &id.to_string().as_str()])
            .stdout(Stdio::piped())
            .spawn()
            .expect("fail to recover ramdisk");
        cmd.wait().expect("Failed to wait on child");
        ublk_state_wait_until(&ctrl, sys::UBLK_S_DEV_LIVE as u16, 20000);
        ctrl.del_dev().unwrap();
    }

    /// Test UBLK_DEV_F_SINGLE_CPU_AFFINITY integration
    #[test]
    fn test_ublk_single_cpu_affinity() {
        fn verify_single_cpu_affinity(ctrl: &UblkCtrl, dev_flags: UblkFlags) {
            // Verify the device was created with the expected flags
            let tgt_flags = ctrl.get_target_flags_from_json().unwrap();
            assert!(UblkFlags::from_bits(tgt_flags).unwrap() == dev_flags);

            // Read the JSON file to check queue affinities
            let run_path = ctrl.run_path();
            let json_path = Path::new(&run_path);
            assert!(json_path.exists() == true, "JSON file should exist");

            let json_content =
                std::fs::read_to_string(json_path).expect("Should be able to read JSON file");
            let json: serde_json::Value =
                serde_json::from_str(&json_content).expect("Should be able to parse JSON");

            // Check that queues section exists
            let queues = json.get("queues").expect("JSON should have queues section");

            // Verify each queue has exactly one CPU in its affinity
            for qid in 0..2u16 {
                let queue_info = queues
                    .get(qid.to_string())
                    .expect(&format!("Queue {} should exist in JSON", qid));

                let affinity = queue_info
                    .get("affinity")
                    .expect(&format!("Queue {} should have affinity field", qid));

                let affinity_array = affinity
                    .as_array()
                    .expect(&format!("Queue {} affinity should be an array", qid));

                assert_eq!(
                    affinity_array.len(), 1,
                    "Queue {} should have exactly 1 CPU in affinity when UBLK_DEV_F_SINGLE_CPU_AFFINITY is set, got {}",
                    qid, affinity_array.len()
                );

                let cpu_id = affinity_array[0].as_u64().expect(&format!(
                    "Queue {} affinity should contain valid CPU ID",
                    qid
                ));

                println!("Queue {} is bound to CPU {}", qid, cpu_id);
            }

            println!(
                "✓ Single CPU affinity verification passed - each queue bound to exactly one CPU"
            );
        }

        fn single_cpu_null_handle_queue(qid: u16, dev: &Arc<UblkDev>) {
            let bufs_rc = Rc::new(dev.alloc_queue_io_bufs());
            let user_copy = (dev.dev_info.flags & libublk::sys::UBLK_F_USER_COPY as u64) != 0;
            let bufs = bufs_rc.clone();

            let io_handler = move |q: &UblkQueue, tag: u16, _io: &UblkIOCtx| {
                let iod = q.get_iod(tag);
                let bytes = (iod.nr_sectors << 9) as i32;

                let buf_desc = if user_copy {
                    BufDesc::Slice(&[]) // Empty slice for user_copy mode
                } else {
                    BufDesc::Slice(bufs[tag as usize].as_slice())
                };
                q.complete_io_cmd_unified(tag, buf_desc, Ok(UblkIORes::Result(bytes)))
                    .unwrap();
            };

            let queue = match UblkQueue::new(qid, dev)
                .unwrap()
                .submit_fetch_commands_unified(BufDescList::Slices(if user_copy {
                    None
                } else {
                    Some(&bufs_rc)
                })) {
                Ok(q) => q,
                Err(e) => {
                    log::error!("submit_fetch_commands_unified failed: {}", e);
                    return;
                }
            };

            queue.wait_and_handle_io(io_handler);
        }

        let dev_flags = UblkFlags::UBLK_DEV_F_ADD_DEV | UblkFlags::UBLK_DEV_F_SINGLE_CPU_AFFINITY;

        let ctrl = UblkCtrlBuilder::default()
            .name("single_cpu_null")
            .nr_queues(2)
            .dev_flags(dev_flags)
            .ctrl_flags(libublk::sys::UBLK_F_USER_COPY.into())
            .build()
            .unwrap();

        let tgt_init = |dev: &mut UblkDev| {
            dev.set_default_params(250_u64 << 30);
            Ok(())
        };

        let q_fn = move |qid: u16, dev: &Arc<UblkDev>| {
            single_cpu_null_handle_queue(qid, dev);
        };

        ctrl.run_target(tgt_init, q_fn, move |ctrl: &UblkCtrl| {
            // Run basic sanity tests
            run_ublk_disk_sanity_test(ctrl, dev_flags);

            // Verify single CPU affinity behavior
            verify_single_cpu_affinity(ctrl, dev_flags);

            // Test that the device works normally
            read_ublk_disk(ctrl, true);

            ctrl.kill_dev().unwrap();
        })
        .unwrap();
    }

    /// Common helper function for testing non-async auto buffer registration APIs
    fn __test_ublk_null_sync_auto_buf_reg(test_name: &str, use_fallback: bool) {
        let dev_flags = UblkFlags::UBLK_DEV_F_ADD_DEV;
        let depth = 64_u16;
        let ctrl = UblkCtrlBuilder::default()
            .name(test_name)
            .nr_queues(1)
            .depth(depth)
            .id(-1)
            .dev_flags(dev_flags)
            .ctrl_flags((sys::UBLK_F_AUTO_BUF_REG | sys::UBLK_F_SUPPORT_ZERO_COPY) as u64)
            .build()
            .unwrap();

        let tgt_init = |dev: &mut UblkDev| {
            dev.set_default_params(250_u64 << 30);
            Ok(())
        };

        let q_fn = move |qid: u16, dev: &Arc<UblkDev>| {
            // Create auto buffer registration data for each tag
            let mut buf_reg_data_list = Vec::with_capacity(depth as usize);
            let flags = if use_fallback {
                sys::UBLK_AUTO_BUF_REG_FALLBACK as u8
            } else {
                0
            };

            for tag in 0..depth {
                buf_reg_data_list.push(sys::ublk_auto_buf_reg {
                    index: tag,
                    flags,
                    ..Default::default()
                });
            }

            let io_handler = move |q: &UblkQueue, tag: u16, _io: &UblkIOCtx| {
                let iod = q.get_iod(tag);
                let bytes = (iod.nr_sectors << 9) as i32;

                // Create auto buffer registration data for completion
                let auto_buf_reg = sys::ublk_auto_buf_reg {
                    index: tag,
                    flags,
                    ..Default::default()
                };

                // Use the unified complete_io_cmd_unified API with auto buffer registration
                q.complete_io_cmd_unified(
                    tag,
                    BufDesc::AutoReg(auto_buf_reg),
                    Ok(UblkIORes::Result(bytes)),
                )
                .unwrap();
            };

            let queue = match UblkQueue::new(qid, dev)
                .unwrap()
                .submit_fetch_commands_unified(BufDescList::AutoRegs(&buf_reg_data_list))
            {
                Ok(q) => q,
                Err(e) => {
                    log::error!("submit_fetch_commands_unified failed: {}", e);
                    return;
                }
            };

            queue.wait_and_handle_io(io_handler);
        };

        ctrl.run_target(tgt_init, q_fn, move |ctrl: &UblkCtrl| {
            run_ublk_disk_sanity_test(ctrl, dev_flags);
            read_ublk_disk(ctrl, true);
            ctrl.kill_dev().unwrap();
        })
        .unwrap();
    }

    /// Test the new non-async auto buffer registration APIs
    #[test]
    fn test_ublk_null_sync_auto_buf_reg() {
        __test_ublk_null_sync_auto_buf_reg("null_sync_auto_buf", false);
    }

    /// Test the new non-async auto buffer registration APIs with fallback
    #[test]
    fn test_ublk_null_sync_auto_buf_reg_fallback() {
        __test_ublk_null_sync_auto_buf_reg("null_sync_auto_buf_fallback", true);
    }

    /// Test mlock IO buffer feature
    #[test]
    fn test_ublk_null_mlock_io_buffer() {
        let dev_flags = UblkFlags::UBLK_DEV_F_ADD_DEV | UblkFlags::UBLK_DEV_F_MLOCK_IO_BUFFER;
        __test_ublk_ramdisk(dev_flags);
    }

    /// Test mlock IO buffer feature incompatibility with other features
    #[test]
    fn test_ublk_mlock_incompatibility() {
        // Test incompatibility with UBLK_F_USER_COPY
        let dev_flags = UblkFlags::UBLK_DEV_F_ADD_DEV | UblkFlags::UBLK_DEV_F_MLOCK_IO_BUFFER;
        let result = UblkCtrlBuilder::default()
            .name("mlock_incompatible")
            .nr_queues(1)
            .dev_flags(dev_flags)
            .ctrl_flags(sys::UBLK_F_USER_COPY as u64)
            .build();
        assert!(
            result.is_err(),
            "Should fail when mlock is combined with UBLK_F_USER_COPY"
        );

        // Test incompatibility with UBLK_F_AUTO_BUF_REG
        let result = UblkCtrlBuilder::default()
            .name("mlock_incompatible")
            .nr_queues(1)
            .dev_flags(dev_flags)
            .ctrl_flags(sys::UBLK_F_AUTO_BUF_REG as u64)
            .build();
        assert!(
            result.is_err(),
            "Should fail when mlock is combined with UBLK_F_AUTO_BUF_REG"
        );

        // Test incompatibility with UBLK_F_SUPPORT_ZERO_COPY
        let result = UblkCtrlBuilder::default()
            .name("mlock_incompatible")
            .nr_queues(1)
            .dev_flags(dev_flags)
            .ctrl_flags(sys::UBLK_F_SUPPORT_ZERO_COPY as u64)
            .build();
        assert!(
            result.is_err(),
            "Should fail when mlock is combined with UBLK_F_SUPPORT_ZERO_COPY"
        );
    }

    /// Test IoBuf mlock functionality directly
    #[test]
    fn test_iobuf_mlock() {
        // Test regular IoBuf doesn't have mlock
        let buf_regular = IoBuf::<u8>::new(4096);
        assert!(
            !buf_regular.is_mlocked(),
            "Regular IoBuf should not be mlocked"
        );

        // Test IoBuf with mlock
        let buf_mlock = IoBuf::<u8>::new(4096);
        let mlock_success = buf_mlock.mlock();
        // Note: mlock may fail due to permissions, but the method should still work
        // In CI or without CAP_IPC_LOCK, this might return false
        println!(
            "Buffer mlock success: {}, status: {}",
            mlock_success,
            buf_mlock.is_mlocked()
        );
    }
}
