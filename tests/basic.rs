#[cfg(test)]
mod integration {
    use io_uring::opcode;
    use libublk::helpers::IoBuf;
    use libublk::io::{BufDescList, UblkDev, UblkIOCtx, UblkQueue};
    use libublk::override_sqe;
    use libublk::uring_async::ublk_wait_and_handle_ios;
    use libublk::uring_async::ublk_wake_task;
    use libublk::{ctrl::UblkCtrl, ctrl::UblkCtrlBuilder, sys, BufDesc, UblkError, UblkFlags, UblkIORes};
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

    fn __test_ublk_null(dev_flags: UblkFlags, q_handler: fn(u16, &UblkDev)) {
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

        let q_fn = move |qid: u16, _dev: &UblkDev| {
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
        fn null_handle_queue(qid: u16, dev: &UblkDev) {
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

    /// make one ublk-null and test if /dev/ublkbN can be created successfully
    #[cfg(feature = "fat_complete")]
    #[test]
    fn test_ublk_null_comp_batch() {
        use libublk::UblkFatRes;
        /// called from queue_handler closure(), which supports Clone(),
        fn null_handle_queue_batch(qid: u16, dev: &UblkDev) {
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

                let res = Ok(UblkIORes::FatRes(UblkFatRes::BatchRes(vec![(tag, bytes)])));
                q.complete_io_cmd_unified(tag, buf_desc, res).unwrap();
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

        __test_ublk_null(
            UblkFlags::UBLK_DEV_F_ADD_DEV | UblkFlags::UBLK_DEV_F_COMP_BATCH,
            null_handle_queue_batch,
        );
    }

    #[test]
    fn test_ublk_null_async() {
        // submit one io_uring Nop via io-uring crate and UringOpFuture, and
        // user_data has to unique among io tasks, also has to encode tag
        // info, so please build user_data by UblkIOCtx::build_user_data_async()
        async fn handle_io_cmd(q: &UblkQueue<'_>, tag: u16) -> i32 {
            let iod = q.get_iod(tag);
            let bytes = (iod.nr_sectors << 9) as i32;

            let res = q.ublk_submit_sqe(opcode::Nop::new().build()).await;
            bytes + res
        }

        async fn test_io_task(q: &UblkQueue<'_>, tag: u16, dev_data: &Arc<Mutex<DevData>>) -> Result<(), UblkError> {
            let buf = IoBuf::<u8>::new(q.dev.dev_info.max_io_buf_bytes as usize);
            let mut res = 0;

            q.register_io_buf(tag, &buf);

            // Submit initial prep command - any error will exit the function
            q.submit_io_prep_cmd(tag, BufDesc::Slice(buf.as_slice()), res).await?;

            loop {
                res = handle_io_cmd(&q, tag).await;
                {
                    let mut guard = dev_data.lock().unwrap();
                    (*guard).done += 1;
                }

                // Any error (including QueueIsDown) will break the loop by exiting the function
                q.submit_io_commit_cmd(tag, BufDesc::Slice(buf.as_slice()), res).await?;
            }
        }

        //Device wide data shared among all queue context
        struct DevData {
            done: u64,
        }

        // submit one io_uring Nop via io-uring crate and UringOpFuture, and
        // user_data has to unique among io tasks, also has to encode tag
        // info, so please build user_data by UblkIOCtx::build_user_data_async()
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
        let q_fn = move |qid: u16, dev: &UblkDev| {
            let q_rc = Rc::new(UblkQueue::new(qid as u16, &dev).unwrap());
            let exe = smol::LocalExecutor::new();
            let mut f_vec = Vec::new();

            // `q_fn` closure implements Clone() Trait, so the captured
            // `dev_data` is cloned to `q_fn` context.
            let _dev_data = Rc::new(dev_data);

            for tag in 0..depth {
                let q = q_rc.clone();
                let __dev_data = _dev_data.clone();

                f_vec.push(exe.spawn(async move {
                    if let Err(e) = test_io_task(&q, tag, &__dev_data).await {
                        log::error!("test_io_task failed for tag {}: {}", tag, e);
                    }
                }));
            }

            ublk_wait_and_handle_ios(&exe, &q_rc);
            smol::block_on(exe.run(async { futures::future::join_all(f_vec).await }));
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
        async fn handle_io_cmd(q: &UblkQueue<'_>, tag: u16) -> i32 {
            let iod = q.get_iod(tag);
            let bytes = (iod.nr_sectors << 9) as i32;

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

            let res = q.ublk_submit_sqe(sqe).await;
            res
        }

        async fn test_auto_reg_io_task(q: &UblkQueue<'_>, tag: u16, depth: u16, bad_buf_idx: bool, fallback: bool) -> Result<(), UblkError> {
            let mut res = 0;
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
            q.submit_io_prep_cmd(tag, BufDesc::AutoReg(auto_buf_reg), res).await?;

            loop {
                res = handle_io_cmd(&q, tag).await;

                // Any error (including QueueIsDown) will break the loop by exiting the function
                q.submit_io_commit_cmd(tag, BufDesc::AutoReg(auto_buf_reg), res).await?;
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
        let q_fn = move |qid: u16, dev: &UblkDev| {
            let q_rc = Rc::new(UblkQueue::new(qid as u16, &dev).unwrap());
            let exe = smol::LocalExecutor::new();
            let mut f_vec = Vec::new();

            for tag in 0..depth {
                let q = q_rc.clone();

                f_vec.push(exe.spawn(async move {
                    if let Err(e) = test_auto_reg_io_task(&q, tag, depth, bad_buf_idx, fallback).await {
                        log::error!("test_auto_reg_io_task failed for tag {}: {}", tag, e);
                    }
                }));
            }

            ublk_wait_and_handle_ios(&exe, &q_rc);
            smol::block_on(exe.run(async { futures::future::join_all(f_vec).await }));
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
            let ext4_options = block_utils::Filesystem::Ext4 {
                inode_size: 512,
                stride: Some(2),
                stripe_width: None,
                reserved_blocks_percentage: 10,
            };
            block_utils::format_block_device(&Path::new(&dev_path), &ext4_options).unwrap();

            let tmp_dir = tempfile::TempDir::new().unwrap();
            let bdev = block_utils::get_device_info(Path::new(&dev_path)).unwrap();

            block_utils::mount_device(&bdev, tmp_dir.path()).unwrap();
            block_utils::unmount_device(tmp_dir.path()).unwrap();
        }
        ctrl.kill_dev().unwrap();
    }

    fn __test_ublk_ramdisk(dev_flags: UblkFlags) {
        // async function to handle individual I/O commands using slice operations for safe buffer access
        async fn handle_io_cmd(
            q: &UblkQueue<'_>,
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

        async fn test_ramdisk_io_task(q: &UblkQueue<'_>, tag: u16, ramdisk_addr: usize, mlock_enabled: bool) -> Result<(), UblkError> {
            let mut buf = IoBuf::<u8>::new(q.dev.dev_info.max_io_buf_bytes as usize);
            let mut res = 0;

            q.register_io_buf(tag, &buf);

            // If mlock is enabled, verify the buffer is mlocked after registration
            if mlock_enabled {
                assert!(
                    buf.is_mlocked(),
                    "Buffer should be mlocked when UBLK_DEV_F_MLOCK_IO_BUFFER is set"
                );
            }

            // Submit initial prep command - any error will exit the function
            q.submit_io_prep_cmd(tag, BufDesc::Slice(buf.as_slice()), res).await?;

            loop {
                res = handle_io_cmd(&q, tag, ramdisk_addr, buf.as_mut_slice()).await;

                // Any error (including QueueIsDown) will break the loop by exiting the function
                q.submit_io_commit_cmd(tag, BufDesc::Slice(buf.as_slice()), res).await?;
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

        let q_fn = move |qid: u16, dev: &UblkDev| {
            let q_rc = Rc::new(UblkQueue::new(qid as u16, &dev).unwrap());
            let exe = smol::LocalExecutor::new();
            let mut f_vec = Vec::new();

            let mlock_enabled = dev.flags.intersects(UblkFlags::UBLK_DEV_F_MLOCK_IO_BUFFER);

            for tag in 0..depth {
                let q = q_rc.clone();

                f_vec.push(exe.spawn(async move {
                    if let Err(e) = test_ramdisk_io_task(&q, tag, ramdisk_addr, mlock_enabled).await {
                        log::error!("test_ramdisk_io_task failed for tag {}: {}", tag, e);
                    }
                }));
            }

            // Show standard async way, however, yield_now() does hurt perf, which is
            // obviously slower than try_tick()
            let q = q_rc.clone();
            f_vec.push(exe.spawn(async move {
                loop {
                    if q.flush_and_wake_io_tasks(|data, cqe, _| ublk_wake_task(data, cqe), 1)
                        .is_err()
                    {
                        break;
                    }
                    //yield for handling incoming command
                    smol::future::yield_now().await;
                }
            }));
            smol::block_on(exe.run(futures::future::join_all(f_vec)));
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
        fn null_queue_mut_io(qid: u16, dev: &UblkDev) {
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

    /// run examples/ramdisk recovery test
    #[test]
    fn test_ublk_ramdisk_recovery() {
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

        let tgt_dir = get_curr_bin_dir().unwrap();
        //println!("top dir: path {:?} {:?}", &tgt_dir, &file);
        let rd_path = tgt_dir.display().to_string() + &"/examples/ramdisk".to_string();
        let mut cmd = Command::new(&rd_path)
            .args(["add", "-1", "32"])
            .stdout(Stdio::piped())
            .spawn()
            .expect("fail to add ublk ramdisk");
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

        fn single_cpu_null_handle_queue(qid: u16, dev: &UblkDev) {
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

        let q_fn = move |qid: u16, dev: &UblkDev| {
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

        let q_fn = move |qid: u16, dev: &UblkDev| {
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
                .submit_fetch_commands_unified(BufDescList::AutoRegs(&buf_reg_data_list)) {
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
