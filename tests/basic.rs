#[cfg(test)]
mod integration {
    use io_uring::opcode;
    use libublk::dev_flags::*;
    use libublk::helpers::IoBuf;
    use libublk::io::{UblkDev, UblkIOCtx, UblkQueue};
    use libublk::uring_async::ublk_wait_and_handle_ios;
    use libublk::{ctrl::UblkCtrl, ctrl::UblkCtrlBuilder, sys, UblkError, UblkIORes};
    use std::env;
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::rc::Rc;
    use std::sync::{Arc, Mutex};

    fn run_ublk_disk_sanity_test(ctrl: &UblkCtrl, dev_flags: u32) {
        use std::os::unix::fs::PermissionsExt;
        let dev_path = ctrl.get_cdev_path();

        std::thread::sleep(std::time::Duration::from_millis(500));

        assert!(ctrl.get_target_flags_from_json().unwrap() == dev_flags);

        //ublk block device should be observed now
        assert!(Path::new(&dev_path).exists() == true);

        //ublk exported json file should be observed
        let run_path = ctrl.run_path();
        let json_path = Path::new(&run_path);
        assert!(json_path.exists() == true);

        let metadata = std::fs::metadata(json_path)
            .map_err(UblkError::OtherIOError)
            .unwrap();
        let permissions = metadata.permissions();
        assert!((permissions.mode() & 0o777) == 0o700);
    }

    fn read_ublk_disk(ctrl: &UblkCtrl) {
        let dev_path = ctrl.get_bdev_path();
        let mut arg_list: Vec<String> = Vec::new();
        let if_dev = format!("if={}", &dev_path);

        arg_list.push(if_dev);
        arg_list.push("of=/dev/null".to_string());
        arg_list.push("bs=4096".to_string());
        arg_list.push("count=10k".to_string());
        println!("{:?}", Command::new("dd").args(arg_list).output().unwrap());
    }

    fn __test_ublk_null(dev_flags: u32, q_handler: fn(u16, &UblkDev)) {
        let ctrl = UblkCtrlBuilder::default()
            .name("null")
            .nr_queues(2)
            .dev_flags(dev_flags)
            .ctrl_flags(libublk::sys::UBLK_F_USER_COPY.into())
            .build()
            .unwrap();
        let tgt_init = |dev: &mut UblkDev| {
            dev.set_default_params(250_u64 << 30);
            Ok(0)
        };

        let q_fn = move |qid: u16, _dev: &UblkDev| {
            q_handler(qid, _dev);
        };

        ctrl.run_target(tgt_init, q_fn, move |ctrl: &UblkCtrl| {
            run_ublk_disk_sanity_test(ctrl, dev_flags);
            read_ublk_disk(ctrl);

            ctrl.kill_dev().unwrap();
        })
        .unwrap();
    }

    /// make one ublk-null and test if /dev/ublkbN can be created successfully
    #[test]
    fn test_ublk_null() {
        /// called from queue_handler closure(), which supports Clone(),
        fn null_handle_queue(qid: u16, _dev: &UblkDev) {
            let io_handler = move |q: &UblkQueue, tag: u16, _io: &UblkIOCtx| {
                let iod = q.get_iod(tag);
                let bytes = (iod.nr_sectors << 9) as i32;
                let buf_addr = std::ptr::null_mut();

                q.complete_io_cmd(tag, buf_addr, Ok(UblkIORes::Result(bytes)));
            };

            UblkQueue::new(qid, _dev)
                .unwrap()
                .submit_fetch_commands(None)
                .wait_and_handle_io(io_handler);
        }

        __test_ublk_null(UBLK_DEV_F_ADD_DEV, null_handle_queue);
    }

    /// make one ublk-null and test if /dev/ublkbN can be created successfully
    #[cfg(feature = "fat_complete")]
    #[test]
    fn test_ublk_null_comp_batch() {
        use libublk::UblkFatRes;
        /// called from queue_handler closure(), which supports Clone(),
        fn null_handle_queue_batch(qid: u16, _dev: &UblkDev) {
            let io_handler = move |q: &UblkQueue, tag: u16, _io: &UblkIOCtx| {
                let iod = q.get_iod(tag);
                let bytes = (iod.nr_sectors << 9) as i32;
                let buf_addr = std::ptr::null_mut();

                let res = Ok(UblkIORes::FatRes(UblkFatRes::BatchRes(vec![(tag, bytes)])));
                q.complete_io_cmd(tag, buf_addr, res);
            };

            UblkQueue::new(qid, _dev)
                .unwrap()
                .submit_fetch_commands(None)
                .wait_and_handle_io(io_handler);
        }

        __test_ublk_null(
            UBLK_DEV_F_ADD_DEV | UBLK_DEV_F_COMP_BATCH,
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

        //Device wide data shared among all queue context
        struct DevData {
            done: u64,
        }

        // submit one io_uring Nop via io-uring crate and UringOpFuture, and
        // user_data has to unique among io tasks, also has to encode tag
        // info, so please build user_data by UblkIOCtx::build_user_data_async()
        let dev_flags = UBLK_DEV_F_ADD_DEV;
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
            Ok(0)
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
                    let mut cmd_op = sys::UBLK_IO_FETCH_REQ;
                    let buf = IoBuf::<u8>::new(q.dev.dev_info.max_io_buf_bytes as usize);
                    let mut res = 0;

                    q.register_io_buf(tag, &buf);
                    loop {
                        let cmd_res = q.submit_io_cmd(tag, cmd_op, buf.as_mut_ptr(), res).await;
                        if cmd_res == sys::UBLK_IO_RES_ABORT {
                            break;
                        }

                        res = handle_io_cmd(&q, tag).await;
                        cmd_op = sys::UBLK_IO_COMMIT_AND_FETCH_REQ;
                        {
                            let mut guard = __dev_data.lock().unwrap();
                            (*guard).done += 1;
                        }
                    }
                }));
            }

            ublk_wait_and_handle_ios(&q_rc, &exe);
            smol::block_on(async { futures::future::join_all(f_vec).await });
        };

        // kick off our targets
        ctrl.run_target(tgt_init, q_fn, move |ctrl: &UblkCtrl| {
            // run sanity and disk IO test after ublk disk is ready
            run_ublk_disk_sanity_test(ctrl, dev_flags);
            read_ublk_disk(ctrl);

            {
                let guard = wh_dev_data.lock().unwrap();
                assert!((*guard).done > 0);
            }

            ctrl.kill_dev().unwrap();
        })
        .unwrap();
    }

    /// make one ublk-ramdisk and test:
    /// - if /dev/ublkbN can be created successfully
    /// - if yes, then test format/mount/umount over this ublk-ramdisk
    #[test]
    fn test_ublk_ramdisk() {
        fn rd_handle_io(q: &UblkQueue, tag: u16, _io: &UblkIOCtx, buf_addr: *mut u8, start: u64) {
            let iod = q.get_iod(tag);
            let off = (iod.start_sector << 9) as u64;
            let bytes = (iod.nr_sectors << 9) as u32;
            let op = iod.op_flags & 0xff;

            match op {
                sys::UBLK_IO_OP_FLUSH => {}
                sys::UBLK_IO_OP_READ => unsafe {
                    libc::memcpy(
                        buf_addr as *mut libc::c_void,
                        (start + off) as *mut libc::c_void,
                        bytes as usize,
                    );
                },
                sys::UBLK_IO_OP_WRITE => unsafe {
                    libc::memcpy(
                        (start + off) as *mut libc::c_void,
                        buf_addr as *mut libc::c_void,
                        bytes as usize,
                    );
                },
                _ => {
                    q.complete_io_cmd(tag, buf_addr, Err(UblkError::OtherError(-libc::EINVAL)));
                    return;
                }
            }

            let res = Ok(UblkIORes::Result(bytes as i32));
            q.complete_io_cmd(tag, buf_addr, res);
        }

        fn __test_ublk_ramdisk(ctrl: &UblkCtrl, dev_flags: u32) {
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

        let size = 32_u64 << 20;
        let buf = libublk::helpers::IoBuf::<u8>::new(size as usize);
        let dev_addr = buf.as_mut_ptr() as u64;
        let dev_flags = UBLK_DEV_F_ADD_DEV;
        let ctrl = UblkCtrlBuilder::default()
            .name("ramdisk")
            .id(-1)
            .nr_queues(1)
            .depth(128)
            .dev_flags(dev_flags)
            .build()
            .unwrap();
        let tgt_init = |dev: &mut UblkDev| {
            dev.set_default_params(size);
            Ok(0)
        };

        let q_fn = move |qid: u16, dev: &UblkDev| {
            let bufs_rc = Rc::new(dev.alloc_queue_io_bufs());
            let bufs = bufs_rc.clone();

            let io_handler = move |q: &UblkQueue, tag: u16, _io: &UblkIOCtx| {
                let bufs = bufs_rc.clone();
                let buf_addr = bufs[tag as usize].as_mut_ptr();

                rd_handle_io(q, tag, _io, buf_addr, dev_addr);
            };

            UblkQueue::new(qid, dev)
                .unwrap()
                .regiser_io_bufs(Some(&bufs))
                .submit_fetch_commands(Some(&bufs))
                .wait_and_handle_io(io_handler);
        };

        ctrl.run_target(tgt_init, q_fn, move |ctrl: &UblkCtrl| {
            __test_ublk_ramdisk(ctrl, dev_flags);
        })
        .unwrap();
    }

    /// make FnMut closure for IO handling
    #[test]
    fn test_fn_mut_io_closure() {
        /// called from queue_handler closure(), which supports Clone(),
        fn null_queue_mut_io(qid: u16, _dev: &UblkDev) {
            // modify this vector in io handling closure
            let mut q_vec = Vec::<i32>::new();
            let io_handler = move |q: &UblkQueue, tag: u16, _io: &UblkIOCtx| {
                let iod = q.get_iod(tag);
                let res = Ok(UblkIORes::Result((iod.nr_sectors << 9) as i32));
                let buf_addr = std::ptr::null_mut();

                {
                    q_vec.push(tag as i32);
                    if q_vec.len() >= 64 {
                        q_vec.clear();
                    }
                }

                q.complete_io_cmd(tag, buf_addr, res);
            };

            UblkQueue::new(qid, _dev)
                .unwrap()
                .submit_fetch_commands(None)
                .wait_and_handle_io(io_handler);
        }

        __test_ublk_null(UBLK_DEV_F_ADD_DEV, null_queue_mut_io);
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
        let tmpfile = tempfile::NamedTempFile::new().unwrap();
        let file = std::fs::File::create(tmpfile.path()).unwrap();

        //println!("top dir: path {:?} {:?}", &tgt_dir, &file);
        let rd_path = tgt_dir.display().to_string() + &"/examples/ramdisk".to_string();
        let mut cmd = Command::new(&rd_path)
            .args(["add", "-1", "32"])
            .stdout(Stdio::from(file))
            .spawn()
            .expect("fail to add ublk ramdisk");
        cmd.wait().unwrap();

        let buf = loop {
            std::thread::sleep(std::time::Duration::from_millis(200));
            let _buf = std::fs::read_to_string(tmpfile.path()).unwrap();

            if _buf.len() >= 200 {
                break _buf;
            }
        };

        let id_regx = regex::Regex::new(r"dev id (\d+)").unwrap();
        let tid_regx = regex::Regex::new(r"queue 0 tid: (\d+)").unwrap();

        let mut id = -1_i32;
        if let Some(c) = id_regx.captures(&buf.as_str()) {
            id = c.get(1).unwrap().as_str().parse().unwrap();
        }

        let mut tid = 0;
        if let Some(c) = tid_regx.captures(&buf.as_str()) {
            tid = c.get(1).unwrap().as_str().parse().unwrap();
        }
        assert!(tid != 0);

        let ctrl = UblkCtrl::new_simple(id, 0).unwrap();
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

        let file = std::fs::File::create(tmpfile.path()).unwrap();
        //recover device
        let mut cmd = Command::new(&rd_path)
            .args(["recover", &id.to_string().as_str()])
            .stdout(Stdio::from(file))
            .spawn()
            .expect("fail to recover ramdisk");
        cmd.wait().unwrap();
        //let buf = std::fs::read_to_string(tmpfile.path()).unwrap();
        //println!("{}", buf);
        ublk_state_wait_until(&ctrl, sys::UBLK_S_DEV_LIVE as u16, 20000);
        ctrl.del_dev().unwrap();
    }
}
