#[cfg(test)]
mod integration {
    use io_uring::opcode;
    use libublk::dev_flags::*;
    use libublk::exe::{Executor, UringOpFuture};
    use libublk::io::{UblkDev, UblkIOCtx, UblkQueue};
    use libublk::{ctrl::UblkCtrl, UblkError, UblkIORes};
    use libublk::{sys, UblkSessionBuilder};
    use std::env;
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::rc::Rc;
    use std::sync::{Arc, Mutex};

    fn run_ublk_disk_sanity_test(ctrl: &mut UblkCtrl, dev_flags: u32) {
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

    fn read_ublk_disk(dev_id: i32) {
        let ctrl = UblkCtrl::new_simple(dev_id, 0).unwrap();
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
        let sess = UblkSessionBuilder::default()
            .name("null")
            .depth(64_u32)
            .nr_queues(2_u32)
            .dev_flags(dev_flags)
            .ctrl_flags(libublk::sys::UBLK_F_USER_COPY)
            .build()
            .unwrap();
        let tgt_init = |dev: &mut UblkDev| {
            dev.set_default_params(250_u64 << 30);
            Ok(0)
        };

        let (mut ctrl, dev) = sess.create_devices(tgt_init).unwrap();
        let q_fn = move |qid: u16, _dev: &UblkDev| {
            q_handler(qid, _dev);
        };

        sess.run_target(&mut ctrl, &dev, q_fn, move |dev_id| {
            let mut ctrl = UblkCtrl::new_simple(dev_id, 0).unwrap();

            run_ublk_disk_sanity_test(&mut ctrl, dev_flags);
            read_ublk_disk(dev_id);

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

                q.complete_io_cmd(tag, Ok(UblkIORes::Result(bytes)));
            };

            UblkQueue::new(qid, _dev)
                .unwrap()
                .wait_and_handle_io(io_handler);
        }

        __test_ublk_null(
            UBLK_DEV_F_ADD_DEV | UBLK_DEV_F_DONT_ALLOC_BUF,
            null_handle_queue,
        );
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

                let res = Ok(UblkIORes::FatRes(UblkFatRes::BatchRes(vec![(tag, bytes)])));
                q.complete_io_cmd(tag, res);
            };

            UblkQueue::new(qid, _dev)
                .unwrap()
                .wait_and_handle_io(io_handler);
        }

        __test_ublk_null(
            UBLK_DEV_F_ADD_DEV | UBLK_DEV_F_DONT_ALLOC_BUF | UBLK_DEV_F_COMP_BATCH,
            null_handle_queue_batch,
        );
    }

    #[test]
    fn test_ublk_null_async() {
        // submit one io_uring Nop via io-uring crate and UringOpFuture, and
        // user_data has to unique among io tasks, also has to encode tag
        // info, so please build user_data by UblkIOCtx::build_user_data_async()
        fn null_submit_nop(q: &UblkQueue<'_>, user_data: u64) -> UringOpFuture {
            let nop_e = opcode::Nop::new().build().user_data(user_data);

            unsafe {
                q.q_ring
                    .borrow_mut()
                    .submission()
                    .push(&nop_e)
                    .expect("submission fail");
            };
            UringOpFuture { user_data }
        }
        async fn handle_io_cmd(q: &UblkQueue<'_>, tag: u16) -> i32 {
            let iod = q.get_iod(tag);
            let bytes = (iod.nr_sectors << 9) as i32;
            let data = UblkIOCtx::build_user_data_async(tag, 0xff, 0);

            bytes + null_submit_nop(&q, data).await
        }

        //Device wide data shared among all queue context
        struct DevData {
            done: u64,
        }

        // submit one io_uring Nop via io-uring crate and UringOpFuture, and
        // user_data has to unique among io tasks, also has to encode tag
        // info, so please build user_data by UblkIOCtx::build_user_data_async()
        let dev_flags = UBLK_DEV_F_ADD_DEV | UBLK_DEV_F_ASYNC;
        let depth = 64_u16;
        let sess = libublk::UblkSessionBuilder::default()
            .name("null")
            .nr_queues(2_u16)
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

        let (mut ctrl, dev) = sess.create_devices(tgt_init).unwrap();
        // queue handler supports Clone(), so will be cloned in each
        // queue pthread context
        let q_fn = move |qid: u16, dev: &UblkDev| {
            let q_rc = Rc::new(UblkQueue::new(qid as u16, &dev).unwrap());
            let exe = Executor::new(dev.get_nr_ios());

            // `q_fn` closure implements Clone() Trait, so the captured
            // `dev_data` is cloned to `q_fn` context.
            let _dev_data = Rc::new(dev_data);

            for tag in 0..depth {
                let q = q_rc.clone();
                let __dev_data = _dev_data.clone();

                exe.spawn(tag as u16, async move {
                    let mut cmd_op = sys::UBLK_IO_FETCH_REQ;
                    let buf = q.get_io_buf_addr(tag);
                    let mut res = 0;
                    loop {
                        let cmd_res = q.submit_io_cmd(tag, cmd_op, buf, res).await;
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
                });
            }
            q_rc.wait_and_wake_io_tasks(&exe);
        };

        // kick off our targets
        sess.run_target(&mut ctrl, &dev, q_fn, move |dev_id| {
            let mut ctrl = UblkCtrl::new_simple(dev_id, 0).unwrap();

            // run sanity and disk IO test after ublk disk is ready
            run_ublk_disk_sanity_test(&mut ctrl, dev_flags);
            read_ublk_disk(dev_id);

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
        fn rd_handle_io(q: &UblkQueue, tag: u16, _io: &UblkIOCtx, start: u64) {
            let iod = q.get_iod(tag);
            let off = (iod.start_sector << 9) as u64;
            let bytes = (iod.nr_sectors << 9) as u32;
            let op = iod.op_flags & 0xff;
            let buf_addr = q.get_io_buf_addr(tag);

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
                    q.complete_io_cmd(tag, Err(UblkError::OtherError(-libc::EINVAL)));
                    return;
                }
            }

            let res = Ok(UblkIORes::Result(bytes as i32));
            q.complete_io_cmd(tag, res);
        }

        fn __test_ublk_ramdisk(dev_id: i32) {
            let mut ctrl = UblkCtrl::new_simple(dev_id, 0).unwrap();
            let dev_path = ctrl.get_bdev_path();

            run_ublk_disk_sanity_test(&mut ctrl, UBLK_DEV_F_ADD_DEV);

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
        let buf = libublk::ublk_alloc_buf(size as usize, 4096);
        let buf_addr = buf as u64;
        let sess = libublk::UblkSessionBuilder::default()
            .name("ramdisk")
            .id(-1)
            .nr_queues(1_u16)
            .depth(128_u16)
            .dev_flags(UBLK_DEV_F_ADD_DEV)
            .build()
            .unwrap();
        let tgt_init = |dev: &mut UblkDev| {
            dev.set_default_params(size);
            Ok(0)
        };

        let (mut ctrl, dev) = sess.create_devices(tgt_init).unwrap();
        let q_fn = move |qid: u16, _dev: &UblkDev| {
            let io_handler = move |q: &UblkQueue, tag: u16, _io: &UblkIOCtx| {
                rd_handle_io(q, tag, _io, buf_addr);
            };
            UblkQueue::new(qid, _dev)
                .unwrap()
                .wait_and_handle_io(io_handler);
        };

        sess.run_target(&mut ctrl, &dev, q_fn, move |dev_id| {
            __test_ublk_ramdisk(dev_id);
        })
        .unwrap();
        libublk::ublk_dealloc_buf(buf, size as usize, 4096);
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

                {
                    q_vec.push(tag as i32);
                    if q_vec.len() >= 64 {
                        q_vec.clear();
                    }
                }

                q.complete_io_cmd(tag, res);
            };

            UblkQueue::new(qid, _dev)
                .unwrap()
                .wait_and_handle_io(io_handler);
        }

        __test_ublk_null(
            UBLK_DEV_F_ADD_DEV | UBLK_DEV_F_DONT_ALLOC_BUF,
            null_queue_mut_io,
        );
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

        fn ublk_state_wait_until(ctrl: &mut UblkCtrl, state: u16, timeout: u32) {
            let mut count = 0;
            let unit = 100_u32;
            loop {
                std::thread::sleep(std::time::Duration::from_millis(unit as u64));

                ctrl.get_info().unwrap();
                if ctrl.dev_info.state == state {
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

        let mut ctrl = UblkCtrl::new_simple(id, 0).unwrap();
        ublk_state_wait_until(&mut ctrl, sys::UBLK_S_DEV_LIVE as u16, 2000);

        //ublk block device should be observed now
        let dev_path = ctrl.get_bdev_path();
        assert!(Path::new(&dev_path).exists() == true);

        //simulate one panic by sending KILL to queue pthread
        unsafe {
            libc::kill(tid, libc::SIGKILL);
        }

        //wait device becomes quiesced
        ublk_state_wait_until(&mut ctrl, sys::UBLK_S_DEV_QUIESCED as u16, 6000);

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
        ublk_state_wait_until(&mut ctrl, sys::UBLK_S_DEV_LIVE as u16, 20000);
        ctrl.del_dev().unwrap();
    }
}
