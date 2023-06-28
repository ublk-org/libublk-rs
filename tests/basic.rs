#[cfg(test)]
mod tests {
    use anyhow::Result as AnyRes;
    use core::any::Any;
    use libublk::*;
    use std::env;
    use std::path::Path;
    use std::sync::Arc;

    #[test]
    fn add_ctrl_dev() {
        let ctrl = UblkCtrl::new(-1, 1, 64, 512_u32 * 1024, 0, true).unwrap();
        let dev_path = format!("{}{}", CDEV_PATH, ctrl.dev_info.dev_id);

        std::thread::sleep(std::time::Duration::from_millis(500));
        assert!(Path::new(&dev_path).exists() == true);
    }

    struct NullTgt {}
    struct NullQueue {}

    // setup null target
    impl UblkTgtImpl for NullTgt {
        fn init_tgt(&self, dev: &UblkDev) -> AnyRes<serde_json::Value> {
            let info = dev.dev_info;
            let dev_size = 250_u64 << 30;

            let mut tgt = dev.tgt.borrow_mut();

            tgt.dev_size = dev_size;
            tgt.params = ublk_params {
                types: UBLK_PARAM_TYPE_BASIC,
                basic: ublk_param_basic {
                    logical_bs_shift: 9,
                    physical_bs_shift: 12,
                    io_opt_shift: 12,
                    io_min_shift: 9,
                    max_sectors: info.max_io_buf_bytes >> 9,
                    dev_sectors: dev_size >> 9,
                    ..Default::default()
                },
                ..Default::default()
            };

            Ok(serde_json::json!({}))
        }
        fn deinit_tgt(&self, _dev: &UblkDev) {}
        fn tgt_type(&self) -> &'static str {
            "null"
        }
        #[inline(always)]
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    // implement io logic, and it is the main job for writing new ublk target
    impl UblkQueueImpl for NullQueue {
        fn queue_io(&self, q: &mut UblkQueue, tag: u32) -> AnyRes<i32> {
            let iod = q.get_iod(tag);
            let bytes = unsafe { (*iod).nr_sectors << 9 } as i32;

            q.complete_io(tag as u16, bytes);
            Ok(0)
        }
    }

    /// make one ublk-null and test if /dev/ublkbN can be created successfully
    #[test]
    fn test_ublk_null() {
        ublk_tgt_worker(
            -1,
            2,
            64,
            512_u32 * 1024,
            0,
            true,
            || Box::new(NullTgt {}),
            Arc::new(|| Box::new(NullQueue {}) as Box<dyn UblkQueueImpl>),
            |dev_id| {
                let mut ctrl = UblkCtrl::new(dev_id, 0, 0, 0, 0, false).unwrap();
                let dev_path = format!("{}{}", BDEV_PATH, dev_id);

                std::thread::sleep(std::time::Duration::from_millis(500));

                //ublk block device should be observed now
                assert!(Path::new(&dev_path).exists() == true);

                //ublk exported json file should be observed
                assert!(Path::new(&ctrl.run_path()).exists() == true);

                ctrl.del().unwrap();
            },
        )
        .unwrap()
        .join()
        .unwrap();
    }

    struct RamdiskTgt {
        size: u64,
        start: u64,
    }

    struct RamdiskQueue {}

    // setup ramdisk target
    impl UblkTgtImpl for RamdiskTgt {
        fn init_tgt(&self, dev: &UblkDev) -> AnyRes<serde_json::Value> {
            let info = dev.dev_info;
            let dev_size = self.size;

            let mut tgt = dev.tgt.borrow_mut();

            tgt.dev_size = dev_size;
            tgt.params = ublk_params {
                types: UBLK_PARAM_TYPE_BASIC,
                basic: ublk_param_basic {
                    logical_bs_shift: 12,
                    physical_bs_shift: 12,
                    io_opt_shift: 12,
                    io_min_shift: 12,
                    max_sectors: info.max_io_buf_bytes >> 9,
                    dev_sectors: dev_size >> 9,
                    ..Default::default()
                },
                ..Default::default()
            };

            Ok(serde_json::json!({}))
        }
        fn deinit_tgt(&self, _dev: &UblkDev) {}
        fn tgt_type(&self) -> &'static str {
            "ramdisk"
        }
        #[inline(always)]
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    // implement io logic, and it is the main job for writing new ublk target
    impl UblkQueueImpl for RamdiskQueue {
        fn queue_io(&self, q: &mut UblkQueue, tag: u32) -> AnyRes<i32> {
            let _iod = q.get_iod(tag);
            let iod = unsafe { &*_iod };
            let off = (iod.start_sector << 9) as u64;
            let bytes = (iod.nr_sectors << 9) as u32;
            let op = iod.op_flags & 0xff;
            let tgt = ublk_tgt_data_from_queue::<RamdiskTgt>(q.dev).unwrap();
            let start = tgt.start;
            let buf_addr = q.get_buf_addr(tag);

            match op {
                UBLK_IO_OP_FLUSH => {}
                UBLK_IO_OP_READ => unsafe {
                    libc::memcpy(
                        buf_addr as *mut libc::c_void,
                        (start + off) as *mut libc::c_void,
                        bytes as usize,
                    );
                },
                UBLK_IO_OP_WRITE => unsafe {
                    libc::memcpy(
                        (start + off) as *mut libc::c_void,
                        buf_addr as *mut libc::c_void,
                        bytes as usize,
                    );
                },
                _ => return Err(anyhow::anyhow!("unexpected op")),
            }

            q.complete_io(tag as u16, bytes as i32);
            Ok(0)
        }
    }

    /// make one ublk-ramdisk and test:
    /// - if /dev/ublkbN can be created successfully
    /// - if yes, then test format/mount/umount over this ublk-ramdisk
    #[test]
    fn test_ublk_ramdisk() {
        let size = 32_u64 << 20;
        let buf = ublk_alloc_buf(size as usize, 4096);
        let buf_addr = buf as u64;

        ublk_tgt_worker(
            -1,
            1,
            64,
            512_u32 * 1024,
            0,
            true,
            || {
                Box::new(RamdiskTgt {
                    size: size,
                    start: buf_addr,
                })
            },
            Arc::new(|| Box::new(RamdiskQueue {}) as Box<dyn UblkQueueImpl>),
            |dev_id| {
                let mut ctrl = UblkCtrl::new(dev_id, 0, 0, 0, 0, false).unwrap();
                let dev_path = format!("{}{}", BDEV_PATH, dev_id);

                std::thread::sleep(std::time::Duration::from_millis(500));

                //ublk block device should be observed now
                assert!(Path::new(&dev_path).exists() == true);

                //ublk exported json file should be observed
                assert!(Path::new(&ctrl.run_path()).exists() == true);

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
                ctrl.del().unwrap();
            },
        )
        .unwrap()
        .join()
        .unwrap();
        ublk_dealloc_buf(buf, size as usize, 4096);
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

    /// run examples/ramdisk recovery test
    #[test]
    fn test_ublk_ramdisk_recovery() {
        use std::process::{Command, Stdio};

        let tgt_dir = get_curr_bin_dir().unwrap();
        let tmpfile = tempfile::NamedTempFile::new().unwrap();
        let file = std::fs::File::create(tmpfile.path()).unwrap();

        //println!("top dir: path {:?} {:?}", &tgt_dir, &file);
        let rd_path = tgt_dir.display().to_string() + &"/examples/ramdisk".to_string();
        let mut cmd = Command::new(&rd_path)
            .args(["add"])
            .stdout(Stdio::from(file))
            .spawn()
            .expect("fail to add ublk ramdisk");
        cmd.wait().unwrap();

        //this magic wait makes a difference
        std::thread::sleep(std::time::Duration::from_millis(100));
        let buf = std::fs::read_to_string(tmpfile.path()).unwrap();

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

        let mut ctrl = UblkCtrl::new(id, 0, 0, 0, 0, false).unwrap();
        ublk_state_wait_until(&mut ctrl, libublk::UBLK_S_DEV_LIVE as u16, 2000);

        //ublk block device should be observed now
        let dev_path = format!("{}{}", libublk::BDEV_PATH, id);
        assert!(Path::new(&dev_path).exists() == true);

        //simulate one panic by sending KILL to queue pthread
        unsafe {
            libc::kill(tid, libc::SIGKILL);
        }

        //wait device becomes quiesced
        ublk_state_wait_until(&mut ctrl, libublk::UBLK_S_DEV_QUIESCED as u16, 6000);

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
        ublk_state_wait_until(&mut ctrl, libublk::UBLK_S_DEV_LIVE as u16, 5000);
        ctrl.del_dev().unwrap();
    }
}
