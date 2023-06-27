#[cfg(test)]
mod tests {
    use anyhow::Result as AnyRes;
    use core::any::Any;
    use libublk::*;
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
}
