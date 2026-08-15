//! End-to-end coverage for the shipped examples.
//!
//! `cargo test` only proves the examples compile; these tests run the
//! built example binaries against real ublk devices: add the device,
//! move data through it with O_DIRECT, and tear it down. Each test uses
//! a fixed device id well above what the auto-allocating library tests
//! grab, so the two suites can share a machine.

#[cfg(test)]
mod examples {
    use libublk::helpers::IoBuf;
    use std::os::fd::AsRawFd;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::{Duration, Instant};

    #[ctor::ctor]
    fn init_logger() {
        let _ = env_logger::builder()
            .format_target(false)
            .format_timestamp(None)
            .is_test(true)
            .try_init();
    }

    /// Locate a built example binary next to this test binary
    /// (target/<profile>/examples/<name>), building it on demand so the
    /// tests also work under `cargo test --tests`.
    fn example_bin(name: &str) -> PathBuf {
        let mut path = std::env::current_exe().unwrap();
        path.pop(); // deps/
        path.pop(); // <profile>/
        path.push("examples");
        path.push(name);
        if !path.exists() {
            let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
            let status = Command::new(cargo)
                .args(["build", "--example", name])
                .status()
                .expect("failed to spawn cargo");
            assert!(status.success(), "failed to build example {}", name);
        }
        path
    }

    /// Run an example command to completion, discarding its output.
    ///
    /// The daemonizing `add` commands keep stdout/stderr, so the daemon
    /// would hold a capture pipe open forever; null stdio plus `status()`
    /// avoids that, and works for every subcommand.
    fn run_example(name: &str, args: &[&str]) -> std::process::ExitStatus {
        Command::new(example_bin(name))
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap_or_else(|e| panic!("failed to run example {}: {}", name, e))
    }

    fn assert_ok(name: &str, args: &[&str], status: std::process::ExitStatus) {
        assert!(status.success(), "example {} {:?} failed: {}", name, args, status);
    }

    fn bdev_path(dev_id: i32) -> PathBuf {
        PathBuf::from(format!("/dev/ublkb{}", dev_id))
    }

    fn wait_for_bdev(dev_id: i32) {
        let path = bdev_path(dev_id);
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            // The device node can exist before START_DEV brings the disk
            // up (opening it then fails with ENXIO), so readiness is
            // "the device opens", not "the node exists".
            match std::fs::File::open(&path) {
                Ok(_) => return,
                Err(e) => {
                    assert!(
                        Instant::now() < deadline,
                        "device {} did not become usable: {}",
                        path.display(),
                        e
                    );
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
    }

    fn wait_bdev_gone(dev_id: i32) {
        let path = bdev_path(dev_id);
        let deadline = Instant::now() + Duration::from_secs(20);
        while path.exists() {
            assert!(
                Instant::now() < deadline,
                "device {} was not torn down",
                path.display()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Deletes the device through the example's own `del` command when the
    /// test exits, including on panic, so a failed run does not leak a
    /// device that blocks the next one.
    struct ExampleDev {
        example: &'static str,
        dev_id: i32,
        del_args: Vec<String>,
    }

    impl ExampleDev {
        /// Run `<example> add <add_args>` and wait for /dev/ublkbN.
        fn add(example: &'static str, dev_id: i32, add_args: &[&str]) -> Self {
            let del_args: Vec<String> = vec!["del".into(), "-n".into(), dev_id.to_string()];
            // Best-effort cleanup of a leftover from an earlier failed run.
            let del_ref: Vec<&str> = del_args.iter().map(|s| s.as_str()).collect();
            let _ = run_example(example, &del_ref);

            let mut args = vec!["add"];
            args.extend_from_slice(add_args);
            let status = run_example(example, &args);
            assert_ok(example, &args, status);
            wait_for_bdev(dev_id);
            Self {
                example,
                dev_id,
                del_args,
            }
        }
    }

    impl Drop for ExampleDev {
        fn drop(&mut self) {
            let del_ref: Vec<&str> = self.del_args.iter().map(|s| s.as_str()).collect();
            let status = run_example(self.example, &del_ref);
            if !std::thread::panicking() {
                assert_ok(self.example, &del_ref, status);
                wait_bdev_gone(self.dev_id);
            }
        }
    }

    fn open_direct(path: &Path, write: bool) -> std::fs::File {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .write(write)
            .custom_flags(libc::O_DIRECT)
            .open(path)
            .unwrap_or_else(|e| panic!("open {} failed: {}", path.display(), e))
    }

    fn read_direct(path: &Path, off: u64, len: usize) -> Vec<u8> {
        let file = open_direct(path, false);
        let buf = IoBuf::<u8>::new(len);
        let r = unsafe {
            libc::pread(
                file.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                len,
                off as libc::off_t,
            )
        };
        assert_eq!(r, len as isize, "short direct read from {}", path.display());
        buf.as_slice().to_vec()
    }

    fn write_direct(path: &Path, off: u64, data: &[u8]) {
        let file = open_direct(path, true);
        let mut buf = IoBuf::<u8>::new(data.len());
        buf.as_mut_slice().copy_from_slice(data);
        let r = unsafe {
            libc::pwrite(
                file.as_raw_fd(),
                buf.as_mut_ptr() as *const libc::c_void,
                data.len(),
                off as libc::off_t,
            )
        };
        assert_eq!(
            r,
            data.len() as isize,
            "short direct write to {}",
            path.display()
        );
    }

    fn pattern(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
            .collect()
    }

    const IO_BYTES: usize = 32 << 10;

    /// null and batch discard writes and return zeroes on read.
    fn null_like_io_check(dev_id: i32) {
        let bdev = bdev_path(dev_id);
        write_direct(&bdev, 1 << 20, &pattern(IO_BYTES, 7));
        let read = read_direct(&bdev, 1 << 20, IO_BYTES);
        assert!(
            read.iter().all(|&b| b == 0),
            "null-like device returned nonzero data"
        );
    }

    /// loop and ramdisk store data: a written pattern must read back.
    fn data_io_check(dev_id: i32, seed: u8) {
        let bdev = bdev_path(dev_id);
        let data = pattern(IO_BYTES, seed);
        write_direct(&bdev, 1 << 20, &data);
        assert_eq!(
            read_direct(&bdev, 1 << 20, IO_BYTES),
            data,
            "data written through the device did not read back"
        );
    }

    #[test]
    fn test_example_null_sync() {
        let id = "131";
        let dev = ExampleDev::add("null", 131, &["-n", id]);
        null_like_io_check(dev.dev_id);

        // The list subcommand must see the live device.
        let status = run_example("null", &["list", "-n", id]);
        assert_ok("null", &["list"], status);
    }

    #[test]
    fn test_example_null_async() {
        let dev = ExampleDev::add("null", 132, &["-n", "132", "-a"]);
        null_like_io_check(dev.dev_id);
    }

    fn loop_example_test(dev_id: i32, async_mode: bool) {
        let backing = std::env::temp_dir().join(format!("libublk-loop-example-{}.img", dev_id));
        let backing_str = backing.to_str().unwrap().to_string();
        let init = pattern(1 << 20, 3);
        std::fs::write(&backing, &init).unwrap();
        // The loop target sizes the device from the backing file; grow it
        // so the IO offsets below stay in range.
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&backing)
            .unwrap();
        file.set_len(8 << 20).unwrap();
        drop(file);

        {
            let id = dev_id.to_string();
            let mut args = vec!["-n", id.as_str(), "-f", backing_str.as_str()];
            if async_mode {
                args.push("-a");
            }
            let _dev = ExampleDev::add("loop", dev_id, &args);

            // Existing backing data must be visible through the device.
            let bdev = bdev_path(dev_id);
            assert_eq!(
                read_direct(&bdev, 0, IO_BYTES),
                init[..IO_BYTES],
                "backing file contents did not read back through the device"
            );
            data_io_check(dev_id, 11);
        }

        // After teardown the write must have landed in the backing file.
        let stored = std::fs::read(&backing).unwrap();
        assert_eq!(
            &stored[1 << 20..(1 << 20) + IO_BYTES],
            &pattern(IO_BYTES, 11)[..],
            "device write did not reach the backing file"
        );
        let _ = std::fs::remove_file(&backing);
    }

    #[test]
    fn test_example_loop_sync() {
        loop_example_test(133, false);
    }

    #[test]
    fn test_example_loop_async() {
        loop_example_test(134, true);
    }

    #[test]
    fn test_example_ramdisk() {
        // ramdisk's CLI is positional (add <id> <MiB>) and its add command
        // blocks on an eventfd until the device is serving, so no polling
        // is needed on the add side; reuse the guard only for teardown.
        let status = run_example("ramdisk", &["add", "135", "16"]);
        assert_ok("ramdisk", &["add", "135", "16"], status);
        let dev = ExampleDev {
            example: "ramdisk",
            dev_id: 135,
            del_args: vec!["del".into(), "135".into()],
        };
        wait_for_bdev(dev.dev_id);
        data_io_check(dev.dev_id, 23);
    }

    #[test]
    fn test_example_batch() {
        let dev = ExampleDev::add("batch", 136, &["-n", "136"]);
        null_like_io_check(dev.dev_id);
    }
}
