use async_lock::Mutex;
use bitflags::bitflags;
use clap::{Arg, ArgAction, Command};
use libublk::helpers::IoBuf;
use libublk::io::{UblkDev, UblkQueue};
use libublk::tokio;
use libublk::{ctrl::UblkCtrl, BufDesc, UblkError, UblkFlags};
use rand::Rng;
use slab::Slab;
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

bitflags! {
    #[derive(Default)]
    struct BatchFlags: u32 {
        const FOREGROUND = 0b00000010;
        const ONESHOT = 0b00000100;
        const ZERO_COPY = 0b00001000;
    }
}

// Batch coordination infrastructure - OPTIMIZED: No more semaphore!
struct BatchCoordinator {
    current_write_batch: Vec<u16>,   // Write tags for this batch
    phase2_flush_mutex: Mutex<bool>, // true when flush is complete
}

impl BatchCoordinator {
    fn new(write_tags: Vec<u16>) -> Self {
        let write_batch_size = write_tags.len();
        log::info!(
            "Created coordinator with {} write tasks: {:?}",
            write_batch_size,
            write_tags
        );

        Self {
            current_write_batch: write_tags,
            phase2_flush_mutex: Mutex::new(false), // false = flush not done yet
        }
    }

    // Remove tag from batch and return true if batch is now empty
    fn remove_write_tag(&mut self, tag: u16) -> bool {
        if let Some(pos) = self.current_write_batch.iter().position(|&x| x == tag) {
            self.current_write_batch.remove(pos);
        }
        self.current_write_batch.is_empty()
    }

    // Tag of all RAID1 write IOs in this batch can be retrieved from `current_write_batch`,
    // then member disk's LBA & sectors can be figured out, either mark bitmap or flush
    // LBA ranges to journal.
    async fn flush_resync_bits(&self, tag: u16) -> Result<(), UblkError> {
        // Phase 2: Simulate RAID1 resync bit flush - only one task does the actual flush
        let mut flush_done = self.phase2_flush_mutex.lock().await;
        if !*flush_done {
            // This task wins the race and performs the flush
            // Simulate flush operation (in real RAID1, this would be disk I/O)
            *flush_done = true;
            log::info!(
                "Task {} completed resync bit flush for {:?}",
                tag,
                &self.current_write_batch
            );
        }
        Ok(())
    }

    async fn mark_task_complete(&mut self, tag: u16) -> Result<bool, UblkError> {
        log::debug!("Task {} completed", tag);

        Ok(self.remove_write_tag(tag))
    }
}

// Per-queue batch management state - OPTIMIZED: Added write tag collection
struct QueueBatchState {
    queue_id: u16,
    coordinators: Slab<BatchCoordinator>,

    // Tags collected in current reap cycle
    pending_write_tags: RefCell<Vec<u16>>,
}

impl QueueBatchState {
    fn new(queue_id: u16) -> Self {
        Self {
            queue_id,
            coordinators: Slab::new(),
            pending_write_tags: RefCell::new(Vec::new()),
        }
    }

    // Called by a write task when its io command arrives
    fn add_write_tag(&self, tag: u16) {
        self.pending_write_tags.borrow_mut().push(tag);
    }

    // Coordinator (if any) whose batch still contains `tag`
    fn find_coordinator_with_tag(&self, tag: u16) -> Option<u32> {
        self.coordinators
            .iter()
            .find(|(_, c)| c.current_write_batch.contains(&tag))
            .map(|(id, _)| id as u32)
    }

    fn create_coordinator(&mut self) -> Option<u32> {
        // Transfer all pending write tags to the coordinator
        let write_tags = self
            .pending_write_tags
            .borrow_mut()
            .drain(..)
            .collect::<Vec<_>>();

        if write_tags.is_empty() {
            return None;
        }

        let coordinator = BatchCoordinator::new(write_tags);
        let context_id = self.coordinators.insert(coordinator) as u32;

        log::info!(
            "Queue {}: Created batch coordinator: context_id={}",
            self.queue_id,
            context_id
        );
        Some(context_id)
    }

    fn get_coordinator(&self, context_id: u32) -> Option<&BatchCoordinator> {
        self.coordinators.get(context_id as usize)
    }

    fn remove_coordinator(&mut self, context_id: u32) -> Option<BatchCoordinator> {
        if self.coordinators.contains(context_id as usize) {
            let coordinator = self.coordinators.remove(context_id as usize);
            log::info!(
                "Queue {}: Removed batch coordinator: context_id={}",
                self.queue_id,
                context_id
            );
            Some(coordinator)
        } else {
            None
        }
    }
}

async fn handle_task_batch_coordination(
    tag: u16,
    batch_state: &Rc<RefCell<QueueBatchState>>,
    q: &UblkQueue,
) -> Result<Option<u32>, UblkError> {
    let queue_id = batch_state.borrow().queue_id;

    // First check if current I/O operation is a write
    let iod = q.get_iod(tag);

    if !is_write_operation(iod) {
        // Not a write operation - proceed immediately without coordination
        return Ok(None);
    }

    // Register this write, then yield once so every write task woken in
    // the same scheduling round registers too; the first task to resume
    // groups all registered tags into one coordinator. Grouping is
    // best-effort: if the scheduler resumes a yielded task before all
    // woken write tasks have registered, the batch merely splits —
    // correctness is unaffected, only the batch size.
    batch_state.borrow().add_write_tag(tag);
    tokio::task::yield_now().await;

    let context_id = {
        let mut state = batch_state.borrow_mut();
        match state.find_coordinator_with_tag(tag) {
            Some(context_id) => context_id,
            None => state
                .create_coordinator()
                .expect("pending write tags include this task's tag"),
        }
    };

    log::debug!(
        "Queue {}: Write task {} participating in batch (context_id={}, op={})",
        queue_id,
        tag,
        context_id,
        iod.op_flags & 0xff
    );

    let batch_state_ref = batch_state.borrow();
    let coordinator = batch_state_ref.get_coordinator(context_id).unwrap();

    // Phase 2: Flush resync bits (only one task does actual flush)
    coordinator.flush_resync_bits(tag).await?;

    Ok(Some(context_id))
}

// OPTIMIZED: Function to handle batch completion - simplified!
async fn complete_task_batch_coordination(
    tag: u16,
    context_id: u32,
    batch_state: &Rc<RefCell<QueueBatchState>>,
) -> Result<(), UblkError> {
    let queue_id = batch_state.borrow().queue_id;

    // Mark task complete and check if batch is empty
    let is_batch_empty = {
        let mut batch_state_ref = batch_state.borrow_mut();
        let coordinator = batch_state_ref
            .coordinators
            .get_mut(context_id as usize)
            .unwrap();

        coordinator.mark_task_complete(tag).await?
    };

    if is_batch_empty {
        log::info!(
            "Queue {}: Write task {} completed batch, triggering cleanup",
            queue_id,
            tag
        );
        batch_state.borrow_mut().remove_coordinator(context_id);
    }

    Ok(())
}

#[inline]
fn get_io_cmd_result(q: &UblkQueue, tag: u16) -> i32 {
    let iod = q.get_iod(tag);
    let bytes = (iod.nr_sectors << 9) as i32;
    bytes
}

// Helper function to check if an I/O operation is a write
#[inline]
fn is_write_operation(iod: &libublk::sys::ublksrv_io_desc) -> bool {
    let op_type = iod.op_flags & 0xff; // Extract operation type
    op_type == libublk::sys::UBLK_IO_OP_WRITE
        || op_type == libublk::sys::UBLK_IO_OP_WRITE_SAME
        || op_type == libublk::sys::UBLK_IO_OP_WRITE_ZEROES
        || op_type == libublk::sys::UBLK_IO_OP_ZONE_APPEND
}

async fn simulate_io_with_delay(io_delay_us: u32) {
    let mut rng = rand::thread_rng();
    let delay_us = rng.gen_range(0..=io_delay_us);

    // Use the ring timer instead of a timer thread: the queue ring is
    // this thread's only wake source.
    if let Ok(sleep) = libublk::ops::sleep(std::time::Duration::from_micros(delay_us as u64)) {
        let _ = sleep.await;
    }
}

// Batch-aware I/O task function
async fn batch_io_task(
    q: &UblkQueue,
    tag: u16,
    buf: Option<&IoBuf<u8>>,
    batch_state: Rc<RefCell<QueueBatchState>>,
    zero_copy: bool,
    io_delay_us: u32,
) -> Result<(), UblkError> {
    let auto_buf_reg = libublk::sys::ublk_auto_buf_reg {
        index: tag,
        flags: libublk::sys::UBLK_AUTO_BUF_REG_FALLBACK as u8,
        ..Default::default()
    };

    let buf_desc = match buf {
        Some(io_buf) => {
            // Note: submit_io_prep_cmd will automatically register the buffer
            BufDesc::Slice(io_buf.as_slice())
        }
        None if zero_copy => BufDesc::AutoReg(auto_buf_reg),
        _ => BufDesc::Slice(&[]),
    };

    // Submit initial prep command
    q.submit_io_prep_cmd(tag, buf_desc.clone(), 0, buf).await?;

    loop {
        // Handle batch coordination (if active)
        let context_id_opt = handle_task_batch_coordination(tag, &batch_state, &q).await?;

        // Apply random delay to simulate real workload
        if io_delay_us > 0 {
            simulate_io_with_delay(io_delay_us).await;
        }

        // Perform I/O operation
        let res = get_io_cmd_result(&q, tag);

        // Complete batch coordination (if active) - before final I/O commit
        if let Some(context_id) = context_id_opt {
            complete_task_batch_coordination(tag, context_id, &batch_state).await?;
        }

        // Final I/O commit - happens after coordination is complete
        q.submit_io_commit_cmd(tag, buf_desc.clone(), res).await?;
    }
}

fn q_async_fn(qid: u16, dev: &Arc<UblkDev>, zero_copy: bool, io_delay_us: u32) {
    let batch_state_rc = Rc::new(RefCell::new(QueueBatchState::new(qid)));

    libublk::UblkRuntime::run_io_tasks(dev, qid, move |q, tag| {
        let batch_state = batch_state_rc.clone();
        async move {
            let buf = if zero_copy && q.support_auto_buf_zc() {
                None
            } else {
                Some(IoBuf::<u8>::new(q.dev().dev_info.max_io_buf_bytes as usize))
            };
            batch_io_task(&q, tag, buf.as_ref(), batch_state, zero_copy, io_delay_us).await
        }
    })
    .unwrap();
}

fn __batch_add(
    id: i32,
    nr_queues: u32,
    depth: u32,
    mut ctrl_flags: u64,
    buf_size: u32,
    flags: BatchFlags,
    io_delay_us: u32,
) {
    let oneshot = flags.intersects(BatchFlags::ONESHOT);
    let zero_copy = flags.intersects(BatchFlags::ZERO_COPY);

    // Add AUTO_BUF_REG flag if zero copy is enabled
    if zero_copy {
        ctrl_flags |= libublk::sys::UBLK_F_AUTO_BUF_REG as u64;
    }

    let ctrl = libublk::ctrl::UblkCtrlBuilder::default()
        .name("example_batch")
        .id(id)
        .depth(depth.try_into().unwrap())
        .nr_queues(nr_queues.try_into().unwrap())
        .io_buf_bytes(buf_size)
        .ctrl_flags(ctrl_flags)
        .dev_flags(UblkFlags::UBLK_DEV_F_ADD_DEV | UblkFlags::UBLK_DEV_F_SINGLE_CPU_AFFINITY)
        .build()
        .unwrap();

    let tgt_init = |dev: &mut UblkDev| {
        dev.set_default_params(250_u64 << 30);
        Ok(())
    };

    let wh = move |d_ctrl: &UblkCtrl| {
        d_ctrl.dump();
        if oneshot {
            d_ctrl.kill_dev().unwrap();
        }
    };

    // Always run in async mode for batch coordination
    let q_async_handler = move |qid, dev: &_| q_async_fn(qid, dev, zero_copy, io_delay_us);
    ctrl.run_target(tgt_init, q_async_handler, wh).unwrap();
}

fn batch_add(
    id: i32,
    nr_queues: u32,
    depth: u32,
    ctrl_flags: u64,
    buf_size: u32,
    flags: BatchFlags,
    io_delay_us: u32,
) {
    if flags.intersects(BatchFlags::FOREGROUND) {
        __batch_add(
            id,
            nr_queues,
            depth,
            ctrl_flags,
            buf_size,
            flags,
            io_delay_us,
        );
    } else {
        let daemonize = daemonize::Daemonize::new()
            .stdout(daemonize::Stdio::keep())
            .stderr(daemonize::Stdio::keep());

        match daemonize.start() {
            Ok(_) => __batch_add(
                id,
                nr_queues,
                depth,
                ctrl_flags,
                buf_size,
                flags,
                io_delay_us,
            ),
            _ => panic!(),
        }
    }
}

fn main() {
    env_logger::builder()
        .format_target(false)
        .format_timestamp(None)
        .init();

    let matches = Command::new("ublk-batch-example")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("add")
                .about("Add ublk device with batch coordination")
                .arg(
                    Arg::new("number")
                        .short('n')
                        .long("number")
                        .default_value("-1")
                        .allow_hyphen_values(true)
                        .help("device id, -1: auto-allocation")
                        .action(ArgAction::Set),
                )
                .arg(
                    Arg::new("queues")
                        .long("queues")
                        .short('q')
                        .default_value("1")
                        .help("nr_hw_queues")
                        .action(ArgAction::Set),
                )
                .arg(
                    Arg::new("depth")
                        .long("depth")
                        .short('d')
                        .default_value("128")
                        .help("queue depth: max in-flight io commands")
                        .action(ArgAction::Set),
                )
                .arg(
                    Arg::new("buf_size")
                        .long("buf_size")
                        .short('b')
                        .default_value("524288")
                        .help("io buffer size")
                        .action(ArgAction::Set),
                )
                .arg(
                    Arg::new("foreground")
                        .long("foreground")
                        .action(ArgAction::SetTrue)
                        .help("run in foreground mode"),
                )
                .arg(
                    Arg::new("oneshot")
                        .long("oneshot")
                        .action(ArgAction::SetTrue)
                        .help("create, dump and remove device automatically"),
                )
                .arg(
                    Arg::new("zero_copy")
                        .long("zero-copy")
                        .short('z')
                        .action(ArgAction::SetTrue)
                        .help("enable zero copy via UBLK_F_AUTO_BUF_REG"),
                )
                .arg(
                    Arg::new("io_delay")
                        .long("io-delay")
                        .default_value("0")
                        .help("maximum random IO delay in microseconds (0 = disabled)")
                        .action(ArgAction::Set),
                ),
        )
        .subcommand(
            Command::new("del").about("Delete ublk device").arg(
                Arg::new("number")
                    .short('n')
                    .long("number")
                    .required(true)
                    .help("device id")
                    .action(ArgAction::Set),
            ),
        )
        .subcommand(
            Command::new("list").about("List ublk device").arg(
                Arg::new("number")
                    .short('n')
                    .long("number")
                    .default_value("-1")
                    .help("device id")
                    .action(ArgAction::Set),
            ),
        )
        .get_matches();

    match matches.subcommand() {
        Some(("add", add_matches)) => {
            let id = add_matches
                .get_one::<String>("number")
                .unwrap()
                .parse::<i32>()
                .unwrap_or(-1);
            let nr_queues = add_matches
                .get_one::<String>("queues")
                .unwrap()
                .parse::<u32>()
                .unwrap_or(1);
            let depth = add_matches
                .get_one::<String>("depth")
                .unwrap()
                .parse::<u32>()
                .unwrap_or(128);
            let buf_size = add_matches
                .get_one::<String>("buf_size")
                .unwrap()
                .parse::<u32>()
                .unwrap_or(524288);
            let mut flags: BatchFlags = Default::default();

            if add_matches.get_flag("foreground") {
                flags |= BatchFlags::FOREGROUND;
            };
            if add_matches.get_flag("oneshot") {
                flags |= BatchFlags::ONESHOT;
            };
            if add_matches.get_flag("zero_copy") {
                flags |= BatchFlags::ZERO_COPY;
            };

            let io_delay_us = add_matches
                .get_one::<String>("io_delay")
                .unwrap()
                .parse::<u32>()
                .unwrap();

            batch_add(id, nr_queues, depth, 0, buf_size, flags, io_delay_us);
        }
        Some(("del", add_matches)) => {
            let id = add_matches
                .get_one::<String>("number")
                .unwrap()
                .parse::<i32>()
                .unwrap_or(-1);
            UblkCtrl::new_simple(id).unwrap().del_dev().unwrap();
        }
        Some(("list", add_matches)) => {
            let dev_id = add_matches
                .get_one::<String>("number")
                .unwrap()
                .parse::<i32>()
                .unwrap_or(-1);
            if dev_id >= 0 {
                UblkCtrl::new_simple(dev_id as i32).unwrap().dump();
            } else {
                UblkCtrl::for_each_dev_id(|dev_id| {
                    UblkCtrl::new_simple(dev_id as i32).unwrap().dump();
                });
            }
        }
        _ => {
            println!("unsupported command");
        }
    };
}
