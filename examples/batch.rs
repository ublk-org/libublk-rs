use async_lock::Mutex;
use bitflags::bitflags;
use clap::{Arg, ArgAction, Command};
use libublk::helpers::IoBuf;
use libublk::io::{with_task_io_ring, with_task_io_ring_mut, UblkDev, UblkQueue};
use libublk::uring_async::{ublk_reap_io_events_with_update_queue, ublk_wake_task};
use libublk::UblkUringData;
use libublk::{ctrl::UblkCtrl, BufDesc, UblkError, UblkFlags};
use slab::Slab;
use std::cell::{Cell, RefCell};
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::rc::Rc;

bitflags! {
    #[derive(Default)]
    struct BatchFlags: u32 {
        const FOREGROUND = 0b00000010;
        const ONESHOT = 0b00000100;
        const ZERO_COPY = 0b00001000;
        const USE_READABLE = 0b010000;
    }
}

// Thread-local storage for current batch context ID
thread_local! {
    static BATCH_CONTEXT: Cell<i32> = Cell::new(-1);
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

    // Called from reap_event when write I/O command is detected
    fn add_write_tag(&self, tag: u16) {
        self.pending_write_tags.borrow_mut().push(tag);
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

fn run_batch_coordination(
    exe: &smol::LocalExecutor<'_>,
    batch_state: &Rc<RefCell<QueueBatchState>>,
) {
    let queue_id = batch_state.borrow().queue_id;
    // Create coordinator if we have pending write operations
    if let Some(context_id) = batch_state.borrow_mut().create_coordinator() {
        BATCH_CONTEXT.with(|c| c.set(context_id as i32));

        log::info!(
            "Queue {}: Processing write batch (context_id={})",
            queue_id,
            context_id
        );
    }

    // Now the context batch coordinator is prepared, run io tasks
    while exe.try_tick() {}

    BATCH_CONTEXT.with(|c| c.set(-1));
}

async fn handle_task_batch_coordination(
    tag: u16,
    batch_state: &Rc<RefCell<QueueBatchState>>,
    q: &UblkQueue<'_>,
) -> Result<Option<u32>, UblkError> {
    let queue_id = batch_state.borrow().queue_id;

    // First check if current I/O operation is a write
    let iod = q.get_iod(tag);

    if !is_write_operation(iod) {
        // Not a write operation - proceed immediately without coordination
        return Ok(None);
    }

    // Get active coordinator context
    let coordinator_opt = BATCH_CONTEXT.with(|c| {
        let context_id = c.get();
        if context_id >= 0 {
            Some(context_id as u32)
        } else {
            None
        }
    });

    if let Some(context_id) = coordinator_opt {
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
    } else {
        // No active coordinator - proceed without coordination
        Ok(None)
    }
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

// Function to handle write tag collection from CQE
#[inline]
fn collect_write_tags_from_cqe(
    user_data: u64,
    q: &UblkQueue<'_>,
    batch_state: &Rc<RefCell<QueueBatchState>>,
) {
    // Check if this is an I/O command (not target operations) by checking Target bit
    if (user_data & libublk::UblkUringData::Target as u64) == 0 {
        let tag = libublk::io::UblkIOCtx::user_data_to_tag(user_data) as u16;
        let iod = q.get_iod(tag);

        // Collect write command tags for batch coordination
        if is_write_operation(iod) {
            batch_state.borrow().add_write_tag(tag);
        }
    }
}

// Batch-aware I/O task function
async fn batch_io_task(
    q: &UblkQueue<'_>,
    tag: u16,
    buf: Option<&IoBuf<u8>>,
    batch_state: Rc<RefCell<QueueBatchState>>,
    zero_copy: bool,
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

async fn handle_uring_events_default<T>(
    exe: &smol::LocalExecutor<'_>,
    q: &UblkQueue<'_>,
    tasks: Vec<smol::Task<T>>,
    batch_state: Rc<RefCell<QueueBatchState>>,
) -> Result<(), UblkError> {
    // Use the same pattern as wait_and_handle_io_events
    let poll_uring = || async {
        let timeout = Some(io_uring::types::Timespec::new().sec(20));
        libublk::uring_poll_io_fn::<io_uring::squeue::Entry>(q, timeout, 1)
    };

    let reap_event = |poll_timeout| {
        ublk_reap_io_events_with_update_queue(q, poll_timeout, None, |cqe| {
            let user_data = cqe.user_data();

            collect_write_tags_from_cqe(user_data, q, &batch_state);

            // Wake the task as usual
            ublk_wake_task(user_data, cqe);
        })
    };
    let run_ops = || {
        run_batch_coordination(exe, &batch_state);
    };
    let is_done = || tasks.iter().all(|task| task.is_finished());

    libublk::run_uring_tasks(poll_uring, reap_event, run_ops, is_done).await
}

async fn handle_uring_events_smol_readable<T>(
    exe: &smol::LocalExecutor<'_>,
    q: &UblkQueue<'_>,
    tasks: Vec<smol::Task<T>>,
    batch_state: Rc<RefCell<QueueBatchState>>,
) -> Result<(), UblkError> {
    use io_uring::{opcode, types};

    const TIMEOUT_USER_DATA: u64 = UblkUringData::Target as u64 | UblkUringData::NonAsync as u64;
    const TIMEOUT_SECS: u64 = 20;

    let uring_fd = with_task_io_ring(|ring| ring.as_raw_fd());
    let file = unsafe { File::from_raw_fd(uring_fd) };
    let async_uring = smol::Async::new(file).map_err(|_e| UblkError::OtherError(-libc::EINVAL))?;

    let ts = types::Timespec::new().sec(TIMEOUT_SECS);
    let timeout_e = opcode::Timeout::new(&ts)
        .flags(io_uring::types::TimeoutFlags::MULTISHOT)
        .build()
        .user_data(TIMEOUT_USER_DATA);
    q.ublk_submit_sqe_sync(timeout_e)?;

    let poll_uring = || async {
        with_task_io_ring_mut(|r| r.submit_and_wait(0))?;
        async_uring
            .readable()
            .await
            .map_err(|_| UblkError::OtherError(-libc::EIO))?;
        Ok(false)
    };

    let reap_event = |poll_timeout| {
        ublk_reap_io_events_with_update_queue(q, poll_timeout, Some(TIMEOUT_USER_DATA), |cqe| {
            let user_data = cqe.user_data();

            collect_write_tags_from_cqe(user_data, q, &batch_state);

            ublk_wake_task(user_data, cqe);
        })
    };

    let run_ops = || {
        run_batch_coordination(exe, &batch_state);
    };

    let is_done = || tasks.iter().all(|task| task.is_finished());

    libublk::run_uring_tasks(poll_uring, reap_event, run_ops, is_done).await?;

    let _ = async_uring.into_inner().map(|f| {
        use std::os::fd::IntoRawFd;
        f.into_raw_fd()
    });

    Ok(())
}

async fn handle_uring_events<T>(
    exe: &smol::LocalExecutor<'_>,
    q: &UblkQueue<'_>,
    tasks: Vec<smol::Task<T>>,
    batch_state: Rc<RefCell<QueueBatchState>>,
    smol_readable: bool,
) -> Result<(), UblkError> {
    if smol_readable {
        handle_uring_events_smol_readable(exe, q, tasks, batch_state).await
    } else {
        handle_uring_events_default(exe, q, tasks, batch_state).await
    }
}

fn q_async_fn(qid: u16, dev: &UblkDev, zero_copy: bool, readable: bool) {
    let q_rc = Rc::new(UblkQueue::new(qid as u16, &dev).unwrap());
    let exe_rc = Rc::new(smol::LocalExecutor::new());
    let batch_state_rc = Rc::new(RefCell::new(QueueBatchState::new(qid)));
    let queue_depth = dev.dev_info.queue_depth;

    let exe = exe_rc.clone();
    let mut f_vec = Vec::new();

    for tag in 0..queue_depth as u16 {
        let q = q_rc.clone();
        let batch_state = batch_state_rc.clone();

        f_vec.push(exe.spawn(async move {
            let buf = if zero_copy && q.support_auto_buf_zc() {
                None
            } else {
                Some(IoBuf::<u8>::new(q.dev.dev_info.max_io_buf_bytes as usize))
            };
            match batch_io_task(&q, tag, buf.as_ref(), batch_state, zero_copy).await {
                Err(UblkError::QueueIsDown) | Ok(_) => {}
                Err(e) => log::error!("batch_io_task failed for tag {}: {}", tag, e),
            }
        }));
    }

    let q = q_rc.clone();
    let exe2 = exe_rc.clone();
    let batch_state = batch_state_rc.clone();
    smol::block_on(exe_rc.run(async move {
        if let Err(e) = handle_uring_events(&exe2, &q, f_vec, batch_state, readable).await {
            log::error!("handle_uring_events failed: {}", e);
        }
    }));
}

fn __batch_add(
    id: i32,
    nr_queues: u32,
    depth: u32,
    mut ctrl_flags: u64,
    buf_size: u32,
    flags: BatchFlags,
) {
    let oneshot = flags.intersects(BatchFlags::ONESHOT);
    let zero_copy = flags.intersects(BatchFlags::ZERO_COPY);
    let use_readable = flags.intersects(BatchFlags::USE_READABLE);

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
    let q_async_handler = move |qid, dev: &_| q_async_fn(qid, dev, zero_copy, use_readable);
    ctrl.run_target(tgt_init, q_async_handler, wh).unwrap();
}

fn batch_add(
    id: i32,
    nr_queues: u32,
    depth: u32,
    ctrl_flags: u64,
    buf_size: u32,
    flags: BatchFlags,
) {
    if flags.intersects(BatchFlags::FOREGROUND) {
        __batch_add(id, nr_queues, depth, ctrl_flags, buf_size, flags);
    } else {
        let daemonize = daemonize::Daemonize::new()
            .stdout(daemonize::Stdio::keep())
            .stderr(daemonize::Stdio::keep());

        match daemonize.start() {
            Ok(_) => __batch_add(id, nr_queues, depth, ctrl_flags, buf_size, flags),
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
                    Arg::new("use_readable")
                        .long("use_readable")
                        .action(ArgAction::SetTrue)
                        .help("use readable polling"),
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
            if add_matches.get_flag("use_readable") {
                flags |= BatchFlags::USE_READABLE;
            };

            batch_add(id, nr_queues, depth, 0, buf_size, flags);
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
