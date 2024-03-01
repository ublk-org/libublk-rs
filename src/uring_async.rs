use crate::io::UblkQueue;
use crate::UblkError;
use io_uring::{cqueue, opcode, squeue, types, IoUring};
use slab::Slab;
use std::cell::RefCell;
use std::os::fd::AsRawFd;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, Waker},
};

struct FutureData {
    waker: Option<Waker>,
    result: Option<i32>,
}

std::thread_local! {
    static MY_SLAB: RefCell<Slab<FutureData>> = RefCell::new(Slab::new());
}

/// User code creates one future with user_data used for submitting
/// uring OP, then future.await returns this uring OP's result.
pub struct UblkUringOpFuture {
    pub user_data: u64,
}

impl UblkUringOpFuture {
    pub fn new(tgt_io: u64) -> Self {
        MY_SLAB.with(|refcell| {
            let mut map = refcell.borrow_mut();

            let key = map.insert(FutureData {
                waker: None,
                result: None,
            });
            let user_data = ((key as u32) << 16) as u64 | tgt_io;
            log::debug!("uring: new future {:x}", user_data);
            UblkUringOpFuture { user_data }
        })
    }
}

impl Future for UblkUringOpFuture {
    type Output = i32;
    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        MY_SLAB.with(|refcell| {
            let mut map = refcell.borrow_mut();
            let key = ((self.user_data & !(1_u64 << 63)) >> 16) as usize;
            match map.get_mut(key) {
                None => {
                    log::debug!("uring: null slab {:x}", self.user_data);
                    Poll::Pending
                }
                Some(fd) => match fd.result {
                    Some(result) => {
                        map.remove(key);
                        log::debug!("uring: uring io ready userdata {:x} ready", self.user_data);
                        Poll::Ready(result)
                    }
                    None => {
                        fd.waker = Some(cx.waker().clone());
                        log::debug!("uring: uring io pending userdata {:x}", self.user_data);
                        Poll::Pending
                    }
                },
            }
        })
    }
}

//// Wakeup the pending future/task
#[inline]
pub fn ublk_wake_task(data: u64, cqe: &cqueue::Entry) {
    MY_SLAB.with(|refcell| {
        let mut map = refcell.borrow_mut();

        log::debug!(
            "ublk_wake_task: data {:x} user_data {:x} result {:x}",
            data,
            cqe.user_data(),
            cqe.result()
        );
        let data = ((data & !(1_u64 << 63)) >> 16) as usize;
        match map.get_mut(data) {
            Some(fd) => {
                fd.result = Some(cqe.result());
                if let Some(w) = &fd.waker {
                    w.clone().wake();
                }
            }
            None => {}
        }
    })
}

fn ublk_try_reap_cqe<S: squeue::EntryMarker>(
    ring: &mut IoUring<S>,
    nr_waits: usize,
) -> Option<cqueue::Entry> {
    match ring.submit_and_wait(nr_waits) {
        Err(_) => None,
        _ => ring.completion().next(),
    }
}

fn ublk_process_queue_io(
    exe: &smol::LocalExecutor,
    q: &UblkQueue,
    nr_waits: usize,
) -> Result<i32, UblkError> {
    let res = q.flush_and_wake_io_tasks(|data, cqe, _| ublk_wake_task(data, cqe), nr_waits);
    while exe.try_tick() {}

    res
}

/// Run one task in this local Executor until the task is finished
pub fn ublk_run_task<T, F>(
    exe: &smol::LocalExecutor,
    task: &smol::Task<T>,
    handler: F,
) -> Result<(), UblkError>
where
    F: Fn(&smol::LocalExecutor) -> Result<(), UblkError>,
{
    while !task.is_finished() {
        handler(exe)?;
    }
    Ok(())
}

/// Run one IO task in this local Executor until the task is finished
pub fn ublk_run_io_task<T>(
    exe: &smol::LocalExecutor,
    task: &smol::Task<T>,
    q: &UblkQueue,
    nr_waits: usize,
) -> Result<(), UblkError> {
    let handler = move |exe: &smol::LocalExecutor| -> Result<(), UblkError> {
        let _ = ublk_process_queue_io(exe, q, nr_waits)?;
        Ok(())
    };

    ublk_run_task(exe, task, handler)
}

/// Run one task in this local Executor until the task is finished
pub fn ublk_run_ctrl_task<T>(
    exe: &smol::LocalExecutor,
    q: &UblkQueue,
    task: &smol::Task<T>,
) -> Result<(), UblkError> {
    let mut pr: IoUring<squeue::Entry, cqueue::Entry> = IoUring::builder().build(4)?;
    let ctrl_fd = crate::ctrl::CTRL_URING.with(|refcell| refcell.borrow().as_raw_fd());
    let q_fd = q.as_raw_fd();
    let mut poll_q = true;
    let mut poll_ctrl = true;

    while exe.try_tick() {}
    while !task.is_finished() {
        log::debug!(
            "poll ring: submit and wait, ctrl_fd {} q_fd {}",
            ctrl_fd,
            q_fd
        );

        if poll_q {
            let q_e = opcode::PollAdd::new(types::Fd(q_fd), (libc::POLLIN | libc::POLLOUT) as _);
            let _ = unsafe { pr.submission().push(&q_e.build().user_data(0x01).into()) };
            poll_q = false;
        }
        if poll_ctrl {
            let ctrl_e =
                opcode::PollAdd::new(types::Fd(ctrl_fd), (libc::POLLIN | libc::POLLOUT) as _);
            let _ = unsafe { pr.submission().push(&ctrl_e.build().user_data(0x02).into()) };
            poll_ctrl = false;
        }

        pr.submit_and_wait(1)?;
        let cqes: Vec<cqueue::Entry> = pr.completion().map(Into::into).collect();
        for cqe in cqes {
            if cqe.user_data() == 0x1 {
                poll_q = true;
            }
            if cqe.user_data() == 0x2 {
                poll_ctrl = true;
            }
        }

        ublk_process_queue_io(exe, q, 0)?;
        let entry =
            crate::ctrl::CTRL_URING.with(|refcell| ublk_try_reap_cqe(&mut refcell.borrow_mut(), 0));
        if let Some(cqe) = entry {
            ublk_wake_task(cqe.user_data(), &cqe);
            while exe.try_tick() {}
        }
    }

    let nr_waits = 1 + if poll_q { 0 } else { 1 } + if poll_ctrl { 0 } else { 1 };
    let poll_e = opcode::PollRemove::new(0x05);
    let _ = unsafe { pr.submission().push(&poll_e.build().user_data(0x05).into()) };
    pr.submit_and_wait(nr_waits)?;

    Ok(())
}

/// Wait and handle incoming IO command
///
/// # Arguments:
///
/// * `q`: UblkQueue instance
/// * `exe`: Local async Executor
///
/// Called in queue context. won't return unless error is observed.
/// Wait and handle any incoming cqe until queue is down.
///
/// This should be the only foreground thing done in queue thread.
pub fn ublk_wait_and_handle_ios(exe: &smol::LocalExecutor, q: &UblkQueue) {
    loop {
        while exe.try_tick() {}
        match q.flush_and_wake_io_tasks(|data, cqe, _| ublk_wake_task(data, cqe), 1) {
            Err(_) => break,
            _ => {}
        }
    }
    q.unregister_io_bufs();
}
