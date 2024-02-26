use crate::io::UblkQueue;
use crate::UblkError;
use io_uring::{cqueue, squeue, IoUring};
use slab::Slab;
use std::cell::RefCell;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, Waker},
};

struct FutureData {
    pub waker: Option<Waker>,
    pub result: Option<i32>,
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
            log::debug!("rublk: new future {:x}", user_data);
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
                    log::debug!("rublk: null slab {:x}", self.user_data);
                    Poll::Pending
                }
                Some(fd) => match fd.result {
                    Some(result) => {
                        map.remove(key);
                        log::debug!("rublk: uring io ready userdata {:x} ready", self.user_data);
                        Poll::Ready(result)
                    }
                    None => {
                        fd.waker = Some(cx.waker().clone());
                        log::debug!("rublk: uring io pending userdata {:x}", self.user_data);
                        Poll::Pending
                    }
                },
            }
        })
    }
}

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
    q: &UblkQueue,
    exe: &smol::LocalExecutor,
    nr_waits: usize,
) -> Result<i32, UblkError> {
    let res = q.flush_and_wake_io_tasks(|data, cqe, _| ublk_wake_task(data, cqe), nr_waits);

    if res.is_ok() {
        while exe.try_tick() {}
    }

    res
}

/// Run one task in this local Executor until the task is finished
pub fn ublk_run_task<T>(
    q: &UblkQueue,
    exe: &smol::LocalExecutor,
    task: &smol::Task<T>,
    nr_waits: usize,
) {
    while !task.is_finished() {
        let res = ublk_process_queue_io(q, exe, nr_waits);

        let wait = match res {
            Ok(nr) if nr > 0 => false,
            _ => false,
        };
        if wait {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}

/// Run one task in this local Executor until the task is finished
pub fn ublk_run_ctrl_task<T>(
    ctrl_exe: &smol::LocalExecutor,
    q: &UblkQueue,
    q_exe: &smol::LocalExecutor,
    task: &smol::Task<T>,
) {
    ctrl_exe.try_tick();
    while !task.is_finished() {
        let mut q_idle = false;
        let mut ctrl_idle = false;

        if ublk_process_queue_io(q, q_exe, 0).unwrap() == 0 {
            q_idle = true;
        }

        let entry =
            crate::ctrl::CTRL_URING.with(|refcell| ublk_try_reap_cqe(&mut refcell.borrow_mut(), 0));
        if let Some(cqe) = entry {
            ublk_wake_task(cqe.user_data(), &cqe);
            while ctrl_exe.try_tick() {}
        } else {
            ctrl_idle = true;
        }

        // Fixme: switch to poll on the two FDs
        if q_idle && ctrl_idle {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
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
pub fn ublk_wait_and_handle_ios(q: &UblkQueue, exe: &smol::LocalExecutor) {
    loop {
        while exe.try_tick() {}
        match q.flush_and_wake_io_tasks(|data, cqe, _| ublk_wake_task(data, cqe), 1) {
            Err(_) => break,
            _ => {}
        }
    }
    q.unregister_io_bufs();
}
