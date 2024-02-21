use crate::io::UblkQueue;
use io_uring::cqueue;
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

/// Run one task in this local Executor until the task is finished
pub fn ublk_run_task<T>(
    q: &UblkQueue,
    exe: &smol::LocalExecutor,
    task: &smol::Task<T>,
    nr_waits: usize,
) {
    while exe.try_tick() {}
    while !task.is_finished() {
        match q.q_ring.borrow().submit_and_wait(nr_waits) {
            Err(_) => break,
            _ => {}
        }
        let cqe = {
            match q.q_ring.borrow_mut().completion().next() {
                None => {
                    exe.try_tick();
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
                Some(r) => r,
            }
        };
        let user_data = cqe.user_data();
        ublk_wake_task(user_data, &cqe);
        while exe.try_tick() {}
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
