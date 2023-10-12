//! Small & fast & single-threaded async executor, dedicated for ublk IO handling
//!
//! Most of the code are borrowed from simple-async-local-executor
//! `<https://github.com/eventhelix/simple-async-local-executor.git>`
//!
//! Also provides basic support for io_uring OP.
//!
use io_uring::cqueue;
use std::cell::UnsafeCell;
use std::{
    cell::RefCell,
    future::Future,
    pin::Pin,
    rc::Rc,
    task::{Context, Poll, RawWaker, RawWakerVTable, Waker},
};

/// User code creates one future with user_data used for submitting
/// uring OP, then future.await returns this uring OP's result.
pub struct UringOpFuture {
    pub user_data: u64,
}

impl Future for UringOpFuture {
    type Output = i32;
    fn poll(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<Self::Output> {
        let cqe = Executor::get_thread_local_cqe();
        if cqe != std::ptr::null() && unsafe { (*cqe).user_data() } == self.user_data {
            Executor::set_thread_local_cqe(std::ptr::null());
            Poll::Ready(unsafe { (*cqe).result() })
        } else {
            Poll::Pending
        }
    }
}

pub struct Task<'a> {
    future: Pin<Box<dyn Future<Output = ()> + 'a>>,
}

impl<'a> Task<'a> {
    #[inline(always)]
    pub fn new(future: Pin<Box<dyn Future<Output = ()> + 'a>>) -> Task {
        Task { future }
    }
    #[inline(always)]
    fn poll(&mut self, context: &mut Context) -> Poll<()> {
        self.future.as_mut().poll(context)
    }
}

#[inline(always)]
fn dummy_raw_waker() -> RawWaker {
    fn no_op(_: *const ()) {}
    fn clone(_: *const ()) -> RawWaker {
        dummy_raw_waker()
    }

    let vtable = &RawWakerVTable::new(clone, no_op, no_op, no_op);
    RawWaker::new(std::ptr::null::<()>(), vtable)
}

#[inline(always)]
fn dummy_waker() -> Waker {
    unsafe { Waker::from_raw(dummy_raw_waker()) }
}

// For simulating one '*const cqueue::Entry'stack variable, so just fine to
// let it unsafe
thread_local! {
    static MY_THREAD_LOCAL_CQE: UnsafeCell<*const cqueue::Entry> = UnsafeCell::new(std::ptr::null());
}

#[derive(Default)]
struct ExecutorInner<'a> {
    tasks: RefCell<Vec<Task<'a>>>,
}

/// ublk dedicated executor
pub struct Executor<'a> {
    inner: Rc<ExecutorInner<'a>>,
}

#[allow(dead_code)]
impl<'a> Executor<'a> {
    pub fn new(nr_tasks: u16) -> Executor<'a> {
        let mut tasks = Vec::<Task>::with_capacity(nr_tasks as usize);

        // initialize this vector for avoiding segment fault when assigning task
        for _i in 0..nr_tasks as usize {
            tasks.push(Task::new(Box::pin(async {})));
        }

        let inner = Rc::new(ExecutorInner {
            tasks: RefCell::new(tasks),
            ..Default::default()
        });

        Executor { inner }
    }

    /// Spawn one ublk io task, which is for handling one specific io command
    /// received from ublk driver, or one specific io task
    #[inline(always)]
    pub fn spawn(&self, tag: u16, future: impl Future<Output = ()> + 'a) {
        let mut tasks = self.inner.tasks.borrow_mut();
        let mut task = Task::new(Box::pin(future));

        match self.__tick(&mut task) {
            Poll::Ready(()) => {}
            Poll::Pending => {
                tasks[tag as usize] = task;
            }
        }
    }

    #[inline(always)]
    fn __tick(&self, task: &mut Task) -> Poll<()> {
        // Dummy waker and context (not used as we poll all tasks)
        let waker = dummy_waker();
        let mut context = Context::from_waker(&waker);

        task.poll(&mut context)
    }

    /// Tick one io task
    #[inline(always)]
    pub fn tick(&self, tag: u16) -> bool {
        let mut tasks = self.inner.tasks.borrow_mut();
        let task = &mut tasks[tag as usize];

        match self.__tick(task) {
            Poll::Ready(()) => true,
            Poll::Pending => false,
        }
    }

    /// Called when one cqe is completed
    #[inline]
    pub(crate) fn wake_with_uring_cqe(&self, tag: u16, cqe: &cqueue::Entry) -> bool {
        Executor::set_thread_local_cqe(cqe as *const cqueue::Entry);
        let done = self.tick(tag);
        Executor::set_thread_local_cqe(std::ptr::null());

        done
    }

    /// Store cqe const pointer to thread_local for avoiding unnecessary
    /// cqe copy.
    ///
    /// Called when one cqe is completed.
    #[inline]
    pub(crate) fn set_thread_local_cqe(cqe: *const cqueue::Entry) {
        MY_THREAD_LOCAL_CQE.with(|cell| unsafe {
            *cell.get() = cqe;
        });
    }

    /// Get current CQE const pointer from thread_local
    ///
    /// Called from Future's poll() method.
    #[inline]
    pub(crate) fn get_thread_local_cqe() -> *const cqueue::Entry {
        MY_THREAD_LOCAL_CQE.with(|cell| unsafe { *cell.get() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test Executor::spawn()
    #[test]
    fn test_executor_spawn() {
        async fn __test_spawn(a: &RefCell<i32>, val: i32) {
            *a.borrow_mut() = val;
        }
        let e = Executor::new(1);
        let a = Rc::new(RefCell::new(0));

        let av = a.clone();
        e.spawn(0, async move { __test_spawn(&av, 1).await });

        assert!(*a.borrow() == 1);
    }

    fn __test_uring_wakeup(e: &Executor, tag: u16, k: u64, res: i32) -> bool {
        let my_cqe = (k, res, 0_i32);
        let cqe = unsafe { std::mem::transmute::<(u64, i32, i32), cqueue::Entry>(my_cqe) };

        e.wake_with_uring_cqe(tag, &cqe)
    }
    /// Test if uring future works as expected
    #[test]
    fn test_executor_uring_nop() {
        async fn __test_uring_nop(k: u64, __res: i32) {
            let f = UringOpFuture { user_data: k };
            let res = f.await;

            assert!(res == __res);
        }

        let k: u64 = 0x0000000100000100;
        let res: i32 = 0x1000;
        let e = Executor::new(1);

        e.spawn(0, async { __test_uring_nop(k, res).await });
        assert!(!e.tick(0));

        //simulate one uring op completion
        assert!(__test_uring_wakeup(&e, 0, k, res));
    }

    /// Test if uring future join!() works as expected
    #[test]
    fn test_executor_uring_join() {
        async fn __test_uring_nop_join(k: u64, exp_res: i32, k2: u64, exp_res2: i32) {
            let f = UringOpFuture { user_data: k };
            let f2 = UringOpFuture { user_data: k2 };

            let (res, res2) = futures::join!(f, f2);
            assert!(res == exp_res && res2 == exp_res2);
        }

        let k: u64 = 0x0000000100000100;
        let res: i32 = 0x1000;
        let k2: u64 = 0x0000000100000200;
        let res2: i32 = 0x2000;
        let e = Executor::new(1);

        e.spawn(0, async { __test_uring_nop_join(k, res, k2, res2).await });
        assert!(!e.tick(0));

        //simulate one uring op completion
        assert!(!__test_uring_wakeup(&e, 0, k, res));
        //simulate one uring op completion
        assert!(__test_uring_wakeup(&e, 0, k2, res2));
    }
}
