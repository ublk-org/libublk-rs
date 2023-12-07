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
        if !cqe.is_null() && unsafe { (*cqe).user_data() } == self.user_data {
            Executor::set_thread_local_cqe(std::ptr::null());
            Poll::Ready(unsafe { (*cqe).result() })
        } else {
            Poll::Pending
        }
    }
}

/// MultiShot CQE
///
/// Totally un-tested, so far serves as sample reference implementation, and
/// target code can define its own MultiShot version too
pub struct UringOpFutureMultiShot {
    pub user_data: u64,
    done: u32,
    expected: u32,
}

impl Future for UringOpFutureMultiShot {
    type Output = u32;
    fn poll(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<Self::Output> {
        let cqe = Executor::get_thread_local_cqe();
        if !cqe.is_null() && unsafe { (*cqe).user_data() } == self.user_data {
            Executor::set_thread_local_cqe(std::ptr::null());

            let cqe_r = unsafe { &*cqe };
            if cqueue::more(cqe_r.flags()) {
                let me = self.as_ref();
                if me.done + cqe_r.result() as u32 == me.expected {
                    Poll::Ready(me.expected)
                } else {
                    self.get_mut().done += cqe_r.result() as u32;
                    Poll::Pending
                }
            } else {
                Poll::Ready(cqe_r.result() as u32 + self.as_ref().done)
            }
        } else {
            Poll::Pending
        }
    }
}

impl UringOpFutureMultiShot {
    pub fn new(user_data: u64, expected: u32) -> UringOpFutureMultiShot {
        UringOpFutureMultiShot {
            user_data,
            expected,
            done: 0,
        }
    }
}

pub struct Task<'a> {
    cnt: i16,
    tag: u16,
    future: Pin<Box<dyn Future<Output = ()> + 'a>>,
}

impl<'a> Task<'a> {
    #[inline(always)]
    pub fn new(tag: u16, future: Pin<Box<dyn Future<Output = ()> + 'a>>) -> Task {
        Task {
            tag,
            cnt: 0,
            future,
        }
    }
    #[inline(always)]
    fn poll(&mut self, context: &mut Context) -> Poll<()> {
        set_current_task_tag(self.tag);

        self.cnt += 1;
        let res = self.future.as_mut().poll(context);
        self.cnt -= 1;

        res
    }

    fn poll_without_ctx(&mut self) -> Poll<()> {
        let waker = dummy_waker(self as *mut Task);
        let mut context = Context::from_waker(&waker);

        self.poll(&mut context)
    }
}

#[inline(always)]
fn dummy_raw_waker(data: *const ()) -> RawWaker {
    fn clone(data: *const ()) -> RawWaker {
        dummy_raw_waker(data)
    }
    fn wake_op(data: *const ()) {
        let raw_task = data as *mut Task;

        unsafe {
            if (*raw_task).cnt == 0 {
                let _ = (*raw_task).poll_without_ctx();
            }
        };
    }
    fn drop_op(_: *const ()) {}

    let vtable = &RawWakerVTable::new(clone, wake_op, wake_op, drop_op);
    RawWaker::new(data, vtable)
}

/// Save current Task pointer into `data` of Waker, this way looks
/// tricky and fragile, but wakeup won't be done after the task
/// is completed, so this way is just fine.
///
/// But it uses raw pointer, borrow checker won't cover it any
/// more.
#[inline(always)]
fn dummy_waker(exec: *mut Task) -> Waker {
    let data = exec as *const ();
    unsafe { Waker::from_raw(dummy_raw_waker(data)) }
}

// For simulating one 'tag' stack variable, so just fine to
// let it unsafe
thread_local! {
    static MY_THREAD_LOCAL_TAG: UnsafeCell<u16> = UnsafeCell::new(0);
}

/// Get current io task's tag from thread_local
///
#[inline]
pub fn get_current_task_tag() -> u16 {
    MY_THREAD_LOCAL_TAG.with(|cell| unsafe { *cell.get() })
}

fn set_current_task_tag(tag: u16) {
    MY_THREAD_LOCAL_TAG.with(|cell| unsafe {
        *cell.get() = tag;
    });
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
        for i in 0..nr_tasks as usize {
            tasks.push(Task::new(i as u16, Box::pin(async {})));
        }

        let inner = Rc::new(ExecutorInner {
            tasks: RefCell::new(tasks),
        });

        Executor { inner }
    }

    /// Spawn one ublk io task, which is for handling one specific io command
    /// received from ublk driver, or one specific io task
    #[inline(always)]
    pub fn spawn(&self, tag: u16, future: impl Future<Output = ()> + 'a) {
        let mut tasks = self.inner.tasks.borrow_mut();
        let mut task = Task::new(tag, Box::pin(future));

        set_current_task_tag(tag);

        match self.__tick(&mut task) {
            Poll::Ready(()) => {}
            Poll::Pending => {
                tasks[tag as usize] = task;
            }
        }
    }

    #[inline(always)]
    fn __tick(&self, task: &mut Task) -> Poll<()> {
        task.poll_without_ctx()
    }

    #[inline]
    fn run_task(&self, task: &mut Task) -> bool {
        match self.__tick(task) {
            Poll::Ready(()) => true,
            Poll::Pending => false,
        }
    }

    /// Tick one io task
    #[inline(always)]
    pub fn tick(&self, tag: u16) -> bool {
        let mut tasks = self.inner.tasks.borrow_mut();
        let task = &mut tasks[tag as usize];

        self.run_task(task)
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
    use std::sync::{Arc, Mutex};

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

    /// Test Waker
    ///
    /// Also one simple prototype of spawn_blocking() for offloading
    /// task to another threads, and the code is borrowed from Programming
    /// Rust(2nd) crab book.
    #[test]
    fn test_executor_waker() {
        struct TestWakerFuture(Arc<Mutex<WakerFutureData>>);
        struct WakerFutureData {
            val: i32,
            waker: Option<Waker>,
        }

        impl Future for TestWakerFuture {
            type Output = i32;
            fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
                let mut guard = self.0.lock().unwrap();

                if guard.val == 2 {
                    Poll::Ready(5)
                } else {
                    guard.waker = Some(cx.waker().clone());
                    Poll::Pending
                }
            }
        }

        async fn __test_waker(inner: Arc<Mutex<WakerFutureData>>) {
            let wf = TestWakerFuture(inner);

            let data = wf.await;
            assert!(data == 5);
            println!("wake successfully");
        }

        let inner = Arc::new(Mutex::new(WakerFutureData {
            val: 0,
            waker: None,
        }));

        let e = Executor::new(1);
        let i = inner.clone();
        e.spawn(0, async move { __test_waker(i).await });

        {
            let guard = inner.lock().unwrap();
            assert!(guard.val == 0);
        }

        std::thread::spawn({
            let inner = inner.clone();

            move || {
                let maybe_waker = {
                    let mut guard = inner.lock().unwrap();
                    guard.val = 2;
                    guard.waker.take()
                };

                if let Some(waker) = maybe_waker {
                    waker.wake();
                }
            }
        })
        .join()
        .unwrap();
    }

    /// Test async mutex
    #[test]
    fn test_excutor_async_mutex() {
        use async_std::sync::Mutex;
        async fn __test_async_mutex(d: Rc<Mutex<i32>>) {
            let mut guard = d.lock().await;
            *guard += 10;
        }

        let data = Rc::new(Mutex::new(0));
        let e = Executor::new(3);

        let d0 = data.clone();
        let d1 = data.clone();
        let d3 = data.clone();
        e.spawn(0, async move { __test_async_mutex(d0).await });
        e.spawn(1, async move { __test_async_mutex(d1).await });
        e.spawn(2, async move {
            let guard = d3.lock().await;
            assert!(*guard == 20);
            println!("async mutex test is done");
        });
    }

    /// Test get_current_task_tag()
    #[test]
    fn test_get_current_task_tag() {
        let e = Executor::new(2);

        e.spawn(0, async move { assert!(get_current_task_tag() == 0) });
        e.spawn(1, async move { assert!(get_current_task_tag() == 1) });
    }
}
