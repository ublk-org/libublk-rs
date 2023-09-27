use std::{
    cell::RefCell,
    future::Future,
    pin::Pin,
    rc::Rc,
    task::{Context, Poll, RawWaker, RawWakerVTable, Waker},
};

// The following code is borrowed from
//
// `<https://github.com/eventhelix/simple-async-local-executor.git>`
//

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

#[derive(Default)]
struct ExecutorInner<'a> {
    tasks: RefCell<Vec<Task<'a>>>,
}

/// ublk dedicated executor
pub struct Executor<'a> {
    inner: Rc<ExecutorInner<'a>>,
}

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
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test Executor::spawn()
    #[test]
    fn test_spawn() {
        async fn __test_spawn(a: &RefCell<i32>, val: i32) {
            *a.borrow_mut() = val;
        }
        let e = Executor::new(1);
        let a = Rc::new(RefCell::new(0));

        let av = a.clone();
        e.spawn(0, async move { __test_spawn(&av, 1).await });

        assert!(*a.borrow() == 1);
    }
}
