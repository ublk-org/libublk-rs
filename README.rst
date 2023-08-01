===============
libublk of Rust
===============

Introduction
============

Rust library for building ublk[1] target device, which talks with linux
``ublk driver`` [#ublk_driver]_ for exposing standard linux block device,
meantime help target code to implement its own IO logic, which is totally
done in userspace.

So Rust's advantage can be taken for building userspace block device.

Linux kernel 6.0 starts to support ublk covered by config option CONFIG_BLK_DEV_UBLK.


Related documentations
======================

`ublk doc links <https://github.com/ming1/ubdsrv/blob/master/doc/external_links.rst>`_

`ublk introduction <https://github.com/ming1/ubdsrv/blob/master/doc/ublk_intro.pdf>`_


Building blocks
===============

UblkCtrl
--------

For controlling ublk device, and the control command is sent to
/dev/ublk-control, such as, add, remove, recover, list, set/get
parameters, ...

UblkDev
-------

For supporting ublk device IO path, and one thin layer of device abstract
in handling IO level. Ublk device supports multiple queue(MQ), and each
queue has its IO depth.

UblkQueue
---------

UblkQueue is the core part of the whole stack, which communicates with
ublk driver via ``io_uring cmd`` [#io_uirng_cmd]_. When any io command for
representing one block IO request originating from /dev/ublkbN comes, one
uring_cmd CQE is received in ublk userspace side. Basically the whole stack
is driven by io_uring CQE(uring_cmd or plain io_uring IO submitted from
target code). Here target means the specific ublk device implementation,
such as ublk-loop, ublk-zoned, ublk-nbd, ublk-qcow2, ...

UblkIOCtx
---------

When any io_uring CQE is received, libublk lets the target code handle it by
IO handling closure. This CQE may represents IO command from /dev/ublkbN,
or plain io_uring IO submitted from ublk target code, still in the same IO
handling closure.

If target won't use io_uring to handle IO, eventfd needs to be sent from the
real handler context to wakeup ublk queue/io_uring context for driving the
machinery. Eventfd gets minimized support with UBLK_DEV_F_COMP_BATCH, and
native & generic IO offloading will be added soon.

UblkIOCtx & UblkQueueCtx provide enough information for target code to handle
this CQE and implement target IO handling logic.

Quick Start
===========

Follows one totally working 2-queue ublk-null target which is built over
libublk 0.1.0, and each queue depth is 64, and each IO's max buffer size
is 512KB.

The closure `tgt_init` provides interface to set all kinds of parameters
for this target.

The closure `io_handler` provides interface to handle incoming CQE/
IO cmmand and implement target IO logic.

Closure interface is flexible since it can capture environment(outside of
closure) variables, and IO handling closure is defined as FnMut which allows
to write to captured variables.

.. code-block:: rust

  use libublk::ctrl::UblkCtrl;
  use libublk::io::{UblkDev, UblkIOCtx, UblkQueue};
  use std::sync::Arc;

  fn main() {
      let nr_queues = 2; //two queues
                         //io depth: 64, max buf size: 512KB
      let mut ctrl = UblkCtrl::new(-1, nr_queues, 64, 512 << 10, 0, true).unwrap();

      //target specific initialization by tgt_init closure
      let tgt_init = |dev: &mut UblkDev| {
          dev.set_default_params(250_u64 << 30);
          Ok(serde_json::json!({}))
      };
      let ublk_dev =
          std::sync::Arc::new(UblkDev::new("null".to_string(), tgt_init, &mut ctrl, 0).unwrap());
      let mut threads = Vec::new();

      for q in 0..nr_queues {
          let dev = Arc::clone(&ublk_dev);
          threads.push(std::thread::spawn(move || {
              let mut queue = UblkQueue::new(q as u16, &dev).unwrap();
              let ctx = queue.make_queue_ctx();

              //IO handling closure(FnMut), we are driven by io_uring
              //CQE, and this closure is called for every incoming CQE
              //(IO command or target io completion)
              let io_handler = move |io: &mut UblkIOCtx| {
                  let iod = ctx.get_iod(io.get_tag());
                  let bytes = unsafe { (*iod).nr_sectors << 9 } as i32;

                  io.complete_io(bytes);
                  Ok(0)
              };
              queue.wait_and_handle_io(io_handler);
          }));
      }
      ctrl.start_dev(&ublk_dev).unwrap();
      ctrl.dump();
      for qh in threads {
          qh.join().unwrap();
      }
      ctrl.stop_dev(&ublk_dev).unwrap();
  }

Target IO handling
==================

Target IO handling needs target code to implement the IO handling
closure.

If IO is super fast to complete, such as ramdisk, this request can be handled
directly in the closure, and call `io.complete_io(result)` to complete
the IO command originated from ublk driver. Another example is null
target(null.rs).

Most of times, IO is slow, so it needs to be handled asynchronously. The
preferred way is to submit target IO by io_uring in IO handling closure by
using the same IO slot(represented by `tag`). After this target IO is
completed, one io_uring CQE will be received, and the same IO closure is
called for handling this target IO, which can be checked by
`UblkIOCtx::is_tgt_io()` method. Finally if the coming target IO completion
means the original IO command is done, `io.complete_io(result)` is called
for moving on, otherwise the IO handling closure can continue to submit IO
or whatever for driving its IO logic.

Not all target IO logics can be done by io_uring, such as some handling
needs extra computation, which often require to offload IO in another
context. However, when target IO is done in remote offload context,
`io.complete_io(result)` has to be called in the queue/io_uring context.
One approach is to use eventfd to wakeup & notify ublk queue/io_uring.
Here, eventfd can be thought as one special target IO. Inside IO closure,
eventfd is queued by io_uring opcode::PollAdd. Once target IO handling is
done, write(eventfd) can wakeup/notify ublk queue & io_uring, then IO
closure can get chance to handle all completed IOs. Unfortunately, each
IO command(originated from ublk driver) can only use its own `UblkIOCtx`
to complete itself. But one eventfd is often reused for the whole queue, so
normally multiple IOs are completed when handling single eventfd CQE.
Here IO completion batch feature is provided, and target code can call
`io.add_to_comp_batch()` for each completed IO(tag, result) in io closure.
Then, all these added IOs will be completed automatically.

Examples
========

null
----

- add one null ublk device

  cargo run --example null -- add

- del one null ublk device

  cargo run --example null -- del [dev_id]


loop
----

- add one loop ublk device

  cargo run --example loop -- add ${backing_file_path}

- del one loop ublk device

  cargo run --example loop -- del [dev_id]


License
=======

This project is licensed under either of Apache License, Version 2.0 or
MIT license at your option.

References
==========

.. [#ublk_driver] https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/block/ublk_drv.c?h=v6.0
.. [#io_uirng_cmd] https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/io_uring/uring_cmd.c
