===============
libublk of Rust
===============

Introduction
============

Rust library for help to build any ublk[1] target device, which talks with
linux ``ublk driver`` [#userspace]_ for exposing standard linux block device,
meantime help target code to implement its own IO logic, which is totally
done in userspace target code.

So Rust's advantage can be taken for building user ublk target.

Related documentations
======================

`ublk doc: <https://github.com/ming1/ubdsrv/blob/master/doc/external_links.rst>`

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
