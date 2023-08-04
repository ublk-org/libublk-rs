#![allow(non_snake_case)]

use anyhow::Result;
use libublk::sys::ublksrv_io_desc;
use libublk::sys::{
    BLK_ZONE_COND_CLOSED, BLK_ZONE_COND_EMPTY, BLK_ZONE_COND_EXP_OPEN, BLK_ZONE_COND_FULL,
    BLK_ZONE_COND_IMP_OPEN, BLK_ZONE_COND_OFFLINE, BLK_ZONE_COND_READONLY,
};
use libublk::sys::{BLK_ZONE_TYPE_CONVENTIONAL, BLK_ZONE_TYPE_SEQWRITE_REQ};
use libublk::sys::{
    UBLK_IO_OP_READ, UBLK_IO_OP_REPORT_ZONES, UBLK_IO_OP_WRITE, UBLK_IO_OP_ZONE_APPEND,
    UBLK_IO_OP_ZONE_CLOSE, UBLK_IO_OP_ZONE_FINISH, UBLK_IO_OP_ZONE_OPEN, UBLK_IO_OP_ZONE_RESET,
};
use libublk::{
    ctrl::UblkCtrl, io::UblkDev, io::UblkIOCtx, io::UblkQueue, io::UblkQueueCtx, UblkError,
};

use log::trace;
//use std::collections::BTreeMap;
use std::sync::RwLock;

#[derive(Debug, Default)]
struct Zone {
    r#type: libublk::sys::blk_zone_type,
    cond: libublk::sys::blk_zone_cond,
    start: u64,
    len: u32,
    capacity: u32,

    wp: u64,
    //map: BTreeMap<(u64, u32), u32>,
}

#[derive(Debug, Default)]
struct TgtData {
    nr_zones_imp_open: u32,
    nr_zones_exp_open: u32,
    nr_zones_closed: u32,
    imp_close_zone_no: u32,
    zones: Vec<Zone>,
}

#[derive(Debug, Default)]
struct ZonedTgt {
    size: u64,
    start: u64,

    zone_size: u64,
    _zone_capacity: u64,
    zone_nr_conv: u32,
    zone_max_open: u32,
    zone_max_active: u32,
    nr_zones: u32,

    pub fd: i32,

    data: RwLock<TgtData>,
}

const DEF_ZSIZE: u64 = 4 << 20;

impl ZonedTgt {
    fn new(size: u64) -> ZonedTgt {
        let buf_addr = libublk::ublk_alloc_buf(size as usize, 4096) as u64;
        let zone_size: u64 = if size >= DEF_ZSIZE { DEF_ZSIZE } else { size };
        let zone_cap = zone_size >> 9;
        let nr_zones = size / zone_size;
        let mut sector = 0;

        let mut zones = Vec::<Zone>::with_capacity(nr_zones as usize);
        unsafe {
            zones.set_len(nr_zones as usize);
        }
        for z in &mut zones {
            z.capacity = zone_cap as u32;
            z.len = (zone_size >> 9) as u32;
            z.r#type = BLK_ZONE_TYPE_SEQWRITE_REQ;
            z.start = sector;
            z.cond = BLK_ZONE_COND_EMPTY;

            z.wp = sector;
            //z.map = BTreeMap::new();
            sector += zone_size >> 9;
        }

        let tgt = ZonedTgt {
            size,
            start: buf_addr,
            zone_size,
            _zone_capacity: zone_size,
            zone_max_open: 0,
            zone_max_active: 0,
            nr_zones: nr_zones as u32,
            data: RwLock::new(TgtData {
                zones,
                ..Default::default()
            }),
            ..Default::default()
        };

        tgt
    }

    fn __close_zone(&self, data: &mut std::sync::RwLockWriteGuard<'_, TgtData>, zno: usize) -> i32 {
        match data.zones[zno].cond {
            BLK_ZONE_COND_CLOSED => return 0,
            BLK_ZONE_COND_IMP_OPEN => data.nr_zones_imp_open -= 1,
            BLK_ZONE_COND_EXP_OPEN => data.nr_zones_exp_open -= 1,
            //case BLK_ZONE_COND_EMPTY:
            //case BLK_ZONE_COND_FULL:
            _ => return -libc::EIO,
        }

        if data.zones[zno].wp == data.zones[zno].start {
            data.zones[zno].cond = BLK_ZONE_COND_EMPTY;
        } else {
            data.zones[zno].cond = BLK_ZONE_COND_CLOSED;
            data.nr_zones_closed += 1;
        }

        //data.zones[zno].map.clear();

        0
    }

    fn close_imp_open_zone(&self, data: &mut std::sync::RwLockWriteGuard<'_, TgtData>) {
        let mut zno = data.imp_close_zone_no;
        if zno >= self.nr_zones {
            zno = self.zone_nr_conv;
        }

        let total = self.zone_nr_conv + self.nr_zones;

        for _ in self.zone_nr_conv..total {
            let _zno = zno as usize;

            zno += 1;

            if zno >= self.nr_zones {
                zno = self.zone_nr_conv;
            }

            if data.zones[_zno].cond == BLK_ZONE_COND_IMP_OPEN {
                self.__close_zone(data, _zno);
                data.imp_close_zone_no = zno;
                return;
            }
        }
    }

    fn check_active(&self, data: &std::sync::RwLockWriteGuard<'_, TgtData>) -> i32 {
        if self.zone_max_active == 0 {
            return 0;
        }

        if data.nr_zones_exp_open + data.nr_zones_imp_open + data.nr_zones_closed
            < self.zone_max_active
        {
            return 0;
        }

        return -libc::EBUSY;
    }

    fn check_open(&self, data: &mut std::sync::RwLockWriteGuard<'_, TgtData>) -> i32 {
        if self.zone_max_open == 0 {
            return 0;
        }

        if data.nr_zones_exp_open + data.nr_zones_imp_open < self.zone_max_open {
            return 0;
        }

        if data.nr_zones_imp_open > 0 {
            if self.check_active(data) == 0 {
                self.close_imp_open_zone(data);
                return 0;
            }
        }

        return -libc::EBUSY;
    }

    fn check_zone_resources(
        &self,
        data: &mut std::sync::RwLockWriteGuard<'_, TgtData>,
        zno: usize,
    ) -> i32 {
        match data.zones[zno].cond {
            BLK_ZONE_COND_EMPTY => {
                let ret = self.check_active(data);
                if ret != 0 {
                    return ret;
                }
                return self.check_open(data);
            }
            BLK_ZONE_COND_CLOSED => return self.check_open(data),
            _ => return -libc::EIO,
        }
    }

    #[inline(always)]
    fn get_zone_no(&self, sector: u64) -> u32 {
        let zsects = (self.zone_size >> 9) as u32;

        (sector / (zsects as u64)) as u32
    }

    fn zone_reset(&self, sector: u64) -> i32 {
        let zno = self.get_zone_no(sector) as usize;
        let mut data = self.data.write().unwrap();

        if data.zones[zno].r#type == BLK_ZONE_TYPE_CONVENTIONAL {
            return -libc::EPIPE;
        }

        match data.zones[zno].cond {
            BLK_ZONE_COND_EMPTY => return 0,
            BLK_ZONE_COND_IMP_OPEN => data.nr_zones_imp_open -= 1,
            BLK_ZONE_COND_EXP_OPEN => data.nr_zones_exp_open -= 1,
            BLK_ZONE_COND_CLOSED => data.nr_zones_closed -= 1,
            BLK_ZONE_COND_FULL => {}
            _ => return -libc::EINVAL,
        }

        let start = data.zones[zno].start;
        data.zones[zno].cond = BLK_ZONE_COND_EMPTY;
        data.zones[zno].wp = start;
        //data.zones[zno].map.clear();

        self.discard_zone(&mut data, zno);

        0
    }

    fn zone_open(&self, sector: u64) -> i32 {
        let zno = self.get_zone_no(sector) as usize;
        let mut data = self.data.write().unwrap();

        if data.zones[zno].r#type == BLK_ZONE_TYPE_CONVENTIONAL {
            return -libc::EPIPE;
        }

        //fixme: add zone check
        match data.zones[zno].cond {
            BLK_ZONE_COND_EXP_OPEN => {}
            BLK_ZONE_COND_EMPTY => {
                let ret = self.check_zone_resources(&mut data, zno);
                if ret != 0 {
                    return ret;
                }
            }
            BLK_ZONE_COND_IMP_OPEN => data.nr_zones_imp_open -= 1,
            BLK_ZONE_COND_CLOSED => {
                let ret = self.check_zone_resources(&mut data, zno);
                if ret != 0 {
                    return ret;
                }
                data.nr_zones_closed -= 1;
            }
            _ => return -libc::EINVAL,
        }
        data.zones[zno].cond = BLK_ZONE_COND_EXP_OPEN;
        data.nr_zones_exp_open += 1;
        0
    }

    fn zone_close(&self, sector: u64) -> i32 {
        let zno = self.get_zone_no(sector) as usize;
        let mut data = self.data.write().unwrap();

        if data.zones[zno].r#type == BLK_ZONE_TYPE_CONVENTIONAL {
            return -libc::EPIPE;
        }

        self.__close_zone(&mut data, zno)
    }

    fn zone_finish(&self, sector: u64) -> i32 {
        let mut ret = 0;
        let zno = self.get_zone_no(sector) as usize;
        let mut data = self.data.write().unwrap();

        if data.zones[zno].r#type == BLK_ZONE_TYPE_CONVENTIONAL {
            return -libc::EPIPE;
        }

        match data.zones[zno].cond {
            // finish operation on full is not an error
            BLK_ZONE_COND_FULL => return ret,
            BLK_ZONE_COND_EMPTY => {
                ret = self.check_zone_resources(&mut data, zno);
                if ret != 0 {
                    return ret;
                }
            }
            BLK_ZONE_COND_IMP_OPEN => data.nr_zones_imp_open -= 1,
            BLK_ZONE_COND_EXP_OPEN => data.nr_zones_exp_open -= 1,
            BLK_ZONE_COND_CLOSED => {
                ret = self.check_zone_resources(&mut data, zno);
                if ret != 0 {
                    return ret;
                }
                data.nr_zones_closed -= 1;
            }
            _ => ret = libc::EIO,
        }

        data.zones[zno].cond = BLK_ZONE_COND_FULL;
        data.zones[zno].wp = data.zones[zno].start + data.zones[zno].len as u64;

        ret
    }

    fn discard_zone(&self, _data: &mut std::sync::RwLockWriteGuard<'_, TgtData>, zon: usize) {
        unsafe {
            let off = zon as u64 * self.zone_size;

            libc::madvise(
                (self.start + off) as *mut libc::c_void,
                0,
                self.zone_size as i32,
            );
        }
    }
}

impl Drop for ZonedTgt {
    fn drop(&mut self) {
        libublk::ublk_dealloc_buf(self.start as *mut u8, self.size as usize, 4096);
    }
}

fn handle_report_zones(
    tgt: &ZonedTgt,
    ctx: &UblkQueueCtx,
    io: &mut UblkIOCtx,
    iod: &ublksrv_io_desc,
) -> isize {
    let zsects = (tgt.zone_size >> 9) as u32;
    let zones = iod.nr_sectors; //union
    let zno = iod.start_sector / (zsects as u64);
    let blkz_sz = core::mem::size_of::<libublk::sys::blk_zone>() as u32;

    // USER_COPY is enabled, so we have to allocate buffer for report_zones
    let buf_addr = libublk::ublk_alloc_buf((blkz_sz * zones) as usize, 4096);
    let mut off = buf_addr as u64;

    trace!(
        "start_sec {} nr_sectors {} zones {}-{} zone_size {} buf {:x}/{:x}",
        iod.start_sector,
        iod.nr_sectors,
        zno,
        zones,
        tgt.zone_size,
        buf_addr as u64,
        off
    );
    for i in zno..(zno + zones as u64) {
        let mut zone = unsafe { &mut *(off as *mut libublk::sys::blk_zone) };
        let data = tgt.data.read().unwrap();
        let z = &data.zones[i as usize];

        zone.capacity = z.capacity as u64;
        zone.len = z.len as u64;
        zone.start = z.start;
        zone.wp = z.wp;
        zone.type_ = z.r#type as u8;
        zone.cond = z.cond as u8;

        off += blkz_sz as u64;
    }

    let dsize = off - buf_addr as u64;
    let ret = unsafe {
        let offset = UblkIOCtx::ublk_user_copy_pos(ctx.q_id, io.get_tag() as u16, 0);

        libc::pwrite(
            tgt.fd,
            buf_addr as *const libc::c_void,
            dsize.try_into().unwrap(),
            offset.try_into().unwrap(),
        )
    };
    libublk::ublk_dealloc_buf(buf_addr, (blkz_sz * zones) as usize, 4096);

    ret
}

fn handle_mgmt(tgt: &ZonedTgt, _ctx: &UblkQueueCtx, _io: &UblkIOCtx, iod: &ublksrv_io_desc) -> i32 {
    {
        let zno = tgt.get_zone_no(iod.start_sector);
        let data = tgt.data.read().unwrap();
        let z = &data.zones[zno as usize];

        if z.cond == BLK_ZONE_COND_READONLY || z.cond == BLK_ZONE_COND_OFFLINE {
            return -libc::EPIPE;
        }
    }

    let ret;
    match iod.op_flags & 0xff {
        UBLK_IO_OP_ZONE_RESET => ret = tgt.zone_reset(iod.start_sector),
        UBLK_IO_OP_ZONE_OPEN => ret = tgt.zone_open(iod.start_sector),
        UBLK_IO_OP_ZONE_CLOSE => ret = tgt.zone_close(iod.start_sector),
        UBLK_IO_OP_ZONE_FINISH => ret = tgt.zone_finish(iod.start_sector),
        _ => ret = -libc::EINVAL,
    }

    ret
}

fn handle_read(
    tgt: &ZonedTgt,
    ctx: &UblkQueueCtx,
    io: &mut UblkIOCtx,
    iod: &ublksrv_io_desc,
) -> i32 {
    let zno = tgt.get_zone_no(iod.start_sector) as usize;
    let data = tgt.data.read().unwrap();

    let cond = data.zones[zno].cond;
    if cond == BLK_ZONE_COND_OFFLINE {
        return -libc::EIO;
    }

    let bytes = (iod.nr_sectors << 9) as usize;
    let off = (iod.start_sector << 9) as u64;

    trace!(
        "read lba {:06x}-{:04}), zone: no {:4} cond {:4} start/wp {:06x}/{:06x}",
        iod.start_sector,
        iod.nr_sectors,
        zno,
        data.zones[zno].cond,
        data.zones[zno].start,
        data.zones[zno].wp,
    );
    unsafe {
        let offset = UblkIOCtx::ublk_user_copy_pos(ctx.q_id, io.get_tag() as u16, 0);
        let mut addr = (tgt.start + off) as *mut libc::c_void;

        // make sure data is zeroed for reset zone
        if cond == BLK_ZONE_COND_EMPTY {
            addr = libublk::ublk_alloc_buf(bytes as usize, 4096) as *mut libc::c_void;

            libc::memset(addr, 0, bytes);
        }

        //write data to /dev/ublkcN from our ram directly
        let ret = libc::pwrite(tgt.fd as i32, addr, bytes, offset.try_into().unwrap()) as i32;

        if cond == BLK_ZONE_COND_EMPTY {
            libublk::ublk_dealloc_buf(addr as *mut u8, bytes as usize, 4096);
        }

        ret
    }
}

fn handle_plain_write(
    tgt: &ZonedTgt,
    ctx: &UblkQueueCtx,
    io: &mut UblkIOCtx,
    start_sector: u64,
    nr_sectors: u32,
) -> i32 {
    let off = (start_sector << 9) as u64;
    let bytes = (nr_sectors << 9) as usize;
    let offset = UblkIOCtx::ublk_user_copy_pos(ctx.q_id, io.get_tag() as u16, 0);

    unsafe {
        //read data from /dev/ublkcN to our ram directly
        libc::pread(
            tgt.fd as i32,
            (tgt.start + off) as *mut libc::c_void,
            bytes,
            offset.try_into().unwrap(),
        ) as i32
    }
}

fn handle_write(
    tgt: &ZonedTgt,
    ctx: &UblkQueueCtx,
    io: &mut UblkIOCtx,
    iod: &libublk::sys::ublksrv_io_desc,
    append: bool,
) -> (u64, i32) {
    let zno = tgt.get_zone_no(iod.start_sector) as usize;
    let mut data = tgt.data.write().unwrap();
    let mut ret = -libc::EIO;

    if data.zones[zno].r#type == BLK_ZONE_TYPE_CONVENTIONAL {
        if append {
            return (u64::MAX, ret);
        }

        return (
            u64::MAX as u64,
            handle_plain_write(tgt, ctx, io, iod.start_sector, iod.nr_sectors),
        );
    }

    let cond = data.zones[zno].cond;
    if cond == BLK_ZONE_COND_FULL || cond == BLK_ZONE_COND_READONLY || cond == BLK_ZONE_COND_OFFLINE
    {
        return (u64::MAX, ret);
    }

    let sector = data.zones[zno].wp;
    if append == false && iod.start_sector != sector {
        return (u64::MAX, ret);
    }

    let zone_end = data.zones[zno].start + data.zones[zno].capacity as u64;
    if data.zones[zno].wp + iod.nr_sectors as u64 > zone_end {
        return (u64::MAX, ret);
    }

    if cond == BLK_ZONE_COND_CLOSED || cond == BLK_ZONE_COND_EMPTY {
        ret = tgt.check_zone_resources(&mut data, zno);
        if ret != 0 {
            return (u64::MAX, ret);
        }

        if cond == BLK_ZONE_COND_CLOSED {
            data.nr_zones_closed -= 1;
            data.nr_zones_imp_open += 1;
        } else if cond == BLK_ZONE_COND_EMPTY {
            data.nr_zones_imp_open += 1;
        }

        if cond != BLK_ZONE_COND_EXP_OPEN {
            data.zones[zno].cond = BLK_ZONE_COND_IMP_OPEN;
        }
    }

    //let offset = (sector - data.zones[zno].start) as u32;
    //data.zones[zno]
    //    .map
    //    .insert((iod.start_sector, iod.nr_sectors), offset);

    ret = handle_plain_write(tgt, ctx, io, sector, iod.nr_sectors);
    data.zones[zno].wp += iod.nr_sectors as u64;

    if data.zones[zno].wp == zone_end {
        let cond = data.zones[zno].cond;

        if cond == BLK_ZONE_COND_EXP_OPEN {
            data.nr_zones_exp_open -= 1;
        } else if cond == BLK_ZONE_COND_IMP_OPEN {
            data.nr_zones_imp_open -= 1;
        }
        data.zones[zno].cond = BLK_ZONE_COND_FULL;
    }
    trace!(
        "write done(append {:1} lba {:06x}-{:04}), zone: no {:4} cond {:4} start/wp {:06x}/{:06x} end {:06x} sector {:06x} sects {:03x}",
        append,
        iod.start_sector,
        iod.nr_sectors,
        zno,
        data.zones[zno].cond,
        data.zones[zno].start,
        data.zones[zno].wp,
        zone_end, sector, ret >> 9,
    );

    (sector, ret)
}

fn zoned_handle_io(
    tgt: &ZonedTgt,
    ctx: &UblkQueueCtx,
    io: &mut UblkIOCtx,
    iod: &libublk::sys::ublksrv_io_desc,
) -> Result<i32, UblkError> {
    let bytes;
    let op = iod.op_flags & 0xff;

    trace!(
        "=>tag {:3} ublk op {:2}, lba {:6x}-{:3} zno {}",
        io.get_tag(),
        op,
        iod.start_sector,
        iod.nr_sectors,
        tgt.get_zone_no(iod.start_sector)
    );

    io.set_buf_addr(0);
    match op {
        UBLK_IO_OP_READ => {
            bytes = handle_read(tgt, ctx, io, iod);
        }
        UBLK_IO_OP_WRITE => {
            (_, bytes) = handle_write(tgt, ctx, io, iod, false);
        }
        UBLK_IO_OP_ZONE_APPEND => {
            let sector;
            (sector, bytes) = handle_write(tgt, ctx, io, iod, true);
            if bytes > 0 {
                io.set_buf_addr(sector);
            }
        }
        UBLK_IO_OP_REPORT_ZONES => {
            bytes = handle_report_zones(tgt, ctx, io, iod) as i32;
        }
        UBLK_IO_OP_ZONE_RESET
        | UBLK_IO_OP_ZONE_OPEN
        | UBLK_IO_OP_ZONE_CLOSE
        | UBLK_IO_OP_ZONE_FINISH => bytes = handle_mgmt(tgt, ctx, io, iod),
        _ => return Err(UblkError::OtherError(-libc::EINVAL)),
    }

    trace!(
        "<=tag {:3} ublk op {:2}, lba {:6x}-{:3} zno {} done {:4}",
        io.get_tag(),
        op,
        iod.start_sector,
        iod.nr_sectors,
        tgt.get_zone_no(iod.start_sector),
        bytes >> 9
    );
    io.complete_io(bytes);
    Ok(0)
}

fn zoned_add_dev(dev_id: i32, size: u64, for_add: bool) {
    let ctrl_flags = libublk::sys::UBLK_F_USER_COPY
        | libublk::sys::UBLK_F_ZONED
        | libublk::sys::UBLK_F_USER_RECOVERY;
    let depth = 128;
    let nr_queues = 1;
    let mut zoned_tgt = ZonedTgt::new(size);

    let max_open = zoned_tgt.zone_max_open;
    let max_active = zoned_tgt.zone_max_active;
    let zone_size = zoned_tgt.zone_size;

    let mut ctrl = UblkCtrl::new(
        dev_id,
        nr_queues,
        depth,
        512 << 10,
        ctrl_flags as u64,
        for_add,
    )
    .unwrap();
    let ublk_dev = UblkDev::new(
        "zoned".to_string(),
        |dev: &mut UblkDev| {
            dev.set_default_params(size);
            dev.tgt.params.types |= libublk::sys::UBLK_PARAM_TYPE_ZONED;
            dev.tgt.params.basic.chunk_sectors = (zone_size >> 9) as u32;
            dev.tgt.params.zoned = libublk::sys::ublk_param_zoned {
                max_open_zones: max_open,
                max_active_zones: max_active,
                max_zone_append_sectors: (zone_size >> 9) as u32,
                ..Default::default()
            };
            Ok(serde_json::json!({}))
        },
        &mut ctrl,
        0,
    )
    .unwrap();

    zoned_tgt.fd = ublk_dev.tgt.fds[0];

    let mut queue = UblkQueue::new(0, &ublk_dev).unwrap();
    let ctx = queue.make_queue_ctx();
    let qc = move |i: &mut UblkIOCtx| {
        let _iod = ctx.get_iod(i.get_tag());
        let iod = unsafe { &*_iod };

        zoned_handle_io(&zoned_tgt, &ctx, i, iod)
    };
    ctrl.configure_queue(&ublk_dev, 0, unsafe { libc::gettid() });

    ctrl.start_dev_in_queue(&ublk_dev, &mut queue, &qc).unwrap();
    ctrl.dump();
    queue.wait_and_handle_io(&qc);
    ctrl.stop_dev(&ublk_dev).unwrap();
}

fn zoned_get_device_size(ctrl: &mut UblkCtrl) -> u64 {
    ctrl.reload_json().unwrap();

    let tgt_val = &ctrl.json["target"];
    let tgt: Result<libublk::io::UblkTgt, _> = serde_json::from_value(tgt_val.clone());
    if let Ok(p) = tgt {
        p.dev_size
    } else {
        0
    }
}

fn test_add(recover: usize) {
    let dev_id: i32 = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "-1".to_string())
        .parse::<i32>()
        .unwrap();
    let s = std::env::args().nth(3).unwrap_or_else(|| "32".to_string());
    let mb = s.parse::<u64>().unwrap();

    //println!("dev_id is {}, recover {}", dev_id, _r);

    let _pid = unsafe { libc::fork() };
    if _pid == 0 {
        let mut size = (mb << 20) as u64;

        if recover > 0 {
            assert!(dev_id >= 0);
            let mut ctrl = UblkCtrl::new(dev_id, 0, 0, 0, 0, false).unwrap();
            size = zoned_get_device_size(&mut ctrl);

            ctrl.start_user_recover().unwrap();
        }
        let buf = libublk::ublk_alloc_buf(size as usize, 4096);

        zoned_add_dev(dev_id, size, recover == 0);

        libublk::ublk_dealloc_buf(buf, size as usize, 4096);
    }
}

fn test_del() {
    let s = std::env::args().nth(2).unwrap_or_else(|| "0".to_string());
    let dev_id = s.parse::<i32>().unwrap();
    let mut ctrl = UblkCtrl::new(dev_id as i32, 0, 0, 0, 0, false).unwrap();

    ctrl.del().unwrap();
}

fn main() {
    if let Some(cmd) = std::env::args().nth(1) {
        match cmd.as_str() {
            "add" => test_add(0),
            "recover" => test_add(1),
            "del" => test_del(),
            _ => todo!(),
        }
    }
}
