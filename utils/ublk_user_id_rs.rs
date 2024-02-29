// SPDX-License-Identifier: MIT or Apache-2.0

fn main() {
    let s = std::env::args().nth(1).unwrap_or_else(|| "".to_string());

    if s.len() >= 6 && (&s[0..5] == "ublkb" || &s[0..5] == "ublkc") {
        match s[5..].parse::<i32>() {
            Ok(id) => match libublk::ctrl::UblkCtrl::new_simple(id) {
                Ok(ctrl) => {
                    let dinfo = ctrl.dev_info();
                    if (dinfo.flags & libublk::sys::UBLK_F_UNPRIVILEGED_DEV as u64) != 0 {
                        println!("{}:{}", dinfo.owner_uid, dinfo.owner_gid);
                    }
                    std::process::exit(0);
                }
                _ => {}
            },
            _ => {}
        }
    }
    std::process::exit(-1);
}
