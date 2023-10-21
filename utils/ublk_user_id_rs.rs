fn main() {
    let s = std::env::args().nth(1).unwrap_or_else(|| "".to_string());

    if s == "" || &s[0..4] != "ublk" {
        println!("{}:{}", -1, -1);
        std::process::exit(-1);
    } else {
        let id_str = &s[5..];
        match id_str.parse::<i32>() {
            Ok(id) => match libublk::ctrl::UblkCtrl::new_simple(id, 0) {
                Ok(ctrl) => {
                    let dinfo = &ctrl.dev_info;
                    if (dinfo.flags & libublk::sys::UBLK_F_UNPRIVILEGED_DEV as u64) != 0 {
                        println!("{}:{}", dinfo.owner_uid, dinfo.owner_gid);
                    } else {
                        println!("{}:{}", -1, -1);
                    }
                }
                _ => {
                    println!("{}:{}", -1, -1);
                    std::process::exit(-1);
                }
            },
            _ => {
                println!("{}:{}", -1, -1);
                std::process::exit(-1);
            }
        }
    }
}
