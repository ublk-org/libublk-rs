extern crate bindgen;

#[derive(Debug)]
pub struct Fix753 {}
impl bindgen::callbacks::ParseCallbacks for Fix753 {
    fn item_name(&self, original_item_name: &str) -> Option<String> {
        Some(original_item_name.trim_start_matches("Fix753_").to_owned())
    }
}

fn add_serialize(outdir: &std::path::Path) -> anyhow::Result<i32> {
    use std::fs::File;
    use std::io::Write;

    let res = std::fs::read_to_string(outdir.join("ublk_cmd.rs"))?;
    let data = format!(
        "use serde::{{Serialize, Deserialize}};\n{}",
        regex::Regex::new(r"#\s*\[\s*derive\s*\((?P<d>[^)]+)\)\s*\]\s*pub\s*(?P<s>struct|enum)")?
            .replace_all(&res, "#[derive($d, Serialize, Deserialize)] pub $s")
    );
    let mut fd = File::create(outdir.join("ublk_cmd.rs"))?;
    fd.write_all(data.as_bytes())?;

    Ok(0)
}

fn main() {
    use std::env;
    use std::path::PathBuf;

    const INCLUDE: &str = r#"
#include <asm/ioctl.h>
#include <linux/errno.h>
#include "ublk_cmd.h"

#ifdef UBLK_F_CMD_IOCTL_ENCODE
#define MARK_FIX_753(req_name) const unsigned long int Fix753_##req_name = req_name;
#else
#define MARK_FIX_753(req_name)
#endif
MARK_FIX_753(UBLK_U_CMD_GET_QUEUE_AFFINITY);
MARK_FIX_753(UBLK_U_CMD_GET_DEV_INFO);
MARK_FIX_753(UBLK_U_CMD_ADD_DEV);
MARK_FIX_753(UBLK_U_CMD_DEL_DEV);
MARK_FIX_753(UBLK_U_CMD_START_DEV);
MARK_FIX_753(UBLK_U_CMD_STOP_DEV);
MARK_FIX_753(UBLK_U_CMD_SET_PARAMS);
MARK_FIX_753(UBLK_U_CMD_GET_PARAMS);
MARK_FIX_753(UBLK_U_CMD_START_USER_RECOVERY);
MARK_FIX_753(UBLK_U_CMD_END_USER_RECOVERY);
MARK_FIX_753(UBLK_U_CMD_GET_DEV_INFO2);
const int Fix753_UBLK_IO_RES_ABORT = UBLK_IO_RES_ABORT;
    "#;

    #[cfg(not(feature = "overwrite"))]
    let outdir = PathBuf::from(env::var("OUT_DIR").unwrap());

    #[cfg(feature = "overwrite")]
    let outdir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("src/sys");

    let mut builder = bindgen::Builder::default();
    builder = builder.header_contents("include-file.h", INCLUDE);

    builder
        .ctypes_prefix("libc")
        .prepend_enum_name(false)
        .derive_default(true)
        .generate_comments(true)
        .use_core()
        .allowlist_var("UBLKSRV_.*|UBLK_.*|UBLK_U_.*|Fix753_.*")
        .allowlist_type("ublksrv_.*|ublk_.*")
        .parse_callbacks(Box::new(Fix753 {}))
        .generate()
        .unwrap()
        .write_to_file(outdir.join("ublk_cmd.rs"))
        .unwrap();

    if let Err(error) = add_serialize(&outdir) {
        eprintln!("Error: {}", error)
    }
}
