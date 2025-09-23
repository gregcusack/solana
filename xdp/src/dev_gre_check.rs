use std::io;
use std::net::IpAddr;
use std::process::Command;

// Your DZ GRE device name from `ip link`
pub const DZ_DEV_NAME: &str = "doublezero0";

/// Very small helper: asks the kernel "which dev would you use for <dst>?"
/// Returns the interface name after the `dev` token from `ip -4 route get`.
pub fn ip_route_get_dev(dst: IpAddr) -> io::Result<Option<String>> {
    let dst_str = match dst {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(_) => return Ok(None), // DZ path here is IPv4; keep it simple.
    };

    // If `ip` is not in PATH on your dev box, change to "/sbin/ip".
    let out = Command::new("ip")
        .args(["-4", "route", "get", &dst_str])
        .output()?;

    if !out.status.success() {
        return Ok(None);
    }

    let first = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or("")
        .to_string();

    // Very dumb parse: find " dev " and take the next token.
    if let Some(idx) = first.find(" dev ") {
        let rest = &first[idx + " dev ".len()..];
        let dev = rest.split_whitespace().next().unwrap_or("").to_string();
        if dev.is_empty() { Ok(None) } else { Ok(Some(dev)) }
    } else {
        Ok(None)
    }
}