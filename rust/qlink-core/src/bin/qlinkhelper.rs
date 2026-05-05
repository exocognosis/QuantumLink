//! `qlinkhelper` — privileged helper that opens a userspace
//! tun/utun device and passes the file descriptor back to an
//! unprivileged client over a Unix domain socket using `SCM_RIGHTS`.
//!
//! ## Why this exists
//!
//! Opening a utun (macOS) or `/dev/net/tun` (Linux) device requires
//! root privileges (or `CAP_NET_ADMIN` on Linux). The QuantumLink
//! GUI app deliberately runs unprivileged for security, but it
//! needs an FD to read/write IP packets. This helper bridges the
//! gap: it runs as root, performs the privileged open, and then
//! ships the resulting FD to the unprivileged app over a Unix
//! socket. After that handover, the app can do all packet I/O
//! without further privilege.
//!
//! ## macOS install path
//!
//! On macOS the helper is installed as a LaunchDaemon at
//! `/Library/LaunchDaemons/com.quantumlink.macos.Helper.plist`.
//! For pre-Apple-Dev local builds we install it via an
//! `osascript "do shell script ... with administrator privileges"`
//! one-time prompt, NOT `SMAppService` (which requires a
//! Developer-ID-signed bundle to register).
//!
//! ## Linux usage
//!
//! On Linux the same binary serves as the helper for desktop
//! clients (where the QuantumLink GUI runs as the user) and as
//! the privileged-open path inside `qlinkd` (the server-side
//! daemon, which uses `AmbientCapabilities=CAP_NET_ADMIN` in its
//! systemd unit and rarely needs the helper indirection).
//!
//! ## Wire protocol
//!
//! Each client request is a single line of JSON:
//!
//! ```json
//! { "command": "open_tun", "name": "utun7" }
//! ```
//!
//! The helper opens the device, then sends a single byte over the
//! Unix stream socket with `sendmsg(SCM_RIGHTS, [fd])` ancillary
//! data carrying the FD. The single-byte payload is the status:
//! `0x00` = OK (FD attached); `0x01` = error (no FD attached;
//! followed by a JSON line on the stream describing the error).

use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};

use qlink_core::utun::UtunDevice;

const DEFAULT_SOCKET_PATH: &str = "/var/run/quantumlink-helper.sock";

fn main() -> std::io::Result<()> {
    // Logging goes to stderr; the LaunchDaemon plist routes that
    // to /var/log/quantumlink-helper.log.
    eprintln!("qlinkhelper starting");

    let socket_path = std::env::var("QLINK_HELPER_SOCKET")
        .unwrap_or_else(|_| DEFAULT_SOCKET_PATH.to_string());

    // Stale socket from a prior run blocks bind(); remove it. We
    // accept the race of two helpers starting at once because
    // LaunchDaemon's KeepAlive=true ensures we're the only instance.
    let _ = std::fs::remove_file(&socket_path);

    let listener = UnixListener::bind(&socket_path)?;
    // Restrict socket access to the user's group. macOS apps run
    // as the console user; the LaunchDaemon installer chgrps the
    // socket so only that user can connect.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o660))?;

    eprintln!("qlinkhelper listening on {}", socket_path);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(e) = handle_client(stream) {
                    eprintln!("client error: {}", e);
                }
            }
            Err(e) => {
                eprintln!("accept error: {}", e);
            }
        }
    }
    Ok(())
}

fn handle_client(mut stream: UnixStream) -> std::io::Result<()> {
    // Read one line of JSON request.
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf)?;
    if n == 0 {
        return Ok(());
    }
    let line = std::str::from_utf8(&buf[..n])
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
        .trim()
        .to_string();

    eprintln!("request: {}", line);

    // Tiny ad-hoc parser — we only support one command, no point
    // pulling in serde_json here when one match is sufficient.
    if line.contains("\"command\":\"open_tun\"") || line.contains("\"command\": \"open_tun\"") {
        match open_tun() {
            Ok(device) => send_fd_ok(&mut stream, &device),
            Err(e) => send_error(&mut stream, &e.to_string()),
        }
    } else {
        send_error(&mut stream, "unknown command")
    }
}

#[cfg(target_os = "macos")]
fn open_tun() -> std::io::Result<UtunDevice> {
    use qlink_core::utun::create_utun;
    // unit=0 → kernel picks first free utun number.
    create_utun(0).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
}

#[cfg(target_os = "linux")]
fn open_tun() -> std::io::Result<UtunDevice> {
    use qlink_core::utun::create_tun;
    // empty name → kernel picks (e.g. tun0).
    create_tun("").map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn open_tun() -> std::io::Result<UtunDevice> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "qlinkhelper supports only macOS and Linux",
    ))
}

/// Write a status byte 0x00 plus a JSON descriptor to the stream,
/// AND attach the device FD as SCM_RIGHTS ancillary data.
fn send_fd_ok(stream: &mut UnixStream, device: &UtunDevice) -> std::io::Result<()> {
    let header = format!(
        "{{\"status\":\"ok\",\"name\":\"{}\"}}\n",
        device.name()
    );
    send_with_fd(stream, header.as_bytes(), device.as_raw_fd())
}

fn send_error(stream: &mut UnixStream, msg: &str) -> std::io::Result<()> {
    let payload = format!("{{\"status\":\"error\",\"message\":{:?}}}\n", msg);
    stream.write_all(payload.as_bytes())?;
    Ok(())
}

/// Send `data` plus one file descriptor over a Unix stream socket.
/// This is the SCM_RIGHTS ancillary-data dance — a stable kernel
/// API on every Unix but verbose to do in pure libc. We hand-roll
/// the cmsghdr because we don't want to pull in `nix` for one
/// system call.
fn send_with_fd(stream: &mut UnixStream, data: &[u8], fd: i32) -> std::io::Result<()> {
    use libc::{
        c_void, iovec, msghdr, sendmsg, CMSG_DATA, CMSG_FIRSTHDR, CMSG_LEN,
        CMSG_SPACE, SCM_RIGHTS, SOL_SOCKET,
    };
    use std::mem::{size_of, zeroed};

    // The cmsghdr buffer needs to be properly aligned for
    // CMSG_FIRSTHDR; CMSG_SPACE(size_of::<i32>()) gives the right
    // size including any padding. We use a fixed-size buffer here
    // because we know we're sending exactly one FD.
    const FD_SIZE: usize = size_of::<i32>();
    let cmsg_space = unsafe { CMSG_SPACE(FD_SIZE as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let mut iov = iovec {
        iov_base: data.as_ptr() as *mut c_void,
        iov_len: data.len(),
    };

    let mut msg: msghdr = unsafe { zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut c_void;
    msg.msg_controllen = cmsg_space as _;

    // Fill in the cmsghdr describing the FD payload.
    unsafe {
        let cmsg = CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "CMSG_FIRSTHDR returned null",
            ));
        }
        (*cmsg).cmsg_len = CMSG_LEN(FD_SIZE as u32) as _;
        (*cmsg).cmsg_level = SOL_SOCKET;
        (*cmsg).cmsg_type = SCM_RIGHTS;
        let data_ptr = CMSG_DATA(cmsg) as *mut i32;
        std::ptr::write_unaligned(data_ptr, fd);
    }

    let n = unsafe { sendmsg(stream.as_raw_fd(), &msg, 0) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Convenience smoke for the path resolution. The actual SCM_RIGHTS
/// transfer is integration-tested in the helper-installer Swift
/// project, since it requires both ends and an actual utun.
#[cfg(test)]
mod tests {
    #[test]
    fn default_socket_path_is_absolute() {
        assert!(super::DEFAULT_SOCKET_PATH.starts_with('/'));
    }
}
