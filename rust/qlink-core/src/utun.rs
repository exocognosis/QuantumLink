//! Userspace TUN/utun device wrapper.
//!
//! Cross-platform packet ingress/egress to the OS without requiring
//! Apple's blessed Network Extension framework or any vendor kernel
//! extension. This is the same implementation strategy as Tailscale's
//! userspace mode, WireGuard's `wireguard-go`, and OpenVPN-Mac's
//! native tun support — open the system-provided utun/tun control
//! socket, push raw IP packets through a file descriptor.
//!
//! ## Platform implementations
//!
//! ### macOS (`utun`)
//!
//! Opens a `utun` device via the kernel control socket
//! (`PF_SYSTEM` + `SYSPROTO_CONTROL` + `com.apple.net.utun_control`).
//! Requires root to call `connect()` on the control socket. The
//! QuantumLink privileged helper performs the open and passes the
//! resulting file descriptor back to the unprivileged app over a
//! Unix domain socket via `SCM_RIGHTS`. Once the FD is in hand, no
//! further root-required syscalls are needed for read/write.
//!
//! macOS utun packets carry a 4-byte `AF_INET` / `AF_INET6` protocol
//! family prefix (network byte order). [`UtunDevice`] strips the
//! prefix on read and prepends it on write so callers see raw IP.
//!
//! ### Linux (`/dev/net/tun`)
//!
//! Opens `/dev/net/tun` and configures it via `ioctl(TUNSETIFF)`.
//! Requires `CAP_NET_ADMIN` (or root). On qlinkd deployments the
//! daemon's systemd unit grants the capability via
//! `AmbientCapabilities=CAP_NET_ADMIN`. We set `IFF_NO_PI` so packets
//! are raw IP (no 4-byte tun_pi header) — matches the macOS path
//! after prefix stripping, so callers see one consistent format.
//!
//! ## What this module does NOT do
//!
//! - **Address assignment / routing.** Setting an IP on the
//!   interface and adding routes requires `ifconfig` / `ip`
//!   invocations or the equivalent SystemConfiguration calls. On
//!   macOS the privileged helper handles this. On Linux the systemd
//!   unit's `ExecStartPost=` hooks handle it.
//! - **Async I/O.** [`UtunDevice`] presents blocking `read_packet` /
//!   `write_packet` methods; integration with tokio is the caller's
//!   responsibility (typically via [`tokio::io::unix::AsyncFd`]).

use crate::error::Result;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

/// Maximum IP packet size for an Ethernet-derived MTU. macOS utun
/// defaults to 1500; Linux tun defaults to 1500. We size buffers a
/// little larger to handle the 4-byte macOS protocol prefix without
/// per-call allocations.
pub const PACKET_BUFFER_SIZE: usize = 1504;

/// Raw IP-packet device. Implementations differ per platform but the
/// surface area is identical: open or adopt-fd, then read/write raw
/// IP packets.
pub struct UtunDevice {
    fd: OwnedFd,
    name: String,
}

impl UtunDevice {
    /// Adopt a file descriptor that some other code (typically the
    /// privileged helper on macOS) has already configured. The FD
    /// must already point at a kernel-control utun socket on macOS,
    /// or a /dev/net/tun device on Linux.
    ///
    /// Caller is responsible for ensuring `name` matches the actual
    /// interface name (e.g. "utun7" / "tun0") so downstream
    /// `ifconfig`/`ip` commands target the right device.
    pub fn from_fd(fd: OwnedFd, name: String) -> Self {
        Self { fd, name }
    }

    /// Interface name (e.g. "utun7" on macOS, "tun0" on Linux).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Underlying file descriptor. Useful for wrapping in
    /// [`tokio::io::unix::AsyncFd`] for async reads.
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Read one IP packet into `buf`. Returns the number of bytes
    /// written into `buf`. The packet starts at `buf[0]` and is the
    /// raw IP datagram (no platform-specific prefixes — those are
    /// stripped here).
    ///
    /// Blocking. For async, wrap [`as_raw_fd`] in
    /// [`tokio::io::unix::AsyncFd`].
    pub fn read_packet(&self, buf: &mut [u8]) -> io::Result<usize> {
        platform::read_packet(self.fd.as_raw_fd(), buf)
    }

    /// Write one raw IP packet. `packet` must start with the IP
    /// header (no platform-specific prefixes — those are added here).
    ///
    /// Blocking. For async, wrap [`as_raw_fd`] in
    /// [`tokio::io::unix::AsyncFd`].
    pub fn write_packet(&self, packet: &[u8]) -> io::Result<usize> {
        platform::write_packet(self.fd.as_raw_fd(), packet)
    }
}

// ---------------------------------------------------------------------------
// macOS implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod platform {
    use super::*;
    use libc::{
        c_char, c_int, c_void, connect, ioctl, sockaddr, socket, socklen_t,
        AF_INET, AF_INET6, PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL,
    };
    use std::ffi::CStr;
    use std::mem::{size_of, MaybeUninit};

    // Kernel-control socket constants. These aren't all exposed by the
    // libc crate, so we define them locally with the values from
    // <sys/kern_control.h> on macOS.
    const CTLIOCGINFO: libc::c_ulong = 0xc0644e03;
    const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control\0";

    // <sys/sys_domain.h>
    const SYSPROTO_EVENT: c_int = 1;
    #[allow(dead_code)]
    const AF_SYS_CONTROL: u16 = 2;

    #[repr(C)]
    struct CtlInfo {
        ctl_id: u32,
        ctl_name: [c_char; 96],
    }

    #[repr(C)]
    struct SockaddrCtl {
        sc_len: u8,
        sc_family: u8,
        ss_sysaddr: u16,
        sc_id: u32,
        sc_unit: u32,
        sc_reserved: [u32; 5],
    }

    /// Open a fresh utun device. Requires root. On the unprivileged
    /// app side, prefer receiving an FD from the privileged helper
    /// via SCM_RIGHTS; this entry point exists for the helper itself
    /// and for tests run as root.
    ///
    /// `unit` is the requested utun number (1 → utun0, 2 → utun1,
    /// etc.). Pass 0 to let the kernel pick the first free unit;
    /// the assigned name is returned.
    pub fn create(unit: u32) -> Result<UtunDevice> {
        // SAFETY: socket(2) with valid constants always returns
        // either a valid FD or -1; the `if fd < 0` branch handles
        // the error case before we wrap.
        let fd = unsafe { socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL) };
        if fd < 0 {
            return Err(io_err("socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)").into());
        }
        // Wrap immediately so any early return drops the FD.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };

        // Resolve the control name "com.apple.net.utun_control" to
        // the kernel-assigned ctl_id we'll use in the connect()
        // sockaddr.
        let mut info = CtlInfo {
            ctl_id: 0,
            ctl_name: [0; 96],
        };
        for (i, b) in UTUN_CONTROL_NAME.iter().enumerate() {
            info.ctl_name[i] = *b as c_char;
        }
        let rc = unsafe {
            ioctl(
                owned.as_raw_fd(),
                CTLIOCGINFO,
                &mut info as *mut CtlInfo as *mut c_void,
            )
        };
        if rc < 0 {
            return Err(io_err("ioctl(CTLIOCGINFO, utun_control)").into());
        }

        // sc_unit semantics: 0 = let kernel pick; N = utun(N-1).
        let sc = SockaddrCtl {
            sc_len: size_of::<SockaddrCtl>() as u8,
            sc_family: libc::AF_SYSTEM as u8,
            ss_sysaddr: SYSPROTO_EVENT as u16, // any nonzero placeholder works; kernel ignores
            sc_id: info.ctl_id,
            sc_unit: unit,
            sc_reserved: [0; 5],
        };
        let rc = unsafe {
            connect(
                owned.as_raw_fd(),
                &sc as *const SockaddrCtl as *const sockaddr,
                size_of::<SockaddrCtl>() as socklen_t,
            )
        };
        if rc < 0 {
            return Err(io_err("connect(utun_control)").into());
        }

        // Read back the assigned interface name. macOS returns it
        // via getsockopt(IPPROTO_IP=0, UTUN_OPT_IFNAME=2).
        const UTUN_OPT_IFNAME: c_int = 2;
        let mut name_buf: [u8; 32] = [0; 32];
        let mut name_len: socklen_t = name_buf.len() as socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                owned.as_raw_fd(),
                SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                name_buf.as_mut_ptr() as *mut c_void,
                &mut name_len,
            )
        };
        if rc < 0 {
            return Err(io_err("getsockopt(UTUN_OPT_IFNAME)").into());
        }
        let name = CStr::from_bytes_until_nul(&name_buf)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "UTUN_OPT_IFNAME not nul-terminated",
                )
            })?
            .to_string_lossy()
            .into_owned();

        Ok(UtunDevice { fd: owned, name })
    }

    /// Read one packet from a utun fd. macOS prefixes each packet
    /// with a 4-byte protocol family in network byte order; we strip
    /// it so the caller sees a raw IP datagram starting at `buf[0]`.
    pub fn read_packet(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
        let mut tmp: [MaybeUninit<u8>; PACKET_BUFFER_SIZE] = [MaybeUninit::uninit(); PACKET_BUFFER_SIZE];
        let n = unsafe {
            libc::read(
                fd,
                tmp.as_mut_ptr() as *mut c_void,
                tmp.len(),
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = n as usize;
        if n < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "utun read returned fewer than 4 bytes (missing protocol prefix)",
            ));
        }
        let payload_len = n - 4;
        if payload_len > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "utun packet larger than caller buffer",
            ));
        }
        // SAFETY: read() wrote `n` bytes into `tmp`; we only read
        // bytes 4..n which are now initialized.
        for i in 0..payload_len {
            buf[i] = unsafe { tmp[i + 4].assume_init() };
        }
        Ok(payload_len)
    }

    /// Write one packet to a utun fd. Prepends the 4-byte protocol
    /// family prefix expected by utun (AF_INET for IPv4, AF_INET6
    /// for IPv6 — chosen from the IP version field of `packet`).
    pub fn write_packet(fd: RawFd, packet: &[u8]) -> io::Result<usize> {
        if packet.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty packet"));
        }
        // First nibble of an IP header is the version: 4 or 6.
        let af: u32 = match packet[0] >> 4 {
            4 => AF_INET as u32,
            6 => AF_INET6 as u32,
            v => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unrecognized IP version: {v}"),
                ));
            }
        };
        let af_be = af.to_be_bytes();

        // utun expects a single contiguous write of [prefix | packet].
        // We compose into a stack buffer to keep allocations off the
        // packet path.
        let mut framed: [u8; PACKET_BUFFER_SIZE] = [0; PACKET_BUFFER_SIZE];
        let total = 4 + packet.len();
        if total > framed.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet too large for utun MTU",
            ));
        }
        framed[..4].copy_from_slice(&af_be);
        framed[4..total].copy_from_slice(packet);
        let n = unsafe {
            libc::write(fd, framed.as_ptr() as *const c_void, total)
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        // Caller-visible bytes are the IP packet only, not the prefix.
        Ok((n as usize).saturating_sub(4))
    }
}

// ---------------------------------------------------------------------------
// Linux implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use libc::{c_char, c_int, c_short, c_void};
    use std::ffi::CString;
    use std::os::fd::{IntoRawFd, RawFd};

    // <linux/if_tun.h> + <linux/if.h> constants. The libc crate
    // exposes some but not all; these locals match the canonical
    // header values.
    const IFF_TUN: c_short = 0x0001;
    const IFF_NO_PI: c_short = 0x1000;
    const TUNSETIFF: libc::c_ulong = 0x400454ca;
    const IFNAMSIZ: usize = 16;
    const TUN_DEV_PATH: &str = "/dev/net/tun";

    #[repr(C)]
    struct IfReq {
        ifr_name: [c_char; IFNAMSIZ],
        ifr_flags: c_short,
        // Padding so the union region is at least as large as the
        // largest variant. We never read it; ioctl() ignores beyond
        // ifr_flags for TUNSETIFF.
        _padding: [u8; 24 - 2],
    }

    /// Open a fresh tun device. Requires CAP_NET_ADMIN (or root).
    ///
    /// `requested_name` may be an empty string to let the kernel
    /// pick (e.g. "tun0"). Otherwise the kernel will use the
    /// requested name if it's not in use.
    pub fn create(requested_name: &str) -> Result<UtunDevice> {
        let path = CString::new(TUN_DEV_PATH).expect("static path is C-safe");
        // SAFETY: open() with valid arguments returns either a valid
        // FD or -1; the `if fd < 0` branch handles the error case.
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(io_err("open(/dev/net/tun)").into());
        }
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };

        let mut req = IfReq {
            ifr_name: [0; IFNAMSIZ],
            ifr_flags: IFF_TUN | IFF_NO_PI,
            _padding: [0; 22],
        };
        let truncated = &requested_name.as_bytes()[..requested_name.len().min(IFNAMSIZ - 1)];
        for (i, b) in truncated.iter().enumerate() {
            req.ifr_name[i] = *b as c_char;
        }

        let rc = unsafe {
            libc::ioctl(
                owned.as_raw_fd(),
                TUNSETIFF,
                &mut req as *mut IfReq as *mut c_void,
            )
        };
        if rc < 0 {
            return Err(io_err("ioctl(TUNSETIFF)").into());
        }

        // ifr_name now contains the assigned name (kernel may have
        // substituted if the request was empty).
        let assigned = {
            let bytes: Vec<u8> = req
                .ifr_name
                .iter()
                .take_while(|&&b| b != 0)
                .map(|&b| b as u8)
                .collect();
            String::from_utf8(bytes).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("non-utf8 interface name from kernel: {e}"),
                )
            })?
        };

        Ok(UtunDevice {
            fd: owned,
            name: assigned,
        })
    }

    pub fn read_packet(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
        let n = unsafe {
            libc::read(fd, buf.as_mut_ptr() as *mut c_void, buf.len())
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    pub fn write_packet(fd: RawFd, packet: &[u8]) -> io::Result<usize> {
        let n = unsafe {
            libc::write(fd, packet.as_ptr() as *const c_void, packet.len())
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }
}

// ---------------------------------------------------------------------------
// Stubs for unsupported platforms (Windows, iOS, BSDs other than macOS)
// ---------------------------------------------------------------------------

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod platform {
    use super::*;
    use std::os::fd::RawFd;

    pub fn read_packet(_fd: RawFd, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "userspace utun not yet implemented on this platform",
        ))
    }

    pub fn write_packet(_fd: RawFd, _packet: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "userspace utun not yet implemented on this platform",
        ))
    }
}

// ---------------------------------------------------------------------------
// Public open helpers
// ---------------------------------------------------------------------------

/// Open a fresh utun (macOS) or tun (Linux) device. Requires root /
/// CAP_NET_ADMIN. Use [`UtunDevice::from_fd`] when adopting an FD
/// passed in from a privileged helper instead.
#[cfg(target_os = "macos")]
pub fn create_utun(unit: u32) -> Result<UtunDevice> {
    platform::create(unit)
}

#[cfg(target_os = "linux")]
pub fn create_tun(requested_name: &str) -> Result<UtunDevice> {
    platform::create(requested_name)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[allow(dead_code)]
fn io_err(label: &'static str) -> io::Error {
    let inner = io::Error::last_os_error();
    io::Error::new(inner.kind(), format!("{label}: {inner}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// We don't unit-test the actual open() path because it requires
    /// root. The packet-framing logic on the macOS path IS testable
    /// without root: we exercise the prefix logic by simulating
    /// reads/writes against a pipe, but skip in this revision —
    /// added in a follow-up alongside integration coverage from
    /// the privileged-helper FD-passing tests.
    #[test]
    fn buffer_size_is_sane() {
        // Sanity: utun MTU plus 4-byte prefix fits in our buffer.
        assert!(PACKET_BUFFER_SIZE >= 1500 + 4);
    }
}
