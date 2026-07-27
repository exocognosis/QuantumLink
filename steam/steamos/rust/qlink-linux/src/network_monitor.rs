//! Non-blocking Linux route/link/address change monitoring.

use std::io;

#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

#[derive(Debug)]
pub struct NetworkChangeMonitor {
    #[cfg(target_os = "linux")]
    fd: OwnedFd,
}

impl NetworkChangeMonitor {
    #[cfg(target_os = "linux")]
    pub fn open() -> io::Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let groups = (libc::RTMGRP_LINK
            | libc::RTMGRP_IPV4_IFADDR
            | libc::RTMGRP_IPV6_IFADDR
            | libc::RTMGRP_IPV4_ROUTE
            | libc::RTMGRP_IPV6_ROUTE) as u32;
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as u16;
        address.nl_pid = 0;
        address.nl_groups = groups;
        let result = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&address as *const libc::sockaddr_nl).cast(),
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn open() -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Linux network change monitoring is available only on Linux",
        ))
    }

    /// Drains all currently queued netlink notifications and returns whether
    /// at least one route, link, or address change was observed.
    #[cfg(target_os = "linux")]
    pub fn poll_changed(&mut self) -> io::Result<bool> {
        let mut changed = false;
        let mut buffer = [0_u8; 8192];
        loop {
            let read = unsafe {
                libc::recv(
                    self.fd.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if read > 0 {
                changed = true;
                continue;
            }
            if read == 0 {
                return Ok(changed);
            }
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock {
                return Ok(changed);
            }
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn poll_changed(&mut self) -> io::Result<bool> {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn monitor_is_explicitly_unsupported_off_linux() {
        assert_eq!(
            NetworkChangeMonitor::open().unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn monitor_opens_without_privilege_and_polls_nonblocking() {
        let mut monitor = NetworkChangeMonitor::open().unwrap();
        monitor.poll_changed().unwrap();
    }
}
