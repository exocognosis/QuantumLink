use std::collections::VecDeque;
use std::error::Error;
use std::fmt;
use std::io::{self, Read, Write};

#[cfg(unix)]
use std::fs::{File, OpenOptions};
#[cfg(unix)]
use std::os::{
    fd::{AsRawFd, RawFd},
    raw::{c_char, c_int, c_short, c_ulong},
};
#[cfg(unix)]
use std::path::Path;

const PROTOCOL_FAMILY_IPV4: u32 = 2;
const PROTOCOL_FAMILY_IPV6: u32 = 10;

#[cfg(unix)]
const LINUX_TUN_PATH: &str = "/dev/net/tun";
#[cfg(unix)]
const IFNAMSIZ: usize = 16;
#[cfg(unix)]
const IFF_TUN: i16 = 0x0001;
#[cfg(unix)]
const IFF_NO_PI: i16 = 0x1000;
#[cfg(unix)]
const TUNSETIFF: c_ulong = 0x400454ca;
#[cfg(unix)]
const F_GETFL: c_int = 3;
#[cfg(unix)]
const F_SETFL: c_int = 4;
#[cfg(unix)]
const O_NONBLOCK: c_int = 0o4000;

pub trait TunPacketIo {
    fn config(&self) -> &TunDeviceConfig;

    fn read_packet(&mut self, buffer: &mut [u8]) -> Result<usize, TunPacketIoError>;

    fn write_packet(&mut self, packet: &[u8]) -> Result<(), TunPacketIoError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunDeviceConfig {
    pub name: String,
    pub mtu: usize,
}

impl TunDeviceConfig {
    pub fn new(name: impl Into<String>, mtu: usize) -> Self {
        Self {
            name: name.into(),
            mtu,
        }
    }
}

#[derive(Debug)]
pub enum TunPacketIoError {
    PacketExceedsMtu {
        packet_len: usize,
        mtu: usize,
    },
    ReadBufferTooSmall {
        packet_len: usize,
        buffer_len: usize,
    },
    Io(io::Error),
}

impl fmt::Display for TunPacketIoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PacketExceedsMtu { packet_len, mtu } => {
                write!(f, "packet length {packet_len} exceeds configured MTU {mtu}")
            }
            Self::ReadBufferTooSmall {
                packet_len,
                buffer_len,
            } => write!(
                f,
                "read buffer length {buffer_len} is smaller than packet length {packet_len}"
            ),
            Self::Io(error) => write!(f, "{error}"),
        }
    }
}

impl Error for TunPacketIoError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::PacketExceedsMtu { .. } | Self::ReadBufferTooSmall { .. } => None,
        }
    }
}

impl From<io::Error> for TunPacketIoError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopbackTunDevice {
    config: TunDeviceConfig,
    packets: VecDeque<Vec<u8>>,
}

impl LoopbackTunDevice {
    pub fn new(config: TunDeviceConfig) -> Self {
        Self {
            config,
            packets: VecDeque::new(),
        }
    }
}

impl TunPacketIo for LoopbackTunDevice {
    fn config(&self) -> &TunDeviceConfig {
        &self.config
    }

    fn read_packet(&mut self, buffer: &mut [u8]) -> Result<usize, TunPacketIoError> {
        let packet = self.packets.front().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "loopback TUN has no queued packet",
            )
        })?;

        if packet.len() > buffer.len() {
            return Err(TunPacketIoError::ReadBufferTooSmall {
                packet_len: packet.len(),
                buffer_len: buffer.len(),
            });
        }

        let packet = self
            .packets
            .pop_front()
            .expect("front packet should remain queued");
        buffer[..packet.len()].copy_from_slice(&packet);
        Ok(packet.len())
    }

    fn write_packet(&mut self, packet: &[u8]) -> Result<(), TunPacketIoError> {
        reject_packet_larger_than_mtu(packet, self.config.mtu)?;
        self.packets.push_back(packet.to_vec());
        Ok(())
    }
}

#[cfg(unix)]
pub struct LinuxTunOpenRequest<'a> {
    pub path: &'a Path,
    pub config: &'a TunDeviceConfig,
    pub flags: i16,
}

#[cfg(unix)]
pub trait TunDeviceOpener {
    type Io: Read + Write;

    fn open(&mut self, request: LinuxTunOpenRequest<'_>) -> io::Result<Self::Io>;
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RealTunOpener;

#[cfg(unix)]
impl TunDeviceOpener for RealTunOpener {
    type Io = File;

    fn open(&mut self, request: LinuxTunOpenRequest<'_>) -> io::Result<Self::Io> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(request.path)?;
        configure_linux_tun(file.as_raw_fd(), &request.config.name, request.flags)?;
        // Non-blocking reads let the resident daemon poll the TUN in its
        // single-threaded pump loop without stalling the control socket when no
        // packet is queued. The data plane treats `WouldBlock` as an idle tick.
        set_nonblocking(file.as_raw_fd())?;
        Ok(file)
    }
}

#[cfg(unix)]
#[derive(Debug)]
pub struct LinuxTunDevice<Io = File> {
    config: TunDeviceConfig,
    io: Io,
}

#[cfg(unix)]
impl LinuxTunDevice<File> {
    pub fn open(config: TunDeviceConfig) -> Result<Self, TunPacketIoError> {
        let mut opener = RealTunOpener;
        Self::open_with(config, &mut opener)
    }
}

#[cfg(unix)]
impl<Io> LinuxTunDevice<Io>
where
    Io: Read + Write,
{
    pub fn open_with<O>(config: TunDeviceConfig, opener: &mut O) -> Result<Self, TunPacketIoError>
    where
        O: TunDeviceOpener<Io = Io>,
    {
        let io = opener.open(LinuxTunOpenRequest {
            path: Path::new(LINUX_TUN_PATH),
            config: &config,
            flags: IFF_TUN | IFF_NO_PI,
        })?;
        Ok(Self { config, io })
    }

    pub fn from_io(config: TunDeviceConfig, io: Io) -> Self {
        Self { config, io }
    }

    pub fn config(&self) -> &TunDeviceConfig {
        &self.config
    }

    pub fn into_inner(self) -> Io {
        self.io
    }
}

#[cfg(unix)]
impl<Io> TunPacketIo for LinuxTunDevice<Io>
where
    Io: Read + Write,
{
    fn config(&self) -> &TunDeviceConfig {
        &self.config
    }

    fn read_packet(&mut self, buffer: &mut [u8]) -> Result<usize, TunPacketIoError> {
        self.io.read(buffer).map_err(Into::into)
    }

    fn write_packet(&mut self, packet: &[u8]) -> Result<(), TunPacketIoError> {
        reject_packet_larger_than_mtu(packet, self.config.mtu)?;
        self.io.write_all(packet).map_err(Into::into)
    }
}

pub fn protocol_family_for_packet(packet: &[u8]) -> Option<u32> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => Some(PROTOCOL_FAMILY_IPV4),
        Some(6) => Some(PROTOCOL_FAMILY_IPV6),
        Some(_) | None => None,
    }
}

fn reject_packet_larger_than_mtu(packet: &[u8], mtu: usize) -> Result<(), TunPacketIoError> {
    if packet.len() > mtu {
        return Err(TunPacketIoError::PacketExceedsMtu {
            packet_len: packet.len(),
            mtu,
        });
    }
    Ok(())
}

#[cfg(unix)]
#[repr(C)]
struct IfReq {
    name: [c_char; IFNAMSIZ],
    flags: c_short,
    padding: [u8; 22],
}

#[cfg(unix)]
impl IfReq {
    fn new(name: &str, flags: i16) -> io::Result<Self> {
        let name_bytes = name.as_bytes();
        if name_bytes.len() >= IFNAMSIZ {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("TUN interface name `{name}` must be shorter than {IFNAMSIZ} bytes"),
            ));
        }

        let mut request = Self {
            name: [0; IFNAMSIZ],
            flags: flags as c_short,
            padding: [0; 22],
        };

        for (destination, source) in request.name.iter_mut().zip(name_bytes.iter().copied()) {
            *destination = source as c_char;
        }

        Ok(request)
    }
}

#[cfg(unix)]
fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { fcntl(fd, F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let result = unsafe { fcntl(fd, F_SETFL, flags | O_NONBLOCK) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

unsafe extern "C" {
    fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
    fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
}

#[cfg(unix)]
fn configure_linux_tun(fd: RawFd, name: &str, flags: i16) -> io::Result<()> {
    let mut request = IfReq::new(name, flags)?;
    let result = unsafe { ioctl(fd, TUNSETIFF, &mut request as *mut IfReq) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::path::PathBuf;

    #[test]
    fn protocol_family_for_packet_classifies_ipv4_and_ipv6() {
        assert_eq!(protocol_family_for_packet(&[0x45, 0x00]), Some(2));
        assert_eq!(protocol_family_for_packet(&[0x60, 0x00]), Some(10));
        assert_eq!(protocol_family_for_packet(&[]), None);
        assert_eq!(protocol_family_for_packet(&[0xf0]), None);
    }

    #[test]
    fn loopback_tun_round_trips_packets_without_root() {
        let config = TunDeviceConfig::new("qlink-test0", 8);
        let mut device = LoopbackTunDevice::new(config);
        let packet = [0x45, 0x00, 0x01, 0x02];
        let mut buffer = [0; 8];

        device.write_packet(&packet).expect("packet should fit mtu");

        let len = device
            .read_packet(&mut buffer)
            .expect("packet should be readable");
        assert_eq!(len, packet.len());
        assert_eq!(&buffer[..len], packet);
    }

    #[test]
    fn loopback_tun_rejects_packets_larger_than_configured_mtu() {
        let config = TunDeviceConfig::new("qlink-test0", 3);
        let mut device = LoopbackTunDevice::new(config);

        let error = device
            .write_packet(&[0x45, 0x00, 0x01, 0x02])
            .expect_err("oversized packet should be rejected");

        assert!(matches!(
            error,
            TunPacketIoError::PacketExceedsMtu {
                packet_len: 4,
                mtu: 3
            }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn linux_tun_open_uses_dev_net_tun_and_no_pi_flags_with_fake_opener() {
        #[derive(Default)]
        struct FakeTunOpener {
            path: Option<PathBuf>,
            name: Option<String>,
            mtu: Option<usize>,
            flags: Option<i16>,
        }

        impl TunDeviceOpener for FakeTunOpener {
            type Io = Cursor<Vec<u8>>;

            fn open(&mut self, request: LinuxTunOpenRequest<'_>) -> std::io::Result<Self::Io> {
                self.path = Some(request.path.to_path_buf());
                self.name = Some(request.config.name.clone());
                self.mtu = Some(request.config.mtu);
                self.flags = Some(request.flags);
                Ok(Cursor::new(Vec::new()))
            }
        }

        let config = TunDeviceConfig::new("qlink0", 1280);
        let mut opener = FakeTunOpener::default();

        let device =
            LinuxTunDevice::<Cursor<Vec<u8>>>::open_with(config.clone(), &mut opener).unwrap();

        assert_eq!(device.config(), &config);
        assert_eq!(
            opener.path.as_deref(),
            Some(std::path::Path::new("/dev/net/tun"))
        );
        assert_eq!(opener.name.as_deref(), Some("qlink0"));
        assert_eq!(opener.mtu, Some(1280));
        assert_eq!(opener.flags, Some(IFF_TUN | IFF_NO_PI));
    }
}
