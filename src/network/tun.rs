use std::{
    io::Read,
    net::Ipv4Addr,
    os::fd::{AsRawFd as _, OwnedFd},
};

use nix::sys::socket::{socket, AddressFamily, SockFlag, SockType};

use super::{
    consts,
    error::NetworkError,
    packet::IpPacket,
    settings::{NetworkCreateTunTap, NetworkSetFlags, NetworkSetIpv4Address, NetworkSetSubnetMask},
};

pub struct NetworkTunBuilder {
    name: Option<String>,
    ip_address: Option<Ipv4Addr>,
    subnet_mask: Option<u8>,
}

impl NetworkTunBuilder {
    pub fn name(&mut self, name: &str) -> &mut Self {
        let _ = self.name.insert(name.to_owned());
        self
    }

    pub fn ip_address(&mut self, ip_address: Ipv4Addr) -> &mut Self {
        let _ = self.ip_address.insert(ip_address);
        self
    }

    pub fn subnet_mask(&mut self, subnet_mask: u8) -> &mut Self {
        let _ = self.subnet_mask.insert(subnet_mask);
        self
    }

    pub fn build(&self) -> Result<NetworkTun, NetworkError> {
        let tun_fd = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .open("/dev/net/tun")
            .map_err(|e| NetworkError::IoError(format!("IO error on tun. {e:?}")))?;

        let tun_name = {
            let ifreq = match &self.name {
                Some(name) => NetworkCreateTunTap::new_tun(name.as_str()),
                None => NetworkCreateTunTap::new_tun_no_name(),
            }?;

            let code = unsafe {
                nix::libc::ioctl(
                    tun_fd.as_raw_fd(),
                    consts::TUNSETIFF,
                    &ifreq as *const NetworkCreateTunTap,
                )
            };
            nix::errno::Errno::result(code).map_err(NetworkError::IoctlError)?;
            ifreq.get_name()
        };

        let sock_fd = socket(
            AddressFamily::Inet,
            SockType::Datagram,
            SockFlag::empty(),
            None,
        )
        .map_err(NetworkError::IoctlError)?;

        let new_tun = NetworkTun {
            tun_fd,
            sock_fd,
            tun_name,
        };

        if let Some(ip_address) = self.ip_address {
            let addr = NetworkSetIpv4Address::new(new_tun.tun_name.as_str(), ip_address)?;
            let code = unsafe {
                nix::libc::ioctl(
                    new_tun.sock_fd.as_raw_fd(),
                    consts::SIOCSIFADDR,
                    &addr as *const NetworkSetIpv4Address,
                )
            };
            nix::errno::Errno::result(code).map_err(NetworkError::IoctlError)?;
        }

        if self.ip_address.is_none() && self.subnet_mask.is_some() {
            return Err(NetworkError::InvalidSubnetMask(
                "Subnet mask cannot be set without also setting an IP address".to_string(),
            ));
        }

        if let Some(mask) = self.subnet_mask {
            if mask == 0 || mask > 32 {
                return Err(NetworkError::InvalidSubnetMask(format!(
                    "Subnet mask value is invalid (got '{mask}')"
                )));
            }
            let mask = NetworkSetSubnetMask::new(new_tun.tun_name.as_str(), mask)?;
            let code = unsafe {
                nix::libc::ioctl(
                    new_tun.sock_fd.as_raw_fd(),
                    consts::SIOCSIFNETMASK,
                    &mask as *const NetworkSetSubnetMask,
                )
            };
            nix::errno::Errno::result(code).map_err(NetworkError::IoctlError)?;
        }

        Ok(new_tun)
    }
}

pub struct NetworkTun {
    pub(crate) tun_fd: std::fs::File,
    pub(crate) sock_fd: OwnedFd,
    tun_name: String,
}

impl NetworkTun {
    pub fn builder() -> NetworkTunBuilder {
        NetworkTunBuilder {
            name: None,
            ip_address: None,
            subnet_mask: None,
        }
    }

    fn get_flags(&self) -> Result<NetworkSetFlags, NetworkError> {
        let flags = NetworkSetFlags::blank(self.tun_name.as_str())?;

        let code = unsafe {
            nix::libc::ioctl(
                self.sock_fd.as_raw_fd(),
                consts::SIOCGIFFLAGS,
                &flags as *const NetworkSetFlags,
            )
        };
        nix::errno::Errno::result(code).map_err(NetworkError::IoctlError)?;

        Ok(flags)
    }

    fn set_flags(&self, flags: &NetworkSetFlags) -> Result<(), NetworkError> {
        let code = unsafe {
            nix::libc::ioctl(
                self.sock_fd.as_raw_fd(),
                consts::SIOCSIFFLAGS,
                flags as *const NetworkSetFlags,
            )
        };
        nix::errno::Errno::result(code).map_err(NetworkError::IoctlError)?;

        Ok(())
    }

    pub fn set_up(&self, up: bool) -> Result<(), NetworkError> {
        let mut flags = self.get_flags()?;

        if up {
            flags.set_flag(consts::IFF_UP);
        } else {
            flags.clear_flag(consts::IFF_UP);
        }

        self.set_flags(&flags)
    }

    pub fn recv(&mut self) -> Result<IpPacket, NetworkError> {
        let mut buf = [0u8; 2000];
        let n = self.tun_fd.read(&mut buf).expect("");

        let _flags = ((buf[0] as u16) << 8) | (buf[1] as u16);
        let _proto = ((buf[2] as u16) << 8) | (buf[3] as u16);

        IpPacket::from_bytes(&buf[4..n])
    }
}
