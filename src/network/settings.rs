use std::net::Ipv4Addr;

use super::{consts, error::NetworkError};

pub(crate) fn validate_name(name: &str) -> Result<[u8; 16], NetworkError> {
    let mut c_name = [0; 16];

    if !name.is_ascii() {
        return Err(NetworkError::InvalidName(format!(
            "Network name can only contain ascii characters (got '{name}'"
        )));
    }
    if name.len() >= c_name.len() {
        return Err(NetworkError::InvalidName(format!(
            "Network name is too long (got '{name}'"
        )));
    }

    let chars = name.chars().map(|x| x as u8).collect::<Vec<_>>();
    c_name[0..(name.len())].copy_from_slice(chars.as_slice());

    Ok(c_name)
}

#[derive(Debug)]
#[repr(C)]
pub struct NetworkCreateTunTap {
    network_name: [u8; 16],
    flags: u16,
    _0: [u8; 22],
}

#[allow(dead_code)]
impl NetworkCreateTunTap {
    pub fn new_tun(name: &str) -> Result<Self, NetworkError> {
        Ok(Self {
            network_name: validate_name(name)?,
            flags: consts::IFF_TUN,
            _0: [0; 22],
        })
    }

    pub fn new_tap(name: &str) -> Result<Self, NetworkError> {
        Ok(Self {
            network_name: validate_name(name)?,
            flags: consts::IFF_TAP,
            _0: [0; 22],
        })
    }

    pub fn new_tun_no_name() -> Result<Self, NetworkError> {
        Ok(Self {
            network_name: [0; 16],
            flags: consts::IFF_TUN,
            _0: [0; 22],
        })
    }

    pub fn new_tap_no_name() -> Result<Self, NetworkError> {
        Ok(Self {
            network_name: [0; 16],
            flags: consts::IFF_TAP,
            _0: [0; 22],
        })
    }

    pub fn get_name(&self) -> String {
        self.network_name
            .iter()
            .filter(|&&x| x != 0)
            .map(|&x| x as char)
            .collect::<String>()
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct NetworkSetIpv4Address {
    network_name: [u8; 16],
    address_family: u16,
    _0: [u8; 2],
    ip_address: Ipv4Addr,
    _1: [u8; 16],
}

impl NetworkSetIpv4Address {
    pub fn new(name: &str, ip_address: Ipv4Addr) -> Result<Self, NetworkError> {
        Ok(Self {
            network_name: validate_name(name)?,
            address_family: 0x0002,
            _0: [0; 2],
            ip_address,
            _1: [0; 16],
        })
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct NetworkSetSubnetMask {
    network_name: [u8; 16],
    address_family: u16,
    _0: [u8; 2],
    subnet_mask: [u8; 4],
    _1: [u8; 16],
}

impl NetworkSetSubnetMask {
    pub fn new(name: &str, subnet_mask: u8) -> Result<Self, NetworkError> {
        let subnet_mask = subnet_mask as u32;
        let subnet_mask_cleared: u32 = 0xFFFF_FFFF >> (32 - subnet_mask) << (32 - subnet_mask);
        Ok(Self {
            network_name: validate_name(name)?,
            address_family: 0x0002,
            _0: [0; 2],
            subnet_mask: subnet_mask_cleared.to_be_bytes(),
            _1: [0; 16],
        })
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct NetworkSetFlags {
    network_name: [u8; 16],
    flags: u16,
    _0: [u8; 22],
}

impl NetworkSetFlags {
    pub fn blank(name: &str) -> Result<Self, NetworkError> {
        Ok(Self {
            network_name: validate_name(name)?,
            flags: 0,
            _0: [0; 22],
        })
    }

    pub fn set_flag(&mut self, flag: u16) {
        self.flags |= flag;
    }

    pub fn clear_flag(&mut self, flag: u16) {
        self.flags &= !flag;
    }
}
