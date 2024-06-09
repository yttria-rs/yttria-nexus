use std::net::{Ipv4Addr, Ipv6Addr};

use super::error::NetworkError;

#[derive(Debug)]
#[repr(u8)]
pub enum IpVersion {
    Ipv4 = 4,
    Ipv6 = 6,
}

#[derive(Debug)]
pub enum IpPacket {
    Ipv4(Ipv4Packet),
    Ipv6(Ipv6Packet),
}

impl IpPacket {
    pub fn from_bytes(data: &[u8]) -> Result<Self, NetworkError> {
        if data.is_empty() {
            return Err(NetworkError::PacketParseError(
                "Provided byte slice is empty!".to_string(),
            ));
        }

        let version = data[0] >> 4;

        let version = if version == 4 {
            IpVersion::Ipv4
        } else if version == 6 {
            IpVersion::Ipv6
        } else {
            return Err(NetworkError::PacketParseError(
                "Could not determine Ip version".to_string(),
            ));
        };

        match version {
            IpVersion::Ipv4 => {
                if data.len() < 20 {
                    return Err(NetworkError::PacketParseError(
                        "provided bytes are too short to be an Ipv4 packet (<20 bytes)".to_string(),
                    ));
                }

                let length = ((data[2] as u16) << 8) | data[3] as u16;

                if data.len() != length as usize {
                    return Err(NetworkError::PacketParseError(format!("provided bytes length does not match parsed length (slice: {}, parsed: {})", data.len(), length)));
                }

                let header_len = (data[0] & 0x0F) * 4;

                if data.len() < header_len as usize {
                    return Err(NetworkError::PacketParseError(format!("parsed header length is greater than total packet length (header: {}, packet: {})", header_len, length)));
                }

                Ok(Self::Ipv4(Ipv4Packet {
                    version,
                    ihl: header_len,
                    dscp: data[1] >> 2,
                    ecn: data[1] & 0x03,
                    total_length: length,
                    identification: ((data[4] as u16) << 8) | data[5] as u16,
                    flags: data[6] >> 5,
                    fragment_offset: (((data[6] as u16) & 0x1F) << 8) | data[7] as u16,
                    ttl: data[8],
                    protocol: data[9],
                    header_checksum: ((data[10] as u16) << 8) | data[11] as u16,
                    source: Ipv4Addr::new(data[12], data[13], data[14], data[15]),
                    destination: Ipv4Addr::new(data[16], data[17], data[18], data[19]),
                    options: data[20..(header_len as usize)].to_vec(),
                    data: data[(header_len as usize)..(length as usize)].to_vec(),
                }))
            }
            IpVersion::Ipv6 => {
                if data.len() < 40 {
                    return Err(NetworkError::PacketParseError(
                        "provided bytes are too short to be an Ipv6 packet (<40 bytes)".to_string(),
                    ));
                }

                let length = ((data[4] as u16) << 8) | data[5] as u16;

                if data.len() - 40 != length as usize {
                    return Err(NetworkError::PacketParseError(format!("provided bytes length does not match parsed length. Note that extensions are not currently supported (slice: {}, parsed: {})", data.len(), length)));
                }

                Ok(Self::Ipv6(Ipv6Packet {
                    version,
                    traffic_class: ((data[0] & 0x0F) << 4) | (data[1] >> 4),
                    flow_label: (((data[1] & 0x0F) as u32) << 16)
                        | ((data[2] as u32) << 8)
                        | (data[3] as u32),
                    payload_length: length,
                    next_header: data[6],
                    hop_limit: data[7],
                    source: Ipv6Addr::new(
                        ((data[8] as u16) << 8) | (data[9] as u16),
                        ((data[10] as u16) << 8) | (data[11] as u16),
                        ((data[12] as u16) << 8) | (data[13] as u16),
                        ((data[14] as u16) << 8) | (data[15] as u16),
                        ((data[16] as u16) << 8) | (data[17] as u16),
                        ((data[18] as u16) << 8) | (data[19] as u16),
                        ((data[20] as u16) << 8) | (data[21] as u16),
                        ((data[22] as u16) << 8) | (data[23] as u16),
                    ),
                    destination: Ipv6Addr::new(
                        ((data[24] as u16) << 8) | (data[25] as u16),
                        ((data[26] as u16) << 8) | (data[27] as u16),
                        ((data[28] as u16) << 8) | (data[29] as u16),
                        ((data[30] as u16) << 8) | (data[31] as u16),
                        ((data[32] as u16) << 8) | (data[33] as u16),
                        ((data[34] as u16) << 8) | (data[35] as u16),
                        ((data[36] as u16) << 8) | (data[37] as u16),
                        ((data[38] as u16) << 8) | (data[39] as u16),
                    ),
                    extension_headers: vec![],
                    data: data[40..(40 + (length as usize))].to_vec(),
                }))
            }
        }
    }
}

impl std::fmt::Display for IpPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpPacket::Ipv4(v) => {
                write!(f, "{v}")
            }
            IpPacket::Ipv6(v) => {
                write!(f, "{v}")
            }
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct Ipv4Packet {
    version: IpVersion,
    ihl: u8,
    dscp: u8,
    ecn: u8,
    total_length: u16,
    identification: u16,
    flags: u8,
    fragment_offset: u16,
    ttl: u8,
    protocol: u8,
    header_checksum: u16,
    source: Ipv4Addr,
    destination: Ipv4Addr,
    options: Vec<u8>,
    data: Vec<u8>,
}

impl std::fmt::Display for Ipv4Packet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "version: {:?}, ihl: {}, dscp: {}, ecn: {}, total_length: {}, identification: {}, flags: {}, fragment_offset: {}, ttl: {}, protocol: {}, header_checksum: {}, source: {}, destination: {}",
            self.version,
            self.ihl,
            self.dscp,
            self.ecn,
            self.total_length,
            self.identification,
            self.flags,
            self.fragment_offset,
            self.ttl,
            self.protocol,
            self.header_checksum,
            self.source,
            self.destination,
        )
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct Ipv6Packet {
    version: IpVersion,
    traffic_class: u8,
    flow_label: u32,
    payload_length: u16,
    next_header: u8,
    hop_limit: u8,
    source: Ipv6Addr,
    destination: Ipv6Addr,
    extension_headers: Vec<u8>,
    data: Vec<u8>,
}

impl std::fmt::Display for Ipv6Packet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "version: {:?}, traffic_class: {}, flow_label: {}, payload_length: {}, next_header: {}, hop_limit: {}, source: {}, destination: {}",
            self.version,
            self.traffic_class,
            self.flow_label,
            self.payload_length,
            self.next_header,
            self.hop_limit,
            self.source,
            self.destination
        )
    }
}
