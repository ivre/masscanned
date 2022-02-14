// This file is part of masscanned.
// Copyright 2021 - The IVRE project
//
// Masscanned is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Masscanned is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
// License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Masscanned. If not, see <http://www.gnu.org/licenses/>.

use log::*;

use std::convert::TryInto;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use byteorder::{BigEndian, ByteOrder};
use std::io;

use crate::client::ClientInfo;
use crate::Masscanned;

/* RFC 5389: The magic cookie field MUST contain the fixed value 0x2112A442 in
network byte order. */
/* Note: disabled for now due to a « bug » in smack */
pub const STUN_PATTERN_MAGIC: &[u8; 8] = b"\x00\x01**\x21\x12\xa4\x42";
pub const STUN_PATTERN_EMPTY: &[u8; 20] = b"\x00\x01\x00\x00****************";
/* RFC 3489: support without cookie */
pub const STUN_PATTERN_CHANGE_REQUEST: &[u8; 28] =
    b"\x00\x01\x00\x08****************\x00\x03\x00\x04\x00\x00\x00*";
pub const _STUN_MAGIC: u32 = 0x2112a442;

pub const STUN_CLASS_REQUEST: u8 = 0b00;
#[allow(dead_code)]
pub const STUN_CLASS_INDICATE: u8 = 0b01;
pub const STUN_CLASS_SUCCESS_RESPONSE: u8 = 0b10;
#[allow(dead_code)]
pub const STUN_CLASS_FAILURE_RESPONSE: u8 = 0b11;

pub const STUN_ATTR_MAPPED_ADDRESS: u16 = 0x0001;
pub const STUN_ATTR_CHANGE_REQUEST: u16 = 0x0003;

pub const STUN_METHOD_BINDING: u16 = 0x001;

pub const STUN_PROTOCOL_FAMILY_IPV4: u8 = 0x01;
pub const STUN_PROTOCOL_FAMILY_IPV6: u8 = 0x02;

pub const STUN_CHANGE_REQUEST_MASK_IP: u32 = 0x00000004;
pub const STUN_CHANGE_REQUEST_MASK_PORT: u32 = 0x00000002;

struct StunGenericAttribute {
    type_: u16,
    length: u16,
    data: Vec<u8>,
}

impl StunGenericAttribute {
    #[allow(dead_code)]
    fn new(data: &[u8]) -> Result<Self, io::Error> {
        if data.len() < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not enough data",
            ));
        }
        let type_ = BigEndian::read_u16(&data[0..2]);
        let length = BigEndian::read_u16(&data[2..4]);
        if data.len() < 4 + length as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not enough data",
            ));
        }
        let data = data[4..4 + length as usize].to_vec();
        Ok(StunGenericAttribute {
            type_,
            length,
            data,
        })
    }
}

impl Into<Vec<u8>> for &StunGenericAttribute {
    fn into(self) -> Vec<u8> {
        let mut v = Vec::<u8>::new();
        v.append(&mut self.type_.to_be_bytes().to_vec());
        v.append(&mut self.length.to_be_bytes().to_vec());
        v.append(&mut self.data.clone());
        v
    }
}

struct StunChangeRequestAttribute {
    type_: u16,
    length: u16,
    change_ip: bool,
    change_port: bool,
}

impl Into<Vec<u8>> for &StunChangeRequestAttribute {
    fn into(self) -> Vec<u8> {
        let mut v = Vec::<u8>::new();
        v.append(&mut self.type_.to_be_bytes().to_vec());
        v.append(&mut self.length.to_be_bytes().to_vec());
        let mut flags: u32 = 0;
        if self.change_ip {
            flags |= STUN_CHANGE_REQUEST_MASK_IP;
        }
        if self.change_port {
            flags |= STUN_CHANGE_REQUEST_MASK_PORT;
        }
        v.append(&mut flags.to_be_bytes().to_vec());
        v
    }
}
struct StunMappedAddressAttribute {
    type_: u16,
    length: u16,
    reserved: u8,
    protocol_family: u8,
    port: u16,
    ip: IpAddr,
}

impl StunMappedAddressAttribute {
    fn new(ip: IpAddr, port: u16) -> Self {
        StunMappedAddressAttribute {
            type_: STUN_ATTR_MAPPED_ADDRESS,
            length: 4 + if let IpAddr::V4(_) = ip { 4 } else { 16 },
            reserved: 0,
            protocol_family: if let IpAddr::V4(_) = ip {
                STUN_PROTOCOL_FAMILY_IPV4
            } else {
                STUN_PROTOCOL_FAMILY_IPV6
            },
            port: port,
            ip: ip,
        }
    }
}

impl Into<Vec<u8>> for &StunMappedAddressAttribute {
    fn into(self) -> Vec<u8> {
        let mut v = Vec::<u8>::new();
        v.append(&mut self.type_.to_be_bytes().to_vec());
        v.append(&mut self.length.to_be_bytes().to_vec());
        v.push(self.reserved);
        v.push(self.protocol_family);
        v.push(((self.port & 0xFF00) >> 8).try_into().unwrap());
        v.push((self.port & 0x00FF).try_into().unwrap());
        let mut ip = if let IpAddr::V4(ip) = self.ip {
            ip.octets().to_vec()
        } else if let IpAddr::V6(ip) = self.ip {
            ip.octets().to_vec()
        } else {
            Vec::new()
        };
        v.append(&mut ip);
        v
    }
}

enum StunAttribute {
    MappedAddress(StunMappedAddressAttribute),
    ChangeRequest(StunChangeRequestAttribute),
    Generic(StunGenericAttribute),
}

impl StunAttribute {
    fn len(&self) -> u16 {
        match self {
            StunAttribute::MappedAddress(s) => s.length,
            StunAttribute::ChangeRequest(s) => s.length,
            StunAttribute::Generic(s) => s.length,
        }
    }

    #[allow(dead_code)]
    fn type_(&self) -> u16 {
        match self {
            StunAttribute::MappedAddress(s) => s.type_,
            StunAttribute::ChangeRequest(s) => s.type_,
            StunAttribute::Generic(s) => s.type_,
        }
    }
}

impl From<Vec<u8>> for StunAttribute {
    fn from(v: Vec<u8>) -> Self {
        if v.len() < 4 {
            panic!("not enough data");
        }
        let type_ = BigEndian::read_u16(&v[0..2]);
        let length = BigEndian::read_u16(&v[2..4]);
        if v.len() < 4 + length as usize {
            panic!("not enough data");
        }
        match type_ {
            STUN_ATTR_MAPPED_ADDRESS => {
                let reserved = v[4];
                let protocol_family = v[5];
                let port = BigEndian::read_u16(&v[6..8]);
                StunAttribute::MappedAddress(StunMappedAddressAttribute {
                    type_,
                    length,
                    reserved,
                    protocol_family,
                    port,
                    ip: if protocol_family == STUN_PROTOCOL_FAMILY_IPV4 {
                        IpAddr::V4(Ipv4Addr::new(v[8], v[9], v[10], v[11]))
                    } else if protocol_family == STUN_PROTOCOL_FAMILY_IPV6 {
                        IpAddr::V6(Ipv6Addr::new(
                            BigEndian::read_u16(&v[8..10]),
                            BigEndian::read_u16(&v[10..12]),
                            BigEndian::read_u16(&v[12..14]),
                            BigEndian::read_u16(&v[14..16]),
                            BigEndian::read_u16(&v[16..18]),
                            BigEndian::read_u16(&v[18..20]),
                            BigEndian::read_u16(&v[20..22]),
                            BigEndian::read_u16(&v[22..24]),
                        ))
                    } else {
                        panic!("unexpected protocol family");
                    },
                })
            }
            STUN_ATTR_CHANGE_REQUEST => StunAttribute::ChangeRequest(StunChangeRequestAttribute {
                type_,
                length,
                change_ip: (BigEndian::read_u32(&v[4..8]) & STUN_CHANGE_REQUEST_MASK_IP)
                    == STUN_CHANGE_REQUEST_MASK_IP,
                change_port: (BigEndian::read_u32(&v[4..8]) & STUN_CHANGE_REQUEST_MASK_PORT)
                    == STUN_CHANGE_REQUEST_MASK_PORT,
            }),
            _ => StunAttribute::Generic(StunGenericAttribute {
                type_,
                length,
                data: v[4..].to_vec(),
            }),
        }
    }
}

impl Into<Vec<u8>> for &StunAttribute {
    fn into(self) -> Vec<u8> {
        match self {
            StunAttribute::Generic(s) => s.into(),
            StunAttribute::MappedAddress(s) => s.into(),
            StunAttribute::ChangeRequest(s) => s.into(),
        }
    }
}

struct StunPacket {
    class: u8,
    method: u16,
    length: u16,
    id: u128,
    data: Vec<u8>,
    attributes: Vec<StunAttribute>,
}

impl StunPacket {
    fn new(data: &[u8]) -> Result<Self, io::Error> {
        if data.len() < 20 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not enough data",
            ));
        }
        let class: u8 = ((data[0] & 0x01) << 1) | ((data[1] & 0x10) >> 4);
        let method: u16 = (((data[0] & 0b00111110) << 7) as u16) | ((data[1] & 0b11101111) as u16);
        let length: u16 = BigEndian::read_u16(&data[2..4]);
        let id: u128 = BigEndian::read_u128(&data[4..20]);
        if data.len() < 20 + length as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not enough data",
            ));
        }
        let data: Vec<u8> = data[20..(20 + length) as usize].to_vec();
        let mut stun = StunPacket {
            class,
            method,
            length,
            id,
            data,
            attributes: Vec::<StunAttribute>::new(),
        };
        stun.attributes = stun.get_attributes();
        Ok(stun)
    }

    fn empty() -> Self {
        StunPacket {
            class: 0,
            method: 0,
            length: 0,
            id: 0,
            data: Vec::new(),
            attributes: Vec::new(),
        }
    }

    fn get_attributes(&self) -> Vec<StunAttribute> {
        let mut i = 0;
        let mut attributes = Vec::<StunAttribute>::new();
        while i + 4 < self.data.len() {
            let attr = StunAttribute::from(self.data[i..].to_vec());
            i += 4 + attr.len() as usize;
            attributes.push(attr);
        }
        attributes
    }

    fn set_length(&mut self) {
        self.length = 0;
        for attr in &self.attributes {
            self.length += 4 + attr.len();
        }
    }
}

impl Into<Vec<u8>> for StunPacket {
    fn into(self) -> Vec<u8> {
        let mut v = Vec::<u8>::new();
        // first cocktail with class and method bits
        v.push(
            TryInto::<u8>::try_into((self.method >> 7) & 0b00111110).unwrap()
                | TryInto::<u8>::try_into((self.class & 0b10) >> 1).unwrap(),
        );
        // second cocktail with class and method bits
        v.push(
            TryInto::<u8>::try_into((self.method & 0b01110000) << 1).unwrap()
                | TryInto::<u8>::try_into((self.class & 0b01) << 4).unwrap()
                | TryInto::<u8>::try_into(self.method & 0b00001111).unwrap(),
        );
        v.append(&mut self.length.to_be_bytes().to_vec());
        v.append(&mut self.id.to_be_bytes().to_vec());
        for attr in &self.attributes {
            v.append(&mut attr.into());
        }
        v
    }
}

pub fn repl<'a>(
    data: &'a [u8],
    _masscanned: &Masscanned,
    mut client_info: &mut ClientInfo,
) -> Option<Vec<u8>> {
    debug!("receiving STUN data");
    let stun_req: StunPacket = if let Ok(s) = StunPacket::new(&data) {
        s
    } else {
        return None;
    };
    if stun_req.class != STUN_CLASS_REQUEST {
        info!(
            "STUN packet not handled (class unknown: 0b{:b})",
            stun_req.class
        );
        return None;
    }
    if stun_req.method != STUN_METHOD_BINDING {
        info!(
            "STUN packet not handled (method unknown: 0x{:03x})",
            stun_req.method
        );
        return None;
    }
    if client_info.ip.src == None {
        error!("STUN packet not handled (expected client ip address not found)");
        return None;
    }
    if client_info.port.src == None {
        error!("STUN packet not handled (expected client port address not found)");
        return None;
    }
    /* Change client_info if CHANGE_REQUEST was set by client */
    for attr in &stun_req.attributes {
        if let StunAttribute::ChangeRequest(a) = attr {
            if a.change_ip {}
            if a.change_port {
                client_info.port.dst = Some(client_info.port.dst.unwrap().wrapping_add(1));
            }
        }
    }
    let mut stun_resp: StunPacket = StunPacket::empty();
    stun_resp.class = STUN_CLASS_SUCCESS_RESPONSE;
    stun_resp.method = STUN_METHOD_BINDING;
    stun_resp.id = stun_req.id;
    stun_resp.attributes = Vec::<StunAttribute>::new();
    stun_resp.attributes.push(StunAttribute::MappedAddress(
        StunMappedAddressAttribute::new(client_info.ip.src.unwrap(), client_info.port.src.unwrap()),
    ));
    stun_resp.set_length();
    debug!("sending STUN answer");
    return Some(stun_resp.into());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::str::FromStr;

    use pnet::util::MacAddr;

    use crate::logger::MetaLogger;

    #[test]
    fn test_proto_stun_ipv4() {
        /* test payload is:
         * - bind request: 0x0001
         * - length: 0x0000
         * - magic cookie: 0x2112a442
         * - id: 0xaabbccddeeffffeeddccbbaa
         * - message: empty
         */
        let payload =
            b"\x00\x01\x00\x00\x21\x12\xa4\x42\xaa\xbb\xcc\xdd\xee\xff\xff\xee\xdd\xcc\xbb\xaa";
        let mut client_info = ClientInfo::new();
        let test_ip_addr = Ipv4Addr::new(3, 2, 1, 0);
        let masscanned_ip_addr = Ipv4Addr::new(0, 1, 2, 3);
        client_info.ip.src = Some(IpAddr::V4(test_ip_addr));
        client_info.ip.dst = Some(IpAddr::V4(masscanned_ip_addr));
        client_info.port.src = Some(55000);
        client_info.port.dst = Some(65000);
        let mut ips = HashSet::new();
        ips.insert(IpAddr::V4(masscanned_ip_addr));
        /* Construct masscanned context object */
        let masscanned = Masscanned {
            synack_key: [0, 0],
            mac: MacAddr::from_str("00:11:22:33:44:55").expect("error parsing MAC address"),
            iface: None,
            ip_addresses: Some(&ips),
            log: MetaLogger::new(),
        };
        let payload_resp = if let Some(r) = repl(payload, &masscanned, &mut client_info) {
            r
        } else {
            panic!("expected an answer, got None");
        };
        let stun_resp = StunPacket::new(&payload_resp).unwrap();
        assert!(stun_resp.class == STUN_CLASS_SUCCESS_RESPONSE);
        assert!(stun_resp.method == STUN_METHOD_BINDING);
        assert!(
            stun_resp.id
                == BigEndian::read_u128(
                    b"\x21\x12\xa4\x42\xaa\xbb\xcc\xdd\xee\xff\xff\xee\xdd\xcc\xbb\xaa"
                )
        );
        assert!(stun_resp.attributes.len() == 1);
        if let StunAttribute::MappedAddress(attr) = &stun_resp.attributes[0] {
            assert!(attr.type_ == STUN_ATTR_MAPPED_ADDRESS);
            assert!(attr.length == 8);
            assert!(attr.reserved == 0);
            assert!(attr.protocol_family == STUN_PROTOCOL_FAMILY_IPV4);
            assert!(attr.port == client_info.port.src.unwrap());
            assert!(attr.ip == client_info.ip.src.unwrap());
        } else {
            panic!("expected MappedAddress attribute");
        }
        /* Check that client_info was not modified */
        assert!(client_info.ip.src == Some(IpAddr::V4(test_ip_addr)));
        assert!(client_info.ip.dst == Some(IpAddr::V4(masscanned_ip_addr)));
        assert!(client_info.port.src == Some(55000));
        assert!(client_info.port.dst == Some(65000));
    }

    #[test]
    fn test_proto_stun_ipv6() {
        /* test payload is:
         * - bind request: 0x0001
         * - length: 0x0000
         * - magic cookie: 0x2112a442
         * - id: 0xaabbccddeeffffeeddccbbaa
         * - message: empty
         */
        let payload =
            b"\x00\x01\x00\x00\x21\x12\xa4\x42\xaa\xbb\xcc\xdd\xee\xff\xff\xee\xdd\xcc\xbb\xaa";
        let mut client_info = ClientInfo::new();
        let test_ip_addr = Ipv6Addr::new(
            0x7777, 0x6666, 0x5555, 0x4444, 0x3333, 0x2222, 0x1111, 0x0000,
        );
        let masscanned_ip_addr = Ipv6Addr::new(
            0x0000, 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777,
        );
        let mut ips = HashSet::new();
        ips.insert(IpAddr::V6(masscanned_ip_addr));
        /* Construct masscanned context object */
        let masscanned = Masscanned {
            synack_key: [0, 0],
            mac: MacAddr::from_str("00:11:22:33:44:55").expect("error parsing MAC address"),
            iface: None,
            ip_addresses: Some(&ips),
            log: MetaLogger::new(),
        };
        client_info.ip.src = Some(IpAddr::V6(test_ip_addr));
        client_info.ip.dst = Some(IpAddr::V6(masscanned_ip_addr));
        client_info.port.src = Some(55000);
        client_info.port.dst = Some(65000);
        let payload_resp = if let Some(r) = repl(payload, &masscanned, &mut client_info) {
            r
        } else {
            panic!("expected an answer, got None");
        };
        let stun_resp = StunPacket::new(&payload_resp).unwrap();
        assert!(stun_resp.class == STUN_CLASS_SUCCESS_RESPONSE);
        assert!(stun_resp.method == STUN_METHOD_BINDING);
        assert!(
            stun_resp.id
                == BigEndian::read_u128(
                    b"\x21\x12\xa4\x42\xaa\xbb\xcc\xdd\xee\xff\xff\xee\xdd\xcc\xbb\xaa"
                )
        );
        assert!(stun_resp.attributes.len() == 1);
        if let StunAttribute::MappedAddress(attr) = &stun_resp.attributes[0] {
            assert!(attr.type_ == STUN_ATTR_MAPPED_ADDRESS);
            assert!(attr.length == 20);
            assert!(attr.reserved == 0);
            assert!(attr.protocol_family == STUN_PROTOCOL_FAMILY_IPV6);
            assert!(attr.port == client_info.port.src.unwrap());
            assert!(attr.ip == client_info.ip.src.unwrap());
        } else {
            panic!("expected MappedAddress attribute");
        }
        /* Check that client_info was not modified */
        assert!(client_info.ip.src == Some(IpAddr::V6(test_ip_addr)));
        assert!(client_info.ip.dst == Some(IpAddr::V6(masscanned_ip_addr)));
        assert!(client_info.port.src == Some(55000));
        assert!(client_info.port.dst == Some(65000));
    }

    #[test]
    fn test_change_request_port() {
        let payload = b"\x00\x01\x00\x08\x03\xa3\xb9FM\xd8\xebu\xe1\x94\x81GB\x93\x84\\\x00\x03\x00\x04\x00\x00\x00\x02";
        let mut client_info = ClientInfo::new();
        let test_ip_addr = Ipv4Addr::new(3, 2, 1, 0);
        let masscanned_ip_addr = Ipv4Addr::new(0, 1, 2, 3);
        let mut ips = HashSet::new();
        ips.insert(IpAddr::V4(masscanned_ip_addr));
        /* Construct masscanned context object */
        let masscanned = Masscanned {
            synack_key: [0, 0],
            mac: MacAddr::from_str("00:11:22:33:44:55").expect("error parsing MAC address"),
            iface: None,
            ip_addresses: Some(&ips),
            log: MetaLogger::new(),
        };
        client_info.ip.src = Some(IpAddr::V4(test_ip_addr));
        client_info.ip.dst = Some(IpAddr::V4(masscanned_ip_addr));
        client_info.port.src = Some(55000);
        client_info.port.dst = Some(65000);
        let payload_resp = if let Some(r) = repl(payload, &masscanned, &mut client_info) {
            r
        } else {
            panic!("expected an answer, got None");
        };
        let stun_resp = StunPacket::new(&payload_resp).unwrap();
        assert!(stun_resp.class == STUN_CLASS_SUCCESS_RESPONSE);
        assert!(stun_resp.method == STUN_METHOD_BINDING);
        assert!(
            stun_resp.id
                == BigEndian::read_u128(b"\x03\xa3\xb9FM\xd8\xebu\xe1\x94\x81GB\x93\x84\\")
        );
        assert!(stun_resp.attributes.len() == 1);
        if let StunAttribute::MappedAddress(attr) = &stun_resp.attributes[0] {
            assert!(attr.type_ == STUN_ATTR_MAPPED_ADDRESS);
            assert!(attr.length == 8);
            assert!(attr.reserved == 0);
            assert!(attr.protocol_family == STUN_PROTOCOL_FAMILY_IPV4);
            assert!(attr.port == client_info.port.src.unwrap());
            assert!(attr.ip == client_info.ip.src.unwrap());
        } else {
            panic!("expected MappedAddress attribute");
        }
        /* Check that client_info was not modified */
        assert!(client_info.ip.src == Some(IpAddr::V4(test_ip_addr)));
        assert!(client_info.ip.dst == Some(IpAddr::V4(masscanned_ip_addr)));
        assert!(client_info.port.src == Some(55000));
        assert!(client_info.port.dst == Some(65001));
    }

    #[test]
    fn test_change_request_port_overflow() {
        let payload = b"\x00\x01\x00\x08\x03\xa3\xb9FM\xd8\xebu\xe1\x94\x81GB\x93\x84\\\x00\x03\x00\x04\x00\x00\x00\x02";
        let mut client_info = ClientInfo::new();
        let test_ip_addr = Ipv4Addr::new(3, 2, 1, 0);
        let masscanned_ip_addr = Ipv4Addr::new(0, 1, 2, 3);
        let mut ips = HashSet::new();
        ips.insert(IpAddr::V4(masscanned_ip_addr));
        /* Construct masscanned context object */
        let masscanned = Masscanned {
            synack_key: [0, 0],
            mac: MacAddr::from_str("00:11:22:33:44:55").expect("error parsing MAC address"),
            iface: None,
            ip_addresses: Some(&ips),
            log: MetaLogger::new(),
        };
        client_info.ip.src = Some(IpAddr::V4(test_ip_addr));
        client_info.ip.dst = Some(IpAddr::V4(masscanned_ip_addr));
        client_info.port.src = Some(55000);
        client_info.port.dst = Some(65535);
        let payload_resp = if let Some(r) = repl(payload, &masscanned, &mut client_info) {
            r
        } else {
            panic!("expected an answer, got None");
        };
        let stun_resp = StunPacket::new(&payload_resp).unwrap();
        assert!(stun_resp.class == STUN_CLASS_SUCCESS_RESPONSE);
        assert!(stun_resp.method == STUN_METHOD_BINDING);
        assert!(
            stun_resp.id
                == BigEndian::read_u128(b"\x03\xa3\xb9FM\xd8\xebu\xe1\x94\x81GB\x93\x84\\")
        );
        assert!(stun_resp.attributes.len() == 1);
        if let StunAttribute::MappedAddress(attr) = &stun_resp.attributes[0] {
            assert!(attr.type_ == STUN_ATTR_MAPPED_ADDRESS);
            assert!(attr.length == 8);
            assert!(attr.reserved == 0);
            assert!(attr.protocol_family == STUN_PROTOCOL_FAMILY_IPV4);
            assert!(attr.port == client_info.port.src.unwrap());
            assert!(attr.ip == client_info.ip.src.unwrap());
        } else {
            panic!("expected MappedAddress attribute");
        }
        /* Check that client_info was not modified */
        assert!(client_info.ip.src == Some(IpAddr::V4(test_ip_addr)));
        assert!(client_info.ip.dst == Some(IpAddr::V4(masscanned_ip_addr)));
        assert!(client_info.port.src == Some(55000));
        assert!(client_info.port.dst == Some(0));
    }
}
