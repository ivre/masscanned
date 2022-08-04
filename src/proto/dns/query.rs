// This file is part of masscanned.
// Copyright 2022 - The IVRE project
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

use super::cst::{DNSClass, DNSType};
use super::rr::DNSRR;

use std::convert::TryFrom;
use std::net::IpAddr;

use crate::proto::dissector::{MPacket, PacketDissector};
use crate::proto::ClientInfo;
use crate::proto::TCPControlBlock;
use crate::Masscanned;

#[derive(PartialEq)]
pub enum DNSQueryState {
    Name,
    Type,
    Class,
    End,
}

pub struct DNSQuery {
    pub d: PacketDissector<DNSQueryState>,
    /* RFC 1035 - Section 4.1.2 */
    pub name: Vec<u8>,
    _u_type: u16,
    pub type_: DNSType,
    _u_class: u16,
    pub class: DNSClass,
}

impl TryFrom<Vec<u8>> for DNSQuery {
    type Error = &'static str;

    fn try_from(item: Vec<u8>) -> Result<Self, Self::Error> {
        let mut query = DNSQuery::new();
        for b in item {
            query.parse(&b);
        }
        if query.d.state == DNSQueryState::End {
            Ok(query)
        } else {
            Err("packet is incomplete")
        }
    }
}

impl From<&DNSQuery> for Vec<u8> {
    fn from(item: &DNSQuery) -> Self {
        let mut v = Vec::new();
        /* name */
        v.extend(&item.name);
        /* type */
        v.push(((u16::from(item.type_)) >> 8) as u8);
        v.push(((u16::from(item.type_)) & 0xFF) as u8);
        /* class */
        v.push(((u16::from(item.class)) >> 8) as u8);
        v.push(((u16::from(item.class)) & 0xFF) as u8);
        /* return */
        v
    }
}

impl MPacket for DNSQuery {
    fn new() -> Self {
        DNSQuery {
            d: PacketDissector::new(DNSQueryState::Name),
            name: Vec::new(),
            _u_type: 0,
            type_: DNSType::NONE,
            _u_class: 0,
            class: DNSClass::NONE,
        }
    }

    fn parse(&mut self, byte: &u8) {
        match self.d.state {
            DNSQueryState::Name => {
                self.name.push(*byte);
                if *byte == 0 {
                    self.d.next_state(DNSQueryState::Type);
                }
            }
            DNSQueryState::Type => {
                self._u_type = self.d.read_u16(byte, self._u_type, DNSQueryState::Class);
            }
            DNSQueryState::Class => {
                self._u_class = self.d.read_u16(byte, self._u_class, DNSQueryState::End);
            }
            DNSQueryState::End => {}
        }
        /* we need this to be executed at the same call
         * the state changes to End, hence it is not in the
         * match structure
         **/
        if self.d.state == DNSQueryState::End {
            self.type_ = DNSType::from(self._u_type);
            self.class = DNSClass::from(self._u_class);
        }
    }

    fn repl(
        &self,
        _masscanned: &Masscanned,
        client_info: &ClientInfo,
        _tcb: Option<&mut TCPControlBlock>,
    ) -> Option<Vec<u8>> {
        match self.class {
            DNSClass::IN => {
                match self.type_ {
                    DNSType::A => {
                        let mut rr = DNSRR::new();
                        /* copy request */
                        for b in &self.name {
                            rr.name.push(*b);
                        }
                        rr.type_ = DNSType::A;
                        rr.class = DNSClass::IN;
                        rr.ttl = 43200;
                        rr.rdata = match client_info.ip.dst {
                            Some(IpAddr::V4(ip)) => ip.octets().to_vec(),
                            Some(IpAddr::V6(_)) => Vec::new(),
                            None => Vec::new(),
                        };
                        rr.rdlen = rr.rdata.len() as u16;
                        Some(Vec::<u8>::from(&rr))
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use pnet::util::MacAddr;
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;
    use strum::IntoEnumIterator;

    use crate::client::ClientInfoSrcDst;
    use crate::logger::MetaLogger;

    #[test]
    fn parse_in_a_all() {
        /* A */
        let payload = b"\x03www\x07example\x03com\x00\x00\x01\x00\x01";
        let qr = match DNSQuery::try_from(payload.to_vec()) {
            Ok(_qr) => _qr,
            Err(e) => panic!("error while parsing DNS query: {}", e),
        };
        assert!(
            qr.name
                == [
                    0x03, 0x77, 0x77, 0x77, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03,
                    0x63, 0x6f, 0x6d, 0x00
                ]
        );
        assert!(qr.type_ == DNSType::A);
        assert!(qr.class == DNSClass::IN);
        assert!(Vec::<u8>::from(&qr) == payload.to_vec());
        /* TXT */
        let payload = b"\x07version\x04bind\x00\x00\x10\x00\x03";
        let qr = match DNSQuery::try_from(payload.to_vec()) {
            Ok(_qr) => _qr,
            Err(e) => panic!("error while parsing DNS query: {}", e),
        };
        assert!(qr.type_ == DNSType::TXT);
        assert!(qr.class == DNSClass::CH);
        assert!(Vec::<u8>::from(&qr) == payload.to_vec());
        /* KO */
        let payload = b"xxx";
        match DNSQuery::try_from(payload.to_vec()) {
            Ok(_) => panic!("parsing should have failed"),
            Err(_) => {}
        }
    }

    #[test]
    fn parse_in_a_byte_by_byte() {
        /* A */
        let payload = b"\x03www\x07example\x03com\x00\x00\x01\x00\x01";
        let mut qr = DNSQuery::new();
        for b in payload {
            qr.parse(b);
        }
        assert!(qr.d.state == DNSQueryState::End);
        assert!(
            qr.name
                == [
                    0x03, 0x77, 0x77, 0x77, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03,
                    0x63, 0x6f, 0x6d, 0x00
                ]
        );
        assert!(qr.type_ == DNSType::A);
        assert!(qr.class == DNSClass::IN);
        assert!(Vec::<u8>::from(&qr) == payload.to_vec());
        /* TXT */
        let payload = b"\x07version\x04bind\x00\x00\x10\x00\x03";
        let mut qr = DNSQuery::new();
        for b in payload {
            qr.parse(b);
        }
        assert!(qr.d.state == DNSQueryState::End);
        assert!(qr.type_ == DNSType::TXT);
        assert!(qr.class == DNSClass::CH);
        assert!(Vec::<u8>::from(&qr) == payload.to_vec());
        /* KO */
        let payload = b"xxx";
        let mut qr = DNSQuery::new();
        for b in payload {
            qr.parse(b);
        }
        assert!(qr.d.state != DNSQueryState::End);
    }

    #[test]
    fn reply_in_a() {
        let masscanned = Masscanned {
            synack_key: [0, 0],
            mac: MacAddr::from_str("00:00:00:00:00:00").expect("error parsing default MAC address"),
            iface: None,
            ip_addresses: None,
            log: MetaLogger::new(),
        };
        let ip_src = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let ip_dst = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        let client_info = ClientInfo {
            mac: ClientInfoSrcDst {
                src: None,
                dst: None,
            },
            ip: ClientInfoSrcDst {
                src: Some(ip_src),
                dst: Some(ip_dst),
            },
            transport: None,
            port: ClientInfoSrcDst {
                src: None,
                dst: None,
            },
            cookie: None,
        };
        /* TXT */
        let payload = b"\x07version\x04bind\x00\x00\x10\x00\x03";
        let mut qr = DNSQuery::new();
        for b in payload {
            qr.parse(b);
        }
        assert!(qr.type_ == DNSType::TXT);
        assert!(qr.class == DNSClass::CH);
        /* A */
        let payload = b"\x03www\x07example\x03com\x00\x00\x01\x00\x01";
        let mut qr = DNSQuery::new();
        for b in payload {
            qr.parse(b);
        }
        assert!(
            qr.name
                == [
                    0x03, 0x77, 0x77, 0x77, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03,
                    0x63, 0x6f, 0x6d, 0x00
                ]
        );
        assert!(qr.type_ == DNSType::A);
        assert!(qr.class == DNSClass::IN);
        let rr_raw = match qr.repl(&masscanned, &client_info, None) {
            None => {
                panic!()
            }
            Some(r) => r,
        };
        let mut rr = DNSRR::new();
        for b in rr_raw {
            rr.parse(&b);
        }
        assert!(rr.name == qr.name);
        assert!(rr.type_ == DNSType::A);
        assert!(rr.class == DNSClass::IN);
        assert!(rr.ttl == 43200);
        assert!(rr.rdata == [127, 0, 0, 2]);
    }

    #[test]
    fn repl() {
        let masscanned = Masscanned {
            synack_key: [0, 0],
            mac: MacAddr::from_str("00:00:00:00:00:00").expect("error parsing default MAC address"),
            iface: None,
            ip_addresses: None,
            log: MetaLogger::new(),
        };
        let client_info = ClientInfo::new();
        /* exhaustive tests */
        let supported: Vec<(DNSClass, DNSType)> = vec![(DNSClass::IN, DNSType::A)];
        let mut qd = DNSQuery::new();
        qd.name = vec![
            0x03, 0x77, 0x77, 0x77, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63,
            0x6f, 0x6d, 0x00,
        ];
        for c in DNSClass::iter() {
            qd.class = c;
            for t in DNSType::iter() {
                qd.type_ = t;
                if supported.contains(&(c, t)) {
                    if qd.repl(&masscanned, &client_info, None) == None {
                        panic!("expected reply, got None");
                    }
                } else {
                    if qd.repl(&masscanned, &client_info, None) != None {
                        panic!("expected no reply, got one for {:?}, {:?}", c, t);
                    }
                }
            }
        }
    }
}
