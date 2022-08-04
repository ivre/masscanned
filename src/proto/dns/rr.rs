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

use std::convert::TryFrom;

use crate::proto::dissector::{MPacket, PacketDissector};
use crate::proto::ClientInfo;
use crate::proto::TCPControlBlock;
use crate::Masscanned;

#[derive(PartialEq, Debug)]
pub enum DNSRRState {
    Name,
    Type,
    Class,
    TTL,
    RDLength,
    RData,
    End,
}

pub struct DNSRR {
    pub d: PacketDissector<DNSRRState>,
    /* RFC 1035 - Section 3.2.1 */
    pub name: Vec<u8>,
    _u_type: u16,
    pub type_: DNSType,
    _u_class: u16,
    pub class: DNSClass,
    pub ttl: u32,
    pub rdlen: u16,
    pub rdata: Vec<u8>,
}

impl From<&DNSRR> for Vec<u8> {
    fn from(item: &DNSRR) -> Self {
        /* CAUTION: for the rdlen field:
         * - if item.rdlen is not 0, its value is packed
         * - if item.rdlen = 0, then the length of item.rdata is used instead
         */
        let mut v = Vec::new();
        /* name */
        for b in &item.name {
            v.push(b.clone());
        }
        /* type */
        let type_: u16 = item.type_.into();
        v.push((type_ >> 8) as u8);
        v.push((type_ & 0xFF) as u8);
        /* class */
        let class: u16 = item.class.into();
        v.push((class >> 8) as u8);
        v.push((class & 0xFF) as u8);
        /* ttl */
        v.push((item.ttl >> 24) as u8);
        v.push((item.ttl >> 16) as u8);
        v.push((item.ttl >> 8) as u8);
        v.push((item.ttl & 0xFF) as u8);
        /* rdlen */
        let rdlen = if item.rdlen == 0 {
            item.rdata.len() as u16
        } else {
            item.rdlen
        };
        v.push((rdlen >> 8) as u8);
        v.push((rdlen & 0xFF) as u8);
        /* rdata */
        for b in &item.rdata {
            v.push(b.clone());
        }
        v
    }
}

impl TryFrom<Vec<u8>> for DNSRR {
    type Error = &'static str;

    fn try_from(item: Vec<u8>) -> Result<Self, Self::Error> {
        let mut rr = DNSRR::new();
        for b in item {
            rr.parse(&b);
        }
        if rr.d.state == DNSRRState::End {
            Ok(rr)
        } else {
            Err("packet is incomplete")
        }
    }
}

impl MPacket for DNSRR {
    fn new() -> Self {
        DNSRR {
            d: PacketDissector::new(DNSRRState::Name),
            name: Vec::new(),
            _u_type: 0,
            type_: DNSType::NONE,
            _u_class: 0,
            class: DNSClass::NONE,
            rdlen: 0,
            ttl: 0,
            rdata: Vec::new(),
        }
    }

    fn parse(&mut self, byte: &u8) {
        match self.d.state {
            DNSRRState::Name => {
                self.name.push(*byte);
                if *byte == 0 {
                    self.d.next_state(DNSRRState::Type);
                }
            }
            DNSRRState::Type => {
                self._u_type = self.d.read_u16(byte, self._u_type, DNSRRState::Class);
            }
            DNSRRState::Class => {
                self._u_class = self.d.read_u16(byte, self._u_class, DNSRRState::TTL);
            }
            DNSRRState::TTL => {
                self.ttl = self.d.read_u32(byte, self.ttl, DNSRRState::RDLength);
            }
            DNSRRState::RDLength => {
                self.rdlen = self.d.read_u16(byte, self.rdlen, DNSRRState::RData);
                /* when read the rdlen, check if len is 0 */
                if self.d.state == DNSRRState::RData && self.rdlen == 0 {
                    self.d.state = DNSRRState::End;
                }
            }
            DNSRRState::RData => {
                self.rdata.push(*byte);
                if self.rdata.len() == self.rdlen as usize {
                    self.d.next_state(DNSRRState::End);
                }
            }
            DNSRRState::End => {}
        }
        /* we need this to be executed at the same call
         * the state changes to End, hence it is not in the
         * match structure
         **/
        if self.d.state == DNSRRState::End {
            self.type_ = DNSType::from(self._u_type);
            self.class = DNSClass::from(self._u_class);
        }
    }

    fn repl(
        &self,
        _masscanned: &Masscanned,
        _client_info: &ClientInfo,
        _tcb: Option<&mut TCPControlBlock>,
    ) -> Option<Vec<u8>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build() {
        let mut rr = DNSRR::new();
        rr.name = b"\x03www\x07example\x03com\x00".to_vec();
        rr.class = DNSClass::IN;
        rr.type_ = DNSType::A;
        rr.ttl = 1234;
        rr.rdlen = 4;
        rr.rdata = b"\x7f\x00\x00\x01".to_vec();
        assert!(Vec::<u8>::from(&rr) == b"\x03www\x07example\x03com\x00\x00\x01\x00\x01\x00\x00\x04\xd2\x00\x04\x7f\x00\x00\x01");
    }

    #[test]
    fn parse_all() {
        /*
         * raw(DNSRR(rrname="www.example.com", rdata="127.0.0.1"))
         */
        let payload = b"\x03www\x07example\x03com\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\x7f\x00\x00\x01";
        let rr = match DNSRR::try_from(payload.to_vec()) {
            Ok(r) => r,
            Err(e) => panic!("error while parsing DNS RR: {}", e),
        };
        assert!(rr.name == b"\x03www\x07example\x03com\x00");
        assert!(rr.class == DNSClass::IN);
        assert!(rr.type_ == DNSType::A);
        assert!(rr.rdata == b"\x7f\x00\x00\x01");
        assert!(Vec::<u8>::from(&rr) == payload.to_vec());
        /*
         * empty data
         */
        let payload = b"\x03www\x07example\x03com\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x00";
        let rr = match DNSRR::try_from(payload.to_vec()) {
            Ok(r) => r,
            Err(e) => panic!("error while parsing DNS RR: {}", e),
        };
        assert!(rr.name == b"\x03www\x07example\x03com\x00");
        assert!(rr.class == DNSClass::IN);
        assert!(rr.type_ == DNSType::A);
        assert!(rr.rdata == b"");
        assert!(Vec::<u8>::from(&rr) == payload.to_vec());
    }

    #[test]
    fn parse_byte_by_byte() {
        /*
         * raw(DNSRR(rrname="www.example.com", rdata="127.0.0.1"))
         */
        let payload = b"\x03www\x07example\x03com\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\x7f\x00\x00\x01";
        let mut rr = DNSRR::new();
        for b in payload {
            assert!(rr.d.state != DNSRRState::End);
            rr.parse(b);
        }
        assert!(rr.d.state == DNSRRState::End);
        assert!(rr.name == b"\x03www\x07example\x03com\x00");
        assert!(rr.class == DNSClass::IN);
        assert!(rr.type_ == DNSType::A);
        assert!(rr.rdata == b"\x7f\x00\x00\x01");
        assert!(Vec::<u8>::from(&rr) == payload.to_vec());
        /*
         * empty data
         */
        let payload = b"\x03www\x07example\x03com\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x00";
        let mut rr = DNSRR::new();
        for b in payload {
            assert!(rr.d.state != DNSRRState::End);
            rr.parse(b);
        }
        assert!(rr.name == b"\x03www\x07example\x03com\x00");
        assert!(rr.class == DNSClass::IN);
        assert!(rr.type_ == DNSType::A);
        assert!(rr.rdata == b"");
        assert!(Vec::<u8>::from(&rr) == payload.to_vec());
    }
}
