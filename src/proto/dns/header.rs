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

use std::convert::TryFrom;

use crate::proto::dissector::{MPacket, PacketDissector};
use crate::proto::ClientInfo;
use crate::proto::TCPControlBlock;
use crate::Masscanned;

#[derive(PartialEq)]
pub enum DNSHeaderState {
    Id,
    Flags,
    QDCount,
    ANCount,
    NSCount,
    ARCount,
    End,
}

pub struct DNSHeader {
    pub d: PacketDissector<DNSHeaderState>,
    pub id: u16,
    pub flags: u16,
    pub _qr: bool,
    pub _opcode: u8,
    pub _aa: bool,
    pub _tc: bool,
    pub _rd: bool,
    pub _ra: bool,
    pub _z: u8,
    pub _rcode: u8,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl TryFrom<Vec<u8>> for DNSHeader {
    type Error = &'static str;

    fn try_from(item: Vec<u8>) -> Result<Self, Self::Error> {
        let mut hdr = DNSHeader::new();
        for b in item {
            hdr.parse(&b);
        }
        if hdr.d.state == DNSHeaderState::End {
            Ok(hdr)
        } else {
            Err("packet is incomplete")
        }
    }
}

impl From<&DNSHeader> for Vec<u8> {
    fn from(item: &DNSHeader) -> Self {
        let mut v = Vec::new();
        /* id */
        v.push((item.id >> 8) as u8);
        v.push((item.id & 0xFF) as u8);

        /* flags */
        /* QR | OPCODE | AA | TC | RD */
        v.push(
            ((item._qr as u8) << 7)
                | (item._opcode << 3)
                | ((item._aa as u8) << 2)
                | ((item._tc as u8) << 1)
                | (item._rd as u8),
        );
        /* AA | ZZZ | RCODE */
        v.push(0);

        /* qdcount */
        v.push((item.qdcount >> 8) as u8);
        v.push((item.qdcount & 0xFF) as u8);

        /* ancount */
        v.push((item.ancount >> 8) as u8);
        v.push((item.ancount & 0xFF) as u8);

        /* nscount */
        v.push((item.nscount >> 8) as u8);
        v.push((item.nscount & 0xFF) as u8);

        /* arcount */
        v.push((item.arcount >> 8) as u8);
        v.push((item.arcount & 0xFF) as u8);

        v
    }
}

impl MPacket for DNSHeader {
    fn new() -> Self {
        DNSHeader {
            d: PacketDissector::new(DNSHeaderState::Id),
            id: 0,
            flags: 0,
            _qr: false,
            _opcode: 0,
            _aa: false,
            _tc: false,
            _rd: false,
            _ra: false,
            _z: 0,
            _rcode: 0,
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }

    fn parse(&mut self, byte: &u8) {
        match self.d.state {
            DNSHeaderState::Id => {
                self.id = self.d.read_u16(byte, self.id, DNSHeaderState::Flags);
            }
            DNSHeaderState::Flags => {
                self.flags = self.d.read_u16(byte, self.flags, DNSHeaderState::QDCount);
            }
            DNSHeaderState::QDCount => {
                self.qdcount = self.d.read_u16(byte, self.qdcount, DNSHeaderState::ANCount);
            }
            DNSHeaderState::ANCount => {
                self.ancount = self.d.read_u16(byte, self.ancount, DNSHeaderState::NSCount);
            }
            DNSHeaderState::NSCount => {
                self.nscount = self.d.read_u16(byte, self.nscount, DNSHeaderState::ARCount);
            }
            DNSHeaderState::ARCount => {
                self.arcount = self.d.read_u16(byte, self.arcount, DNSHeaderState::End);
            }
            DNSHeaderState::End => {}
        }
        /* we need this to be executed at the same call
         * the state changes to End, hence it is not in the
         * match structure
         **/
        if self.d.state == DNSHeaderState::End {
            self._qr = (self.flags >> 15) == 1;
            self._opcode = ((self.flags >> 11) & 0x0F) as u8;
            self._aa = (self.flags >> 10) & 0x01 == 1;
            self._tc = (self.flags >> 9) & 0x01 == 1;
            self._rd = (self.flags >> 8) & 0x01 == 1;
            self._ra = (self.flags >> 7) & 0x01 == 1;
            self._z = ((self.flags >> 4) & 0x07) as u8;
            self._rcode = (self.flags & 0x0F) as u8;
        }
    }

    fn repl(
        &self,
        _masscanned: &Masscanned,
        _client_info: &ClientInfo,
        _tcb: Option<&mut TCPControlBlock>,
    ) -> Option<Vec<u8>> {
        let mut r = DNSHeader::new();
        r.id = self.id;
        r._qr = true;
        r._opcode = self._opcode;
        r._aa = true;
        r._tc = false;
        /*  RFC1035
         *  Recursion Desired - this bit may be set in a query and
         *      is copied into the response. */
        r._rd = self._rd;
        r._ra = false;
        r.qdcount = self.qdcount;
        r.ancount = self.qdcount;
        Some(Vec::<u8>::from(&r))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use pnet::util::MacAddr;
    use std::str::FromStr;

    use crate::logger::MetaLogger;

    #[test]
    fn parse_all() {
        let payload = b"\xb3\x07\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00";
        let hdr = match DNSHeader::try_from(payload.to_vec()) {
            Ok(_hdr) => _hdr,
            Err(e) => panic!("error while parsing DNS header: {}", e),
        };
        assert!(hdr.d.state == DNSHeaderState::End);
        assert!(hdr.id == 0xb307);
        assert!(hdr.flags == 0x0100);
        assert!(hdr._qr == false);
        assert!(hdr._opcode == 0);
        assert!(hdr._aa == false);
        assert!(hdr._tc == false);
        assert!(hdr._rd == true);
        assert!(hdr._ra == false);
        assert!(hdr._z == 0);
        assert!(hdr._rcode == 0);
        assert!(hdr.qdcount == 1);
        assert!(hdr.ancount == 0);
        assert!(hdr.nscount == 0);
        assert!(hdr.arcount == 0);
        assert!(Vec::<u8>::from(&hdr) == payload.to_vec());
        /* KO */
        let payload = b"\xb3\x07\x01\x00\x00\x01\x00\x00\x00\x00\x00";
        match DNSHeader::try_from(payload.to_vec()) {
            Ok(_) => panic!("parsing should have failed"),
            Err(_) => {}
        };
    }

    #[test]
    fn parse_byte_by_byte() {
        /* OK */
        let payload = b"\xb3\x07\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00";
        let mut hdr = DNSHeader::new();
        for b in payload {
            assert!(hdr.d.state != DNSHeaderState::End);
            hdr.parse(b);
        }
        assert!(hdr.d.state == DNSHeaderState::End);
        assert!(hdr.id == 0xb307);
        assert!(hdr.flags == 0x0100);
        assert!(hdr._qr == false);
        assert!(hdr._opcode == 0);
        assert!(hdr._aa == false);
        assert!(hdr._tc == false);
        assert!(hdr._rd == true);
        assert!(hdr._ra == false);
        assert!(hdr._z == 0);
        assert!(hdr._rcode == 0);
        assert!(hdr.qdcount == 1);
        assert!(hdr.ancount == 0);
        assert!(hdr.nscount == 0);
        assert!(hdr.arcount == 0);
        assert!(Vec::<u8>::from(&hdr) == payload.to_vec());
        /* KO */
        let payload = b"\xb3\x07\x01\x00\x00\x01\x00\x00\x00\x00\x00";
        let mut hdr = DNSHeader::new();
        for b in payload {
            hdr.parse(b);
        }
        assert!(hdr.d.state != DNSHeaderState::End);
    }

    fn consistency_qd_rr(qd: &DNSHeader, rr: &DNSHeader) {
        assert!(rr.id == qd.id);
        assert!(rr._qr == true);
        assert!(rr._opcode == qd._opcode);
        assert!(rr._aa == true);
        assert!(rr._tc == false);
        assert!(rr._rd == qd._rd);
        assert!(rr._ra == false);
        assert!(rr._z == 0);
        assert!(rr._rcode == 0);
        /* check flags */
        assert!(rr.flags >> 15 == rr._qr as u16);
        assert!((rr.flags >> 11) & 0xF == rr._opcode as u16);
        assert!((rr.flags >> 10) & 0x1 == rr._aa as u16);
        assert!((rr.flags >> 9) & 0x1 == rr._tc as u16);
        assert!((rr.flags >> 8) & 0x1 == rr._rd as u16);
        assert!((rr.flags >> 7) & 0x1 == rr._ra as u16);
        assert!((rr.flags >> 4) & 0x7 == rr._z as u16);
        assert!(rr.flags & 0xF == rr._rcode as u16);
        assert!(rr.qdcount == qd.qdcount);
        assert!(rr.ancount == qd.qdcount);
        assert!(rr.nscount == 0);
        assert!(rr.arcount == 0);
    }

    #[test]
    fn repl_id() {
        let masscanned = Masscanned {
            synack_key: [0, 0],
            mac: MacAddr::from_str("00:00:00:00:00:00").expect("error parsing default MAC address"),
            iface: None,
            ip_addresses: None,
            ignored_ip_addresses: None,
            log: MetaLogger::new(),
        };
        let client_info = ClientInfo::new();
        let mut hdr = DNSHeader::new();
        hdr._qr = false;
        for id in [0x1234, 0x4321, 0xffff, 0x0, 0x1337] {
            hdr.id = id;
            let hdr_repl = if let Some(r) = hdr.repl(&masscanned, &client_info, None) {
                DNSHeader::try_from(r).unwrap()
            } else {
                panic!("expected DNS header answer, got None");
            };
            consistency_qd_rr(&hdr, &hdr_repl);
        }
    }

    #[test]
    fn repl_opcode() {
        let masscanned = Masscanned {
            synack_key: [0, 0],
            mac: MacAddr::from_str("00:00:00:00:00:00").expect("error parsing default MAC address"),
            iface: None,
            ip_addresses: None,
            ignored_ip_addresses: None,
            log: MetaLogger::new(),
        };
        let client_info = ClientInfo::new();
        let mut hdr = DNSHeader::new();
        hdr._qr = false;
        /* opcode */
        for opcode in 0..3 {
            hdr._opcode = opcode;
            let hdr_repl = if let Some(r) = hdr.repl(&masscanned, &client_info, None) {
                DNSHeader::try_from(r).unwrap()
            } else {
                panic!("expected DNS header answer, got None");
            };
            consistency_qd_rr(&hdr, &hdr_repl);
        }
    }

    #[test]
    fn repl_rd() {
        let masscanned = Masscanned {
            synack_key: [0, 0],
            mac: MacAddr::from_str("00:00:00:00:00:00").expect("error parsing default MAC address"),
            iface: None,
            ip_addresses: None,
            ignored_ip_addresses: None,
            log: MetaLogger::new(),
        };
        let client_info = ClientInfo::new();
        let mut hdr = DNSHeader::new();
        hdr._qr = false;
        /* rd */
        for rd in [false, true] {
            hdr._rd = rd;
            let hdr_repl = if let Some(r) = hdr.repl(&masscanned, &client_info, None) {
                DNSHeader::try_from(r).unwrap()
            } else {
                panic!("expected DNS header answer, got None");
            };
            consistency_qd_rr(&hdr, &hdr_repl);
        }
    }

    #[test]
    fn repl_ancount() {
        let masscanned = Masscanned {
            synack_key: [0, 0],
            mac: MacAddr::from_str("00:00:00:00:00:00").expect("error parsing default MAC address"),
            iface: None,
            ip_addresses: None,
            ignored_ip_addresses: None,
            log: MetaLogger::new(),
        };
        let client_info = ClientInfo::new();
        let mut hdr = DNSHeader::new();
        hdr._qr = false;
        /* rd */
        for qdcount in 0..16 {
            hdr.qdcount = qdcount;
            let hdr_repl = if let Some(r) = hdr.repl(&masscanned, &client_info, None) {
                DNSHeader::try_from(r).unwrap()
            } else {
                panic!("expected DNS header answer, got None");
            };
            consistency_qd_rr(&hdr, &hdr_repl);
        }
    }
}
