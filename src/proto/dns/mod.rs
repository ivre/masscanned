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

mod cst;

mod header;
use header::{DNSHeader, DNSHeaderState};

mod query;
use query::{DNSQuery, DNSQueryState};

mod rr;
use rr::{DNSRRState, DNSRR};

use crate::proto::dissector::{MPacket, PacketDissector};
use crate::proto::ClientInfo;
use crate::proto::TCPControlBlock;
use crate::Masscanned;

#[derive(PartialEq, Debug)]
enum DNSState {
    Header,
    Query,
    Answer,
    Authority,
    Additional,
    End,
}

pub struct DNSPacket {
    d: PacketDissector<DNSState>,
    header: DNSHeader,
    qd: Vec<DNSQuery>,
    rr: Vec<DNSRR>,
    ns: Vec<DNSRR>,
    ar: Vec<DNSRR>,
}

impl TryFrom<Vec<u8>> for DNSPacket {
    type Error = &'static str;

    fn try_from(item: Vec<u8>) -> Result<Self, Self::Error> {
        let mut dns = DNSPacket::new();
        for b in item {
            dns.parse(&b);
        }
        if dns.d.state == DNSState::End {
            Ok(dns)
        } else {
            Err("packet is incomplete")
        }
    }
}

impl From<&DNSPacket> for Vec<u8> {
    fn from(item: &DNSPacket) -> Self {
        let mut v = Vec::new();
        v.extend(Vec::<u8>::from(&item.header));
        for qd in &item.qd {
            v.extend(Vec::<u8>::from(qd));
        }
        for rr in &item.rr {
            v.extend(Vec::<u8>::from(rr));
        }
        for ns in &item.ns {
            v.extend(Vec::<u8>::from(ns));
        }
        for ar in &item.ar {
            v.extend(Vec::<u8>::from(ar));
        }
        v
    }
}

impl MPacket for DNSPacket {
    fn new() -> Self {
        DNSPacket {
            d: PacketDissector::new(DNSState::Header),
            header: DNSHeader::new(),
            qd: Vec::new(),
            rr: Vec::new(),
            ns: Vec::new(),
            ar: Vec::new(),
        }
    }

    fn parse(&mut self, byte: &u8) {
        match self.d.state {
            DNSState::Header => {
                self.header.parse(byte);
                if self.header.d.state == DNSHeaderState::End {
                    if self.header.qdcount > 0 {
                        self.qd.push(DNSQuery::new());
                        self.d.next_state(DNSState::Query);
                    } else if self.header.ancount > 0 {
                        self.rr.push(DNSRR::new());
                        self.d.next_state(DNSState::Answer);
                    } else if self.header.nscount > 0 {
                        self.d.next_state(DNSState::Authority);
                    } else if self.header.arcount > 0 {
                        self.d.next_state(DNSState::Additional);
                    } else {
                        self.d.next_state(DNSState::End);
                    }
                }
            }
            DNSState::Query => {
                let qdcount = self.qd.len();
                self.qd[qdcount - 1].parse(byte);
                if self.qd[qdcount - 1].d.state == DNSQueryState::End {
                    if self.header.qdcount as usize > self.qd.len() {
                        self.qd.push(DNSQuery::new());
                    } else if self.header.ancount > 0 {
                        self.rr.push(DNSRR::new());
                        self.d.next_state(DNSState::Answer);
                    } else if self.header.nscount > 0 {
                        self.d.next_state(DNSState::Authority);
                    } else if self.header.arcount > 0 {
                        self.d.next_state(DNSState::Additional);
                    } else {
                        self.d.next_state(DNSState::End);
                    }
                }
            }
            DNSState::Answer => {
                let ancount = self.rr.len();
                self.rr[ancount - 1].parse(byte);
                if self.rr[ancount - 1].d.state == DNSRRState::End {
                    if self.header.ancount as usize > self.rr.len() {
                        self.rr.push(DNSRR::new());
                    } else if self.header.nscount > 0 {
                        self.d.next_state(DNSState::Authority);
                    } else if self.header.arcount > 0 {
                        self.d.next_state(DNSState::Additional);
                    } else {
                        self.d.next_state(DNSState::End);
                    }
                }
            }
            _ => {}
        }
    }

    fn repl(
        &self,
        masscanned: &Masscanned,
        client_info: &ClientInfo,
        _tcb: Option<&mut TCPControlBlock>,
    ) -> Option<Vec<u8>> {
        let mut ans = DNSPacket::new();
        ans.header = if let Some(hdr) = self.header.repl(&masscanned, &client_info, None) {
            if let Ok(h) = DNSHeader::try_from(hdr) {
                h
            } else {
                return None;
            }
        } else {
            return None;
        };
        /* reply to qd */
        for qd in &self.qd {
            if let Ok(q) = DNSQuery::try_from(Vec::<u8>::from(qd)) {
                ans.qd.push(q);
            } else {
                return None;
            }
            if let Some(raw_rr) = qd.repl(&masscanned, &client_info, None) {
                if let Ok(rr) = DNSRR::try_from(raw_rr) {
                    ans.rr.push(rr);
                } else {
                    return None;
                }
            } else {
                return None;
            }
        }
        Some(Vec::<u8>::from(&ans))
    }
}

#[cfg(test)]
mod tests {
    use super::cst::{DNSClass, DNSType};
    use super::*;

    use pnet::util::MacAddr;
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    use crate::logger::MetaLogger;

    #[test]
    fn parse_qd_all() {
        /* OK */
        /* scapy: DNS(id=0x1337,
         * qd=DNSQR(qname="www.example1.com")/DNSQR(qname="www.example2.com")/DNSQR(qname="www.example3.com"))
         **/
        let payload = b"\x137\x01\x00\x00\x03\x00\x00\x00\x00\x00\x00\x03www\x08example1\x03com\x00\x00\x01\x00\x01\x03www\x08example2\x03com\x00\x00\x01\x00\x01\x03www\x08example3\x03com\x00\x00\x01\x00\x01";
        let dns = match DNSPacket::try_from(payload.to_vec()) {
            Ok(_dns) => _dns,
            Err(e) => panic!("error while parsing DNS packet: {}", e),
        };
        assert!(dns.header.id == 0x1337);
        assert!(dns.header._qr == false);
        assert!(dns.header._opcode == 0);
        assert!(dns.header._aa == false);
        assert!(dns.header._tc == false);
        assert!(dns.header._rd == true);
        assert!(dns.header._ra == false);
        assert!(dns.header._z == 0);
        assert!(dns.header._rcode == 0);
        assert!(dns.header.qdcount == 3);
        assert!(dns.header.ancount == 0);
        assert!(dns.header.nscount == 0);
        assert!(dns.header.arcount == 0);
        assert!(dns.qd.len() == 3);
        assert!(
            dns.qd[0].name
                == [
                    0x03, 0x77, 0x77, 0x77, 0x08, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x31,
                    0x03, 0x63, 0x6f, 0x6d, 0x00
                ]
        );
        assert!(dns.qd[0].type_ == DNSType::A);
        assert!(dns.qd[0].class == DNSClass::IN);
        assert!(
            dns.qd[1].name
                == [
                    0x03, 0x77, 0x77, 0x77, 0x08, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x32,
                    0x03, 0x63, 0x6f, 0x6d, 0x00
                ]
        );
        assert!(dns.qd[1].type_ == DNSType::A);
        assert!(dns.qd[1].class == DNSClass::IN);
        assert!(
            dns.qd[2].name
                == [
                    0x03, 0x77, 0x77, 0x77, 0x08, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x33,
                    0x03, 0x63, 0x6f, 0x6d, 0x00
                ]
        );
        assert!(dns.qd[2].type_ == DNSType::A);
        assert!(dns.qd[2].class == DNSClass::IN);
        /* KO */
        let payload = b"\x137\x01\x00\x00\x03\x00\x00\x00\x00\x00\x00\x03www\x08example1\x03com\x00\x00\x01\x00\x01\x03www\x08example2\x03com\x00\x00\x01\x00\x01\x03www\x08example3\x03com\x00\x00\x01\x00";
        match DNSPacket::try_from(payload.to_vec()) {
            Ok(_) => panic!("parsing should have failed"),
            Err(_) => {}
        }
        let payload = b"xxx";
        match DNSPacket::try_from(payload.to_vec()) {
            Ok(_) => panic!("parsing should have failed"),
            Err(_) => {}
        }
    }

    #[test]
    fn parse_qd_byte_by_byte() {
        /* scapy: DNS(id=0x1337,
         * qd=DNSQR(qname="www.example1.com")/DNSQR(qname="www.example2.com")/DNSQR(qname="www.example3.com"))
         **/
        let payload = b"\x137\x01\x00\x00\x03\x00\x00\x00\x00\x00\x00\x03www\x08example1\x03com\x00\x00\x01\x00\x01\x03www\x08example2\x03com\x00\x00\x01\x00\x01\x03www\x08example3\x03com\x00\x00\x01\x00\x01";
        let mut dns = DNSPacket::new();
        for b in payload {
            assert!(dns.d.state != DNSState::End);
            dns.parse(&b);
        }
        assert!(dns.d.state == DNSState::End);
        assert!(dns.header.id == 0x1337);
        assert!(dns.header._qr == false);
        assert!(dns.header._opcode == 0);
        assert!(dns.header._aa == false);
        assert!(dns.header._tc == false);
        assert!(dns.header._rd == true);
        assert!(dns.header._ra == false);
        assert!(dns.header._z == 0);
        assert!(dns.header._rcode == 0);
        assert!(dns.header.qdcount == 3);
        assert!(dns.header.ancount == 0);
        assert!(dns.header.nscount == 0);
        assert!(dns.header.arcount == 0);
        assert!(dns.qd.len() == 3);
        assert!(
            dns.qd[0].name
                == [
                    0x03, 0x77, 0x77, 0x77, 0x08, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x31,
                    0x03, 0x63, 0x6f, 0x6d, 0x00
                ]
        );
        assert!(dns.qd[0].type_ == DNSType::A);
        assert!(dns.qd[0].class == DNSClass::IN);
        assert!(
            dns.qd[1].name
                == [
                    0x03, 0x77, 0x77, 0x77, 0x08, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x32,
                    0x03, 0x63, 0x6f, 0x6d, 0x00
                ]
        );
        assert!(dns.qd[1].type_ == DNSType::A);
        assert!(dns.qd[1].class == DNSClass::IN);
        assert!(
            dns.qd[2].name
                == [
                    0x03, 0x77, 0x77, 0x77, 0x08, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x33,
                    0x03, 0x63, 0x6f, 0x6d, 0x00
                ]
        );
        assert!(dns.qd[2].type_ == DNSType::A);
        assert!(dns.qd[2].class == DNSClass::IN);
    }

    #[test]
    fn parse_rr_all() {
        /* OK */
        /* scapy: DNS(id=1234, qr=True, aa=True, qd=None,
         * an=DNSRR(rrname="www.example1.com", rdata="127.0.0.1")/DNSRR(rrname="www.example2.com", rdata="127.0.0.2")/DNSRR(rrname="www.example3.com", rdata="127.0.0.3"))
         **/
        let payload = b"\x04\xd2\x85\x00\x00\x00\x00\x03\x00\x00\x00\x00\x03www\x08example1\x03com\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\x7f\x00\x00\x01\x03www\x08example2\x03com\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\x7f\x00\x00\x02\x03www\x08example3\x03com\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\x7f\x00\x00\x03";
        let dns = match DNSPacket::try_from(payload.to_vec()) {
            Ok(_dns) => _dns,
            Err(e) => panic!("error while parsing DNS packet: {}", e),
        };
        assert!(dns.header.id == 1234);
        assert!(dns.header._qr == true);
        assert!(dns.header._opcode == 0);
        assert!(dns.header._aa == true);
        assert!(dns.header._tc == false);
        assert!(dns.header._rd == true);
        assert!(dns.header._ra == false);
        assert!(dns.header._z == 0);
        assert!(dns.header._rcode == 0);
        assert!(dns.header.qdcount == 0);
        assert!(dns.header.ancount == 3);
        assert!(dns.header.nscount == 0);
        assert!(dns.header.arcount == 0);
        assert!(dns.rr.len() == 3);
        assert!(
            dns.rr[0].name
                == [
                    0x03, 0x77, 0x77, 0x77, 0x08, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x31,
                    0x03, 0x63, 0x6f, 0x6d, 0x00
                ]
        );
        assert!(dns.rr[0].type_ == DNSType::A);
        assert!(dns.rr[0].class == DNSClass::IN);
        assert!(dns.rr[0].rdata == [0x7f, 0x00, 0x00, 0x01]);
        assert!(
            dns.rr[1].name
                == [
                    0x03, 0x77, 0x77, 0x77, 0x08, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x32,
                    0x03, 0x63, 0x6f, 0x6d, 0x00
                ]
        );
        assert!(dns.rr[1].type_ == DNSType::A);
        assert!(dns.rr[1].class == DNSClass::IN);
        assert!(dns.rr[1].rdata == [0x7f, 0x00, 0x00, 0x02]);
        assert!(
            dns.rr[2].name
                == [
                    0x03, 0x77, 0x77, 0x77, 0x08, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x33,
                    0x03, 0x63, 0x6f, 0x6d, 0x00
                ]
        );
        assert!(dns.rr[2].type_ == DNSType::A);
        assert!(dns.rr[2].class == DNSClass::IN);
        assert!(dns.rr[2].rdata == [0x7f, 0x00, 0x00, 0x03]);
        /* KO */
        let payload = b"\x04\xd2\x85\x00\x00\x00\x00\x04\x00\x00\x00\x00\x03www\x08example1\x03com\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\x7f\x00\x00\x01\x03www\x08example2\x03com\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\x7f\x00\x00\x02\x03www\x08example3\x03com\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\x7f\x00\x00\x03";
        match DNSPacket::try_from(payload.to_vec()) {
            Ok(_) => panic!("parsing should have failed"),
            Err(_) => {}
        }
        let payload = b"xxx";
        match DNSPacket::try_from(payload.to_vec()) {
            Ok(_) => panic!("parsing should have failed"),
            Err(_) => {}
        }
    }

    #[test]
    fn parse_rr_byte_by_byte() {
        /* scapy: DNS(id=1234, qr=True, aa=True, qd=None,
         * an=DNSRR(rrname="www.example1.com", rdata="127.0.0.1")/DNSRR(rrname="www.example2.com", rdata="127.0.0.2")/DNSRR(rrname="www.example3.com", rdata="127.0.0.3"))
         **/
        let payload = b"\x04\xd2\x85\x00\x00\x00\x00\x03\x00\x00\x00\x00\x03www\x08example1\x03com\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\x7f\x00\x00\x01\x03www\x08example2\x03com\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\x7f\x00\x00\x02\x03www\x08example3\x03com\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\x7f\x00\x00\x03";
        let mut dns = DNSPacket::new();
        for b in payload {
            assert!(dns.d.state != DNSState::End);
            dns.parse(&b);
        }
        assert!(dns.d.state == DNSState::End);
        assert!(dns.header.id == 1234);
        assert!(dns.header._qr == true);
        assert!(dns.header._opcode == 0);
        assert!(dns.header._aa == true);
        assert!(dns.header._tc == false);
        assert!(dns.header._rd == true);
        assert!(dns.header._ra == false);
        assert!(dns.header._z == 0);
        assert!(dns.header._rcode == 0);
        assert!(dns.header.qdcount == 0);
        assert!(dns.header.ancount == 3);
        assert!(dns.header.nscount == 0);
        assert!(dns.header.arcount == 0);
        assert!(dns.rr.len() == 3);
        assert!(
            dns.rr[0].name
                == [
                    0x03, 0x77, 0x77, 0x77, 0x08, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x31,
                    0x03, 0x63, 0x6f, 0x6d, 0x00
                ]
        );
        assert!(dns.rr[0].type_ == DNSType::A);
        assert!(dns.rr[0].class == DNSClass::IN);
        assert!(dns.rr[0].rdata == [0x7f, 0x00, 0x00, 0x01]);
        assert!(
            dns.rr[1].name
                == [
                    0x03, 0x77, 0x77, 0x77, 0x08, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x32,
                    0x03, 0x63, 0x6f, 0x6d, 0x00
                ]
        );
        assert!(dns.rr[1].type_ == DNSType::A);
        assert!(dns.rr[1].class == DNSClass::IN);
        assert!(dns.rr[1].rdata == [0x7f, 0x00, 0x00, 0x02]);
        assert!(
            dns.rr[2].name
                == [
                    0x03, 0x77, 0x77, 0x77, 0x08, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x33,
                    0x03, 0x63, 0x6f, 0x6d, 0x00
                ]
        );
        assert!(dns.rr[2].type_ == DNSType::A);
        assert!(dns.rr[2].class == DNSClass::IN);
        assert!(dns.rr[2].rdata == [0x7f, 0x00, 0x00, 0x03]);
    }

    #[test]
    fn parse_qd_rr_all() {
        /* scapy: DNS(id=1234, qr=True, aa=True,
         * qd=DNSQR(qname="www.example1.com")/DNSQR(qname="www.example2.com")/DNSQR(qname="www.example3.com"),
         * an=DNSRR(rrname="www.example1.com", rdata="127.0.0.1")/DNSRR(rrname="www.example2.com", rdata="127.0.0.2")/DNSRR(rrname="www.example3.com", rdata="127.0.0.3"))
         */
        let payload = b"\x04\xd2\x85\x00\x00\x03\x00\x03\x00\x00\x00\x00\x03www\x08example1\x03com\x00\x00\x01\x00\x01\x03www\x08example2\x03com\x00\x00\x01\x00\x01\x03www\x08example3\x03com\x00\x00\x01\x00\x01\x03www\x08example1\x03com\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\x7f\x00\x00\x01\x03www\x08example2\x03com\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\x7f\x00\x00\x02\x03www\x08example3\x03com\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\x7f\x00\x00\x03";
        let dns = match DNSPacket::try_from(payload.to_vec()) {
            Ok(_dns) => _dns,
            Err(e) => panic!("error while parsing DNS packet: {}", e),
        };
        assert!(dns.header.id == 1234);
        assert!(dns.header._qr == true);
        assert!(dns.header._opcode == 0);
        assert!(dns.header._aa == true);
        assert!(dns.header._tc == false);
        assert!(dns.header._rd == true);
        assert!(dns.header._ra == false);
        assert!(dns.header._z == 0);
        assert!(dns.header._rcode == 0);
        assert!(dns.header.qdcount == 3);
        assert!(dns.header.ancount == 3);
        assert!(dns.header.nscount == 0);
        assert!(dns.header.arcount == 0);
        assert!(dns.qd.len() == 3);
        assert!(
            dns.qd[0].name
                == [
                    0x03, 0x77, 0x77, 0x77, 0x08, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x31,
                    0x03, 0x63, 0x6f, 0x6d, 0x00
                ]
        );
        assert!(dns.qd[0].type_ == DNSType::A);
        assert!(dns.qd[0].class == DNSClass::IN);
        assert!(
            dns.qd[1].name
                == [
                    0x03, 0x77, 0x77, 0x77, 0x08, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x32,
                    0x03, 0x63, 0x6f, 0x6d, 0x00
                ]
        );
        assert!(dns.qd[1].type_ == DNSType::A);
        assert!(dns.qd[1].class == DNSClass::IN);
        assert!(
            dns.qd[2].name
                == [
                    0x03, 0x77, 0x77, 0x77, 0x08, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x33,
                    0x03, 0x63, 0x6f, 0x6d, 0x00
                ]
        );
        assert!(dns.qd[2].type_ == DNSType::A);
        assert!(dns.qd[2].class == DNSClass::IN);
        assert!(dns.rr.len() == 3);
        assert!(
            dns.rr[0].name
                == [
                    0x03, 0x77, 0x77, 0x77, 0x08, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x31,
                    0x03, 0x63, 0x6f, 0x6d, 0x00
                ]
        );
        assert!(dns.rr[0].type_ == DNSType::A);
        assert!(dns.rr[0].class == DNSClass::IN);
        assert!(dns.rr[0].rdata == [0x7f, 0x00, 0x00, 0x01]);
        assert!(
            dns.rr[1].name
                == [
                    0x03, 0x77, 0x77, 0x77, 0x08, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x32,
                    0x03, 0x63, 0x6f, 0x6d, 0x00
                ]
        );
        assert!(dns.rr[1].type_ == DNSType::A);
        assert!(dns.rr[1].class == DNSClass::IN);
        assert!(dns.rr[1].rdata == [0x7f, 0x00, 0x00, 0x02]);
        assert!(
            dns.rr[2].name
                == [
                    0x03, 0x77, 0x77, 0x77, 0x08, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x33,
                    0x03, 0x63, 0x6f, 0x6d, 0x00
                ]
        );
        assert!(dns.rr[2].type_ == DNSType::A);
        assert!(dns.rr[2].class == DNSClass::IN);
        assert!(dns.rr[2].rdata == [0x7f, 0x00, 0x00, 0x03]);
    }

    #[test]
    fn parse_qr_rr_byte_by_byte() {
        /* scapy: DNS(id=1234, qr=True, aa=True,
         * qd=DNSQR(qname="www.example1.com")/DNSQR(qname="www.example2.com")/DNSQR(qname="www.example3.com"),
         * an=DNSRR(rrname="www.example1.com", rdata="127.0.0.1")/DNSRR(rrname="www.example2.com", rdata="127.0.0.2")/DNSRR(rrname="www.example3.com", rdata="127.0.0.3"))
         */
        let payload = b"\x04\xd2\x85\x00\x00\x03\x00\x03\x00\x00\x00\x00\x03www\x08example1\x03com\x00\x00\x01\x00\x01\x03www\x08example2\x03com\x00\x00\x01\x00\x01\x03www\x08example3\x03com\x00\x00\x01\x00\x01\x03www\x08example1\x03com\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\x7f\x00\x00\x01\x03www\x08example2\x03com\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\x7f\x00\x00\x02\x03www\x08example3\x03com\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\x7f\x00\x00\x03";
        let mut dns = DNSPacket::new();
        for b in payload {
            assert!(dns.d.state != DNSState::End);
            dns.parse(&b);
        }
        assert!(dns.d.state == DNSState::End);
        assert!(dns.header.id == 1234);
        assert!(dns.header._qr == true);
        assert!(dns.header._opcode == 0);
        assert!(dns.header._aa == true);
        assert!(dns.header._tc == false);
        assert!(dns.header._rd == true);
        assert!(dns.header._ra == false);
        assert!(dns.header._z == 0);
        assert!(dns.header._rcode == 0);
        assert!(dns.header.qdcount == 3);
        assert!(dns.header.ancount == 3);
        assert!(dns.header.nscount == 0);
        assert!(dns.header.arcount == 0);
        assert!(dns.qd.len() == 3);
        assert!(
            dns.qd[0].name
                == [
                    0x03, 0x77, 0x77, 0x77, 0x08, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x31,
                    0x03, 0x63, 0x6f, 0x6d, 0x00
                ]
        );
        assert!(dns.qd[0].type_ == DNSType::A);
        assert!(dns.qd[0].class == DNSClass::IN);
        assert!(
            dns.qd[1].name
                == [
                    0x03, 0x77, 0x77, 0x77, 0x08, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x32,
                    0x03, 0x63, 0x6f, 0x6d, 0x00
                ]
        );
        assert!(dns.qd[1].type_ == DNSType::A);
        assert!(dns.qd[1].class == DNSClass::IN);
        assert!(
            dns.qd[2].name
                == [
                    0x03, 0x77, 0x77, 0x77, 0x08, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x33,
                    0x03, 0x63, 0x6f, 0x6d, 0x00
                ]
        );
        assert!(dns.qd[2].type_ == DNSType::A);
        assert!(dns.qd[2].class == DNSClass::IN);
        assert!(dns.rr.len() == 3);
        assert!(
            dns.rr[0].name
                == [
                    0x03, 0x77, 0x77, 0x77, 0x08, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x31,
                    0x03, 0x63, 0x6f, 0x6d, 0x00
                ]
        );
        assert!(dns.rr[0].type_ == DNSType::A);
        assert!(dns.rr[0].class == DNSClass::IN);
        assert!(dns.rr[0].rdata == [0x7f, 0x00, 0x00, 0x01]);
        assert!(
            dns.rr[1].name
                == [
                    0x03, 0x77, 0x77, 0x77, 0x08, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x32,
                    0x03, 0x63, 0x6f, 0x6d, 0x00
                ]
        );
        assert!(dns.rr[1].type_ == DNSType::A);
        assert!(dns.rr[1].class == DNSClass::IN);
        assert!(dns.rr[1].rdata == [0x7f, 0x00, 0x00, 0x02]);
        assert!(
            dns.rr[2].name
                == [
                    0x03, 0x77, 0x77, 0x77, 0x08, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x33,
                    0x03, 0x63, 0x6f, 0x6d, 0x00
                ]
        );
        assert!(dns.rr[2].type_ == DNSType::A);
        assert!(dns.rr[2].class == DNSClass::IN);
        assert!(dns.rr[2].rdata == [0x7f, 0x00, 0x00, 0x03]);
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
        let mut client_info = ClientInfo::new();
        /* scapy: DNS(id=0x1337,
         * qd=DNSQR(qname="www.example.com"))
         **/
        let payload = b"\x137\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01";
        let dns = DNSPacket::try_from(payload.to_vec()).unwrap();
        for ip in [
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(4, 3, 2, 1),
        ] {
            client_info.ip.dst = Some(IpAddr::V4(ip));
            let ans = if let Some(a) = dns.repl(&masscanned, &client_info, None) {
                DNSPacket::try_from(a).unwrap()
            } else {
                panic!("expected a reply, got None");
            };
            assert!(ans.header.id == 0x1337);
            assert!(ans.header._qr == true);
            assert!(ans.header._opcode == 0);
            assert!(ans.header._aa == true);
            assert!(ans.header._tc == false);
            assert!(ans.header._rd == dns.header._rd);
            assert!(ans.header._ra == false);
            assert!(ans.header._z == 0);
            assert!(ans.header._rcode == 0);
            assert!(ans.header.qdcount == 1);
            assert!(ans.header.ancount == 1);
            assert!(ans.header.nscount == 0);
            assert!(ans.header.arcount == 0);
            assert!(ans.qd.len() == 1);
            assert!(
                ans.qd[0].name
                    == [
                        0x03, 0x77, 0x77, 0x77, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
                        0x03, 0x63, 0x6f, 0x6d, 0x00
                    ]
            );
            assert!(ans.qd[0].type_ == DNSType::A);
            assert!(ans.qd[0].class == DNSClass::IN);
            assert!(ans.rr.len() == 1);
            assert!(
                ans.rr[0].name
                    == [
                        0x03, 0x77, 0x77, 0x77, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
                        0x03, 0x63, 0x6f, 0x6d, 0x00
                    ]
            );
            assert!(ans.rr[0].type_ == DNSType::A);
            assert!(ans.rr[0].class == DNSClass::IN);
            assert!(ans.rr[0].rdata == ip.octets());
        }
    }
}
