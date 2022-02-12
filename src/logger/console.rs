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

use std::time::SystemTime;

use pnet::packet::{
    arp::{ArpPacket, MutableArpPacket},
    ethernet::{EthernetPacket, MutableEthernetPacket},
    icmp::{IcmpPacket, MutableIcmpPacket},
    icmpv6::{Icmpv6Packet, MutableIcmpv6Packet},
    ipv4::{Ipv4Packet, MutableIpv4Packet},
    ipv6::{Ipv6Packet, MutableIpv6Packet},
    tcp::{MutableTcpPacket, TcpPacket},
    udp::{MutableUdpPacket, UdpPacket},
};

use crate::client::ClientInfo;
use crate::logger::Logger;

pub struct ConsoleLogger {
    arp: bool,
    eth: bool,
    ipv4: bool,
    ipv6: bool,
    icmpv4: bool,
    icmpv6: bool,
    tcp: bool,
    udp: bool,
}

impl ConsoleLogger {
    pub fn new() -> Self {
        ConsoleLogger {
            arp: true,
            eth: true,
            ipv4: true,
            ipv6: true,
            icmpv4: true,
            icmpv6: true,
            tcp: true,
            udp: true,
        }
    }
    fn prolog(&self, proto: &str, verb: &str, crlf: bool) {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
        print!(
            "{}.{}\t{}\t{}{}",
            now.as_secs(),
            now.subsec_millis(),
            proto,
            verb,
            if crlf { "\n" } else { "\t" },
        );
    }
    fn client_info(&self, c: &ClientInfo) {
        print!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t",
            if let Some(m) = c.mac.src {
                format!("{}", m)
            } else {
                "".to_string()
            },
            if let Some(m) = c.mac.dst {
                format!("{}", m)
            } else {
                "".to_string()
            },
            if let Some(i) = c.ip.src {
                format!("{}", i)
            } else {
                "".to_string()
            },
            if let Some(i) = c.ip.dst {
                format!("{}", i)
            } else {
                "".to_string()
            },
            if let Some(t) = c.transport {
                format!("{}", t)
            } else {
                "".to_string()
            },
            if let Some(p) = c.port.src {
                format!("{}", p)
            } else {
                "".to_string()
            },
            if let Some(p) = c.port.dst {
                format!("{}", p)
            } else {
                "".to_string()
            },
        );
    }
}

impl Logger for ConsoleLogger {
    fn init(&self) {
        self.prolog("arp", "init", true);
        self.prolog("eth", "init", true);
        self.prolog("ipv4", "init", true);
    }
    /* ARP */
    fn arp_enabled(&self) -> bool {
        self.arp
    }
    fn arp_recv(&self, p: &ArpPacket) {
        self.prolog("arp", "recv", false);
        println!(
            "{:}\t{:}\t{:}\t{:}\t{:?}",
            p.get_sender_hw_addr(),
            p.get_target_hw_addr(),
            p.get_sender_proto_addr(),
            p.get_target_proto_addr(),
            p.get_operation(),
        );
    }
    fn arp_drop(&self, p: &ArpPacket) {
        self.prolog("arp", "drop", false);
        println!(
            "{:}\t{:}\t{:}\t{:}\t{:?}",
            p.get_sender_hw_addr(),
            p.get_target_hw_addr(),
            p.get_sender_proto_addr(),
            p.get_target_proto_addr(),
            p.get_operation(),
        );
    }
    fn arp_send(&self, p: &MutableArpPacket) {
        self.prolog("arp", "send", false);
        println!(
            "{:}\t{:}\t{:}\t{:}\t{:?}",
            p.get_target_hw_addr(),
            p.get_sender_hw_addr(),
            p.get_target_proto_addr(),
            p.get_sender_proto_addr(),
            p.get_operation(),
        );
    }
    /* Ethernet */
    fn eth_enabled(&self) -> bool {
        self.eth
    }
    fn eth_recv(&self, p: &EthernetPacket, c: &ClientInfo) {
        self.prolog("eth", "recv", false);
        self.client_info(c);
        println!("{:}", p.get_ethertype(),);
    }
    fn eth_drop(&self, p: &EthernetPacket, c: &ClientInfo) {
        self.prolog("eth", "drop", false);
        self.client_info(c);
        println!("{:}", p.get_ethertype(),);
    }
    fn eth_send(&self, p: &MutableEthernetPacket, c: &ClientInfo) {
        self.prolog("eth", "send", false);
        self.client_info(c);
        println!("{:}", p.get_ethertype(),);
    }
    /* IPv4 */
    fn ipv4_enabled(&self) -> bool {
        self.ipv4
    }
    fn ipv4_recv(&self, p: &Ipv4Packet, c: &ClientInfo) {
        self.prolog("ipv4", "recv", false);
        self.client_info(c);
        println!("{:}", p.get_next_level_protocol(),);
    }
    fn ipv4_drop(&self, p: &Ipv4Packet, c: &ClientInfo) {
        self.prolog("ipv4", "drop", false);
        self.client_info(c);
        println!("{:}", p.get_next_level_protocol(),);
    }
    fn ipv4_send(&self, p: &MutableIpv4Packet, c: &ClientInfo) {
        self.prolog("ipv4", "send", false);
        self.client_info(c);
        println!("{:}", p.get_next_level_protocol(),);
    }
    /* IPv6 */
    fn ipv6_enabled(&self) -> bool {
        self.ipv6
    }
    fn ipv6_recv(&self, p: &Ipv6Packet, c: &ClientInfo) {
        self.prolog("ipv6", "recv", false);
        self.client_info(c);
        println!("{:}", p.get_next_header(),);
    }
    fn ipv6_drop(&self, p: &Ipv6Packet, c: &ClientInfo) {
        self.prolog("ipv6", "drop", false);
        self.client_info(c);
        println!("{:}", p.get_next_header(),);
    }
    fn ipv6_send(&self, p: &MutableIpv6Packet, c: &ClientInfo) {
        self.prolog("ipv6", "send", false);
        self.client_info(c);
        println!("{:}", p.get_next_header(),);
    }
    /* ICMPv4 */
    fn icmpv4_enabled(&self) -> bool {
        self.icmpv4
    }
    fn icmpv4_recv(&self, p: &IcmpPacket, c: &ClientInfo) {
        self.prolog("icmpv4", "recv", false);
        self.client_info(c);
        println!("{:?}\t{:?}", p.get_icmp_type(), p.get_icmp_code(),);
    }
    fn icmpv4_drop(&self, p: &IcmpPacket, c: &ClientInfo) {
        self.prolog("icmpv4", "drop", false);
        self.client_info(c);
        println!("{:?}\t{:?}", p.get_icmp_type(), p.get_icmp_code(),);
    }
    fn icmpv4_send(&self, p: &MutableIcmpPacket, c: &ClientInfo) {
        self.prolog("icmpv4", "send", false);
        self.client_info(c);
        println!("{:?}\t{:?}", p.get_icmp_type(), p.get_icmp_code(),);
    }
    /* ICMPv6 */
    fn icmpv6_enabled(&self) -> bool {
        self.icmpv6
    }
    fn icmpv6_recv(&self, p: &Icmpv6Packet, c: &ClientInfo) {
        self.prolog("icmpv6", "recv", false);
        self.client_info(c);
        println!("{:?}\t{:?}", p.get_icmpv6_type(), p.get_icmpv6_code(),);
    }
    fn icmpv6_drop(&self, p: &Icmpv6Packet, c: &ClientInfo) {
        self.prolog("icmpv6", "drop", false);
        self.client_info(c);
        println!("{:?}\t{:?}", p.get_icmpv6_type(), p.get_icmpv6_code(),);
    }
    fn icmpv6_send(&self, p: &MutableIcmpv6Packet, c: &ClientInfo) {
        self.prolog("icmpv6", "send", false);
        self.client_info(c);
        println!("{:?}\t{:?}", p.get_icmpv6_type(), p.get_icmpv6_code(),);
    }
    /* TCP */
    fn tcp_enabled(&self) -> bool {
        self.tcp
    }
    fn tcp_recv(&self, p: &TcpPacket, c: &ClientInfo) {
        self.prolog("tcp", "recv", false);
        self.client_info(c);
        println!(
            "{:?}\t{:}\t{:}",
            p.get_flags(),
            p.get_sequence(),
            p.get_acknowledgement(),
        );
    }
    fn tcp_drop(&self, p: &TcpPacket, c: &ClientInfo) {
        self.prolog("tcp", "drop", false);
        self.client_info(c);
        println!(
            "{:?}\t{:}\t{:}",
            p.get_flags(),
            p.get_sequence(),
            p.get_acknowledgement(),
        );
    }
    fn tcp_send(&self, p: &MutableTcpPacket, c: &ClientInfo) {
        self.prolog("tcp", "send", false);
        self.client_info(c);
        println!(
            "{:?}\t{:}\t{:}",
            p.get_flags(),
            p.get_sequence(),
            p.get_acknowledgement(),
        );
    }
    /* UDP */
    fn udp_enabled(&self) -> bool {
        self.udp
    }
    fn udp_recv(&self, _p: &UdpPacket, c: &ClientInfo) {
        self.prolog("udp", "recv", false);
        self.client_info(c);
        println!("");
    }
    fn udp_drop(&self, _p: &UdpPacket, c: &ClientInfo) {
        self.prolog("udp", "drop", false);
        self.client_info(c);
        println!("");
    }
    fn udp_send(&self, _p: &MutableUdpPacket, c: &ClientInfo) {
        self.prolog("udp", "send", false);
        self.client_info(c);
        println!("");
    }
}
