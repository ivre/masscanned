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

use pnet::packet::{
    arp::{ArpPacket, MutableArpPacket},
    ethernet::{EthernetPacket, MutableEthernetPacket},
    ipv4::{Ipv4Packet, MutableIpv4Packet},
    ipv6::{Ipv6Packet, MutableIpv6Packet},
    icmp::{IcmpPacket, MutableIcmpPacket},
    icmpv6::{Icmpv6Packet, MutableIcmpv6Packet},
    tcp::{TcpPacket, MutableTcpPacket},
    udp::{UdpPacket, MutableUdpPacket},
};

use crate::client::ClientInfo;
use crate::logger::Logger;

pub struct MetaLogger {
    loggers: Vec<Box<dyn Logger>>,
}

impl MetaLogger {
    pub fn new() -> Self {
        MetaLogger {
            loggers: Vec::new(),
        }
    }
    pub fn add(&mut self, log: Box<dyn Logger>) {
        self.loggers.push(log);
    }
    pub fn init(&self) {
        for l in &self.loggers {
            l.init();
        }
    }
    /* ARP */
    pub fn arp_recv(&self, p: &ArpPacket) {
        for l in &self.loggers {
            if l.arp_enabled() {
                l.arp_recv(p);
            }
        }
    }
    pub fn arp_drop(&self, p: &ArpPacket) {
        for l in &self.loggers {
            if l.arp_enabled() {
                l.arp_drop(p);
            }
        }
    }
    pub fn arp_send(&self, p: &MutableArpPacket) {
        for l in &self.loggers {
            if l.arp_enabled() {
                l.arp_send(p);
            }
        }
    }
    /* Ethernet */
    pub fn eth_recv(&self, p: &EthernetPacket, c: &ClientInfo) {
        for l in &self.loggers {
            if l.eth_enabled() {
                l.eth_recv(p, c);
            }
        }
    }
    pub fn eth_drop(&self, p: &EthernetPacket, c: &ClientInfo) {
        for l in &self.loggers {
            if l.eth_enabled() {
                l.eth_drop(p, c);
            }
        }
    }
    pub fn eth_send(&self, p: &MutableEthernetPacket, c: &ClientInfo) {
        for l in &self.loggers {
            if l.eth_enabled() {
                l.eth_send(p, c);
            }
        }
    }
    /* IPv4 */
    pub fn ipv4_recv(&self, p: &Ipv4Packet, c: &ClientInfo) {
        for l in &self.loggers {
            if l.ipv4_enabled() {
                l.ipv4_recv(p, c);
            }
        }
    }
    pub fn ipv4_drop(&self, p: &Ipv4Packet, c: &ClientInfo) {
        for l in &self.loggers {
            if l.ipv4_enabled() {
                l.ipv4_drop(p, c);
            }
        }
    }
    pub fn ipv4_send(&self, p: &MutableIpv4Packet, c: &ClientInfo) {
        for l in &self.loggers {
            if l.ipv4_enabled() {
                l.ipv4_send(p, c);
            }
        }
    }
    /* IPv6 */
    pub fn ipv6_recv(&self, p: &Ipv6Packet, c: &ClientInfo) {
        for l in &self.loggers {
            if l.ipv6_enabled() {
                l.ipv6_recv(p, c);
            }
        }
    }
    pub fn ipv6_drop(&self, p: &Ipv6Packet, c: &ClientInfo) {
        for l in &self.loggers {
            if l.ipv6_enabled() {
                l.ipv6_drop(p, c);
            }
        }
    }
    pub fn ipv6_send(&self, p: &MutableIpv6Packet, c: &ClientInfo) {
        for l in &self.loggers {
            if l.ipv6_enabled() {
                l.ipv6_send(p, c);
            }
        }
    }
    /* ICMPv4 */
    pub fn icmpv4_recv(&self, p: &IcmpPacket, c: &ClientInfo) {
        for l in &self.loggers {
            if l.icmpv4_enabled() {
                l.icmpv4_recv(p, c);
            }
        }
    }
    pub fn icmpv4_drop(&self, p: &IcmpPacket, c: &ClientInfo) {
        for l in &self.loggers {
            if l.icmpv4_enabled() {
                l.icmpv4_drop(p, c);
            }
        }
    }
    pub fn icmpv4_send(&self, p: &MutableIcmpPacket, c: &ClientInfo) {
        for l in &self.loggers {
            if l.icmpv4_enabled() {
                l.icmpv4_send(p, c);
            }
        }
    }
    /* ICMPv6 */
    pub fn icmpv6_recv(&self, p: &Icmpv6Packet, c: &ClientInfo) {
        for l in &self.loggers {
            if l.icmpv6_enabled() {
                l.icmpv6_recv(p, c);
            }
        }
    }
    pub fn icmpv6_drop(&self, p: &Icmpv6Packet, c: &ClientInfo) {
        for l in &self.loggers {
            if l.icmpv6_enabled() {
                l.icmpv6_drop(p, c);
            }
        }
    }
    pub fn icmpv6_send(&self, p: &MutableIcmpv6Packet, c: &ClientInfo) {
        for l in &self.loggers {
            if l.icmpv6_enabled() {
                l.icmpv6_send(p, c);
            }
        }
    }
    /* TCP */
    pub fn tcp_recv(&self, p: &TcpPacket, c: &ClientInfo) {
        for l in &self.loggers {
            if l.tcp_enabled() {
                l.tcp_recv(p, c);
            }
        }
    }
    pub fn tcp_drop(&self, p: &TcpPacket, c: &ClientInfo) {
        for l in &self.loggers {
            if l.tcp_enabled() {
                l.tcp_drop(p, c);
            }
        }
    }
    pub fn tcp_send(&self, p: &MutableTcpPacket, c: &ClientInfo) {
        for l in &self.loggers {
            if l.tcp_enabled() {
                l.tcp_send(p, c);
            }
        }
    }
    /* UDP */
    pub fn udp_recv(&self, p: &UdpPacket, c: &ClientInfo) {
        for l in &self.loggers {
            if l.udp_enabled() {
                l.udp_recv(p, c);
            }
        }
    }
    pub fn udp_drop(&self, p: &UdpPacket, c: &ClientInfo) {
        for l in &self.loggers {
            if l.udp_enabled() {
                l.udp_drop(p, c);
            }
        }
    }
    pub fn udp_send(&self, p: &MutableUdpPacket, c: &ClientInfo) {
        for l in &self.loggers {
            if l.udp_enabled() {
                l.udp_send(p, c);
            }
        }
    }
}
