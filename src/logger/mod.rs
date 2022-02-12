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

mod meta;
mod console;

pub use meta::MetaLogger;
pub use console::ConsoleLogger;

pub trait Logger {
    fn init(&self);
    /* list of notifications that a logger might or might not implement */
    /* ARP */
    fn arp_enabled(&self) -> bool {
        true
    }
    fn arp_recv(&self, _p: &ArpPacket) {}
    fn arp_drop(&self, _p: &ArpPacket) {}
    fn arp_send(&self, _p: &MutableArpPacket) {}
    /* Ethernet */
    fn eth_enabled(&self) -> bool {
        true
    }
    fn eth_recv(&self, _p: &EthernetPacket, _c: &ClientInfo) {}
    fn eth_drop(&self, _p: &EthernetPacket, _c: &ClientInfo) {}
    fn eth_send(&self, _p: &MutableEthernetPacket, _c: &ClientInfo) {}
    /* IPv4 */
    fn ipv4_enabled(&self) -> bool {
        true
    }
    fn ipv4_recv(&self, _p: &Ipv4Packet, _c: &ClientInfo) {}
    fn ipv4_drop(&self, _p: &Ipv4Packet, _c: &ClientInfo) {}
    fn ipv4_send(&self, _p: &MutableIpv4Packet, _c: &ClientInfo) {}
    /* IPv6 */
    fn ipv6_enabled(&self) -> bool {
        true
    }
    fn ipv6_recv(&self, _p: &Ipv6Packet, _c: &ClientInfo) {}
    fn ipv6_drop(&self, _p: &Ipv6Packet, _c: &ClientInfo) {}
    fn ipv6_send(&self, _p: &MutableIpv6Packet, _c: &ClientInfo) {}
    /* ICMPv4 */
    fn icmpv4_enabled(&self) -> bool {
        true
    }
    fn icmpv4_recv(&self, _p: &IcmpPacket, _c: &ClientInfo) {}
    fn icmpv4_drop(&self, _p: &IcmpPacket, _c: &ClientInfo) {}
    fn icmpv4_send(&self, _p: &MutableIcmpPacket, _c: &ClientInfo) {}
    /* ICMPv6 */
    fn icmpv6_enabled(&self) -> bool {
        true
    }
    fn icmpv6_recv(&self, _p: &Icmpv6Packet, _c: &ClientInfo) {}
    fn icmpv6_drop(&self, _p: &Icmpv6Packet, _c: &ClientInfo) {}
    fn icmpv6_send(&self, _p: &MutableIcmpv6Packet, _c: &ClientInfo) {}
    /* TCP */
    fn tcp_enabled(&self) -> bool {
        true
    }
    fn tcp_recv(&self, _p: &TcpPacket, _c: &ClientInfo) {}
    fn tcp_drop(&self, _p: &TcpPacket, _c: &ClientInfo) {}
    fn tcp_send(&self, _p: &MutableTcpPacket, _c: &ClientInfo) {}
    /* UDP */
    fn udp_enabled(&self) -> bool {
        true
    }
    fn udp_recv(&self, _p: &UdpPacket, _c: &ClientInfo) {}
    fn udp_drop(&self, _p: &UdpPacket, _c: &ClientInfo) {}
    fn udp_send(&self, _p: &MutableUdpPacket, _c: &ClientInfo) {}
}
