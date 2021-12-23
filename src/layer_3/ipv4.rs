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
use std::net::IpAddr;

use pnet::packet::{
    icmp::checksum as ipv4_checksum_icmp,
    icmp::IcmpPacket,
    ip::IpNextHeaderProtocols,
    ipv4::{Ipv4Flags, Ipv4Packet, MutableIpv4Packet},
    tcp::ipv4_checksum as ipv4_checksum_tcp,
    tcp::TcpPacket,
    udp::ipv4_checksum as ipv4_checksum_udp,
    udp::UdpPacket,
    Packet,
};

use crate::client::ClientInfo;
use crate::layer_4;
use crate::Masscanned;

pub fn repl<'a, 'b>(
    ip_req: &'a Ipv4Packet,
    masscanned: &Masscanned,
    mut client_info: &mut ClientInfo,
) -> Option<MutableIpv4Packet<'b>> {
    debug!("receiving IPv4 packet: {:?}", ip_req);
    /* If masscanned is configured with IP addresses, then
     * check that the dest. IP address of the packet is one of
     * those handled by masscanned - otherwise, drop the packet.
     **/
    if let Some(ip_addr_list) = masscanned.ip_addresses {
        if !ip_addr_list.contains(&IpAddr::V4(ip_req.get_destination())) {
            info!(
                "Ignoring IP packet from {} for {}",
                ip_req.get_source(),
                ip_req.get_destination()
            );
            return None;
        }
    }
    /* Fill client info with source and dest. IP addresses */
    client_info.ip.src = Some(IpAddr::V4(ip_req.get_source()));
    client_info.ip.dst = Some(IpAddr::V4(ip_req.get_destination()));
    /* Fill client info with transport layer procotol */
    client_info.transport = Some(ip_req.get_next_level_protocol());
    let mut ip_repl;
    match ip_req.get_next_level_protocol() {
        /* Answer to an ICMP packet */
        IpNextHeaderProtocols::Icmp => {
            let icmp_req = IcmpPacket::new(ip_req.payload()).expect("error parsing ICMP packet");
            if let Some(mut icmp_repl) = layer_4::icmpv4::repl(&icmp_req, masscanned, &client_info)
            {
                icmp_repl.set_checksum(ipv4_checksum_icmp(&icmp_repl.to_immutable()));
                let icmp_len = icmp_repl.packet().len();
                let ip_len = MutableIpv4Packet::minimum_packet_size() + icmp_len;
                ip_repl = MutableIpv4Packet::owned(vec![0; ip_len])
                    .expect("error constructing an IPv4 packet");
                ip_repl.set_total_length(ip_len as u16);
                // FIXME
                ip_repl.set_header_length(5);
                ip_repl.set_payload(icmp_repl.packet());
                ip_repl.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
            } else {
                return None;
            }
        }
        /* Answer to a TCP packet */
        IpNextHeaderProtocols::Tcp => {
            let tcp_req = TcpPacket::new(ip_req.payload()).expect("error parsing TCP packet");
            if let Some(mut tcp_repl) = layer_4::tcp::repl(&tcp_req, masscanned, &mut client_info) {
                tcp_repl.set_checksum(ipv4_checksum_tcp(
                    &tcp_repl.to_immutable(),
                    &ip_req.get_destination(),
                    &ip_req.get_source(),
                ));
                let tcp_len = tcp_repl.packet().len();
                let ip_len = Ipv4Packet::minimum_packet_size() + tcp_len;
                ip_repl = MutableIpv4Packet::owned(vec![0; ip_len])
                    .expect("error constructing an IPv4 packet");
                ip_repl.set_total_length(ip_len as u16);
                // FIXME
                ip_repl.set_header_length(5);
                ip_repl.set_payload(tcp_repl.packet());
                ip_repl.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
            } else {
                return None;
            }
        }
        /* Answer to an UDP packet */
        IpNextHeaderProtocols::Udp => {
            let udp_req = UdpPacket::new(ip_req.payload()).expect("error parsing UDP packet");
            if let Some(mut udp_repl) = layer_4::udp::repl(&udp_req, masscanned, &mut client_info) {
                udp_repl.set_checksum(ipv4_checksum_udp(
                    &udp_repl.to_immutable(),
                    &ip_req.get_destination(),
                    &ip_req.get_source(),
                ));
                let udp_len = udp_repl.packet().len();
                udp_repl.set_length(udp_len.try_into().unwrap());
                debug!("udp len: {}", udp_len);
                let ip_len = Ipv4Packet::minimum_packet_size() + udp_len;
                ip_repl = MutableIpv4Packet::owned(vec![0; ip_len])
                    .expect("error constructing an IPv4 packet");
                ip_repl.set_total_length(ip_len as u16);
                // FIXME
                ip_repl.set_header_length(5);
                ip_repl.set_payload(udp_repl.packet());
                ip_repl.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            } else {
                return None;
            }
        }
        /* Next layer protocol not handled (yet) - dropping packet */
        _ => {
            info!(
                "IPv4 upper layer not handled: {:?}",
                ip_req.get_next_level_protocol()
            );
            return None;
        }
    };
    /* Set IP packet fields before sending */
    ip_repl.set_version(4);
    ip_repl.set_ttl(64);
    ip_repl.set_identification(0);
    /* These values are already initialized with 0s
     * ip_repl.set_dscp(0);
     * ip_repl.set_ecn(0);
     * ip_repl.set_identification(0);
     **/
    /* Do not fragment packet */
    ip_repl.set_flags(Ipv4Flags::DontFragment);
    /* Set source and dest. IP address */
    /* FIXME when dest. was a multicast IP address */
    ip_repl.set_source(ip_req.get_destination());
    ip_repl.set_destination(ip_req.get_source());
    debug!("sending IPv4 packet: {:?}", ip_repl);
    Some(ip_repl)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    use pnet::util::MacAddr;

    use crate::utils::MetaLogger;

    #[test]
    fn test_ipv4_reply() {
        /* test payload is scapy> ICMP() */
        let payload = b"\x08\x00\xf7\xff\x00\x00\x00\x00";
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
        let mut ip_req =
            MutableIpv4Packet::owned(vec![0; Ipv4Packet::minimum_packet_size() + payload.len()])
                .expect("error constructing IPv4 packet");
        ip_req.set_version(4);
        ip_req.set_ttl(64);
        ip_req.set_identification(0);
        ip_req.set_flags(Ipv4Flags::DontFragment);
        ip_req.set_source(test_ip_addr);
        ip_req.set_header_length(5);
        /* Set test payload for layer 4 */
        ip_req.set_total_length(ip_req.packet().len() as u16);
        ip_req.set_payload(payload);
        /* Set next protocol */
        ip_req.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
        /* Send to a legitimate IP address */
        ip_req.set_destination(masscanned_ip_addr);
        if let Some(ip_repl) = repl(&ip_req.to_immutable(), &masscanned, &mut client_info) {
            assert!(ip_repl.get_destination() == test_ip_addr);
            assert!(ip_repl.get_source() == masscanned_ip_addr);
            assert!(ip_repl.get_next_level_protocol() == IpNextHeaderProtocols::Icmp);
            assert!(ip_repl.get_total_length() == ip_repl.packet().len() as u16);
        } else {
            panic!("expected an IP answer, got None");
        }
        /* Send to a non-legitimate IP address */
        ip_req.set_destination(Ipv4Addr::new(2, 2, 2, 2));
        assert!(repl(&ip_req.to_immutable(), &masscanned, &mut client_info) == None);
    }
}
