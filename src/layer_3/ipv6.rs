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

use std::net::IpAddr;

use pnet::packet::{
    icmpv6::{checksum as icmpv6_checksum, Icmpv6Packet, Icmpv6Types},
    ip::IpNextHeaderProtocols,
    ipv6::{Ipv6Packet, MutableIpv6Packet},
    tcp::{ipv6_checksum as ipv6_checksum_tcp, TcpPacket},
    udp::{ipv6_checksum as ipv6_checksum_udp, UdpPacket},
    Packet,
};

use crate::client::ClientInfo;
use crate::layer_4;
use crate::Masscanned;

pub fn repl<'a, 'b>(
    ip_req: &'a Ipv6Packet,
    masscanned: &Masscanned,
    mut client_info: &mut ClientInfo,
) -> Option<MutableIpv6Packet<'b>> {
    /* Fill client info with source and dest. IP address */
    client_info.ip.src = Some(IpAddr::V6(ip_req.get_source()));
    client_info.ip.dst = Some(IpAddr::V6(ip_req.get_destination()));
    masscanned.log.ipv6_recv(ip_req, client_info);
    let src = ip_req.get_source();
    let mut dst = ip_req.get_destination();
    /* If masscanned is configured with IP addresses, check that
     * the dest. IP address corresponds to one of those
     * Otherwise, drop the packet.
     **/
    if let Some(ip_addr_list) = masscanned.ip_addresses {
        if !ip_addr_list.contains(&IpAddr::V6(dst))
            && ip_req.get_next_header() != IpNextHeaderProtocols::Icmpv6
        {
            masscanned.log.ipv6_drop(ip_req, client_info);
            return None;
        }
    }
    /* Fill client info with source and dest. IP address */
    client_info.ip.src = Some(IpAddr::V6(ip_req.get_source()));
    client_info.ip.dst = Some(IpAddr::V6(ip_req.get_destination()));
    /* Fill client info with transport layer procotol */
    client_info.transport = Some(ip_req.get_next_header());
    let mut ip_repl;
    match ip_req.get_next_header() {
        /* Answer to ICMPv6 */
        IpNextHeaderProtocols::Icmpv6 => {
            let icmp_req =
                Icmpv6Packet::new(ip_req.payload()).expect("error parsing ICMPv6 packet");
            if let (Some(mut icmp_repl), dst_addr) =
                layer_4::icmpv6::repl(&icmp_req, masscanned, &client_info)
            {
                if let Some(ip) = dst_addr {
                    dst = ip;
                }
                /* Compute checksum of upper layer */
                icmp_repl.set_checksum(icmpv6_checksum(&icmp_repl.to_immutable(), &src, &dst));
                /* Compute answer length */
                let icmp_len = icmp_repl.packet().len();
                let ip_len = MutableIpv6Packet::minimum_packet_size() + icmp_len;
                /* Create answer packet */
                ip_repl = MutableIpv6Packet::owned(vec![0; ip_len])
                    .expect("error constructing an IPv6 packet");
                /* Set next header protocol and payload */
                ip_repl.set_next_header(IpNextHeaderProtocols::Icmpv6);
                ip_repl.set_payload_length(icmp_len as u16);
                ip_repl.set_payload(&icmp_repl.packet().to_vec());
                /* Special value of hlim for ICMP */
                if let Icmpv6Types::NeighborAdvert = icmp_repl.get_icmpv6_type() {
                    ip_repl.set_hop_limit(255);
                };
            } else {
                masscanned.log.ipv6_drop(ip_req, client_info);
                return None;
            }
        }
        /* Answer to TCP */
        IpNextHeaderProtocols::Tcp => {
            let tcp_req = TcpPacket::new(ip_req.payload()).expect("error parsing TCP packet");
            if let Some(mut tcp_repl) = layer_4::tcp::repl(&tcp_req, masscanned, &mut client_info) {
                /* Compute and set TCP checksum */
                tcp_repl.set_checksum(ipv6_checksum_tcp(
                    &tcp_repl.to_immutable(),
                    &ip_req.get_destination(),
                    &ip_req.get_source(),
                ));
                /* Compute answer length */
                let tcp_len = tcp_repl.packet().len();
                let ip_len = Ipv6Packet::minimum_packet_size() + tcp_len;
                /* Create answer packet */
                ip_repl = MutableIpv6Packet::owned(vec![0; ip_len])
                    .expect("error constructing an IPv6 packet");
                /* Set next header protocol and payload */
                ip_repl.set_next_header(IpNextHeaderProtocols::Tcp);
                ip_repl.set_payload_length(tcp_len as u16);
                ip_repl.set_payload(&tcp_repl.packet());
            } else {
                masscanned.log.ipv6_drop(ip_req, client_info);
                return None;
            }
        }
        /* Answer to UDP */
        IpNextHeaderProtocols::Udp => {
            let udp_req = UdpPacket::new(ip_req.payload()).expect("error parsing UDP packet");
            if let Some(mut udp_repl) = layer_4::udp::repl(&udp_req, masscanned, &mut client_info) {
                /* Compute and set UDP checksum */
                udp_repl.set_checksum(ipv6_checksum_udp(
                    &udp_repl.to_immutable(),
                    &ip_req.get_destination(),
                    &ip_req.get_source(),
                ));
                /* Compute answer length */
                let udp_len = udp_repl.packet().len();
                let ip_len = Ipv6Packet::minimum_packet_size() + udp_len;
                /* Create answer packet */
                ip_repl = MutableIpv6Packet::owned(vec![0; ip_len])
                    .expect("error constructing an IPv6 packet");
                /* Set next header protocol and payload */
                ip_repl.set_next_header(IpNextHeaderProtocols::Udp);
                ip_repl.set_payload_length(udp_len as u16);
                ip_repl.set_payload(&udp_repl.packet());
            } else {
                masscanned.log.ipv6_drop(ip_req, client_info);
                return None;
            }
        }
        /* Other protocols are not handled (yet) - dropping */
        _ => {
            masscanned.log.ipv6_drop(ip_req, client_info);
            return None;
        }
    };
    /* If not already set, we set the hlim value */
    if ip_repl.get_hop_limit() == 0 {
        ip_repl.set_hop_limit(64);
    }
    /* Set IP version */
    ip_repl.set_version(6);
    /* Set packet source and dest. */
    ip_repl.set_source(dst);
    ip_repl.set_destination(src);
    masscanned.log.ipv6_send(&ip_repl, client_info);
    Some(ip_repl)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::net::Ipv6Addr;
    use std::str::FromStr;

    use pnet::util::MacAddr;

    use crate::utils::MetaLogger;

    #[test]
    fn test_ipv6_reply() {
        /* test payload is scapy> IPv6(src="7777:6666:5555:4444:3333:2222:1111:0000",
         * dst="0000:1111:2222:3333:4444:5555:6666:7777")/TCP(sport=12345, dport=54321,
         * flags="S"))[TCP] */
        let payload = b"09\xd41\x00\x00\x00\x00\x00\x00\x00\x00P\x02 \x00\xcf\xbc\x00\x00";
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
        let mut ip_req =
            MutableIpv6Packet::owned(vec![0; Ipv6Packet::minimum_packet_size() + payload.len()])
                .expect("error constructing IPv6 packet");
        ip_req.set_version(6);
        ip_req.set_source(test_ip_addr);
        /* Set test payload for layer 4 */
        ip_req.set_payload_length(payload.len() as u16);
        ip_req.set_payload(payload);
        /* Set next protocol */
        ip_req.set_next_header(IpNextHeaderProtocols::Tcp);
        /* Send to a legitimate IP address */
        ip_req.set_destination(masscanned_ip_addr);
        if let Some(ip_repl) = repl(&ip_req.to_immutable(), &masscanned, &mut client_info) {
            assert!(ip_repl.get_destination() == test_ip_addr);
            assert!(ip_repl.get_source() == masscanned_ip_addr);
            assert!(ip_repl.get_next_header() == IpNextHeaderProtocols::Tcp);
            assert!(ip_repl.get_payload_length() == ip_repl.payload().len() as u16);
        } else {
            panic!("expected an IP answer, got None");
        }
        /* Send to a non-legitimate IP address */
        ip_req.set_destination(Ipv6Addr::new(
            0x0000, 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7778,
        ));
        assert!(repl(&ip_req.to_immutable(), &masscanned, &mut client_info) == None);
    }
}
