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
use std::convert::From;
use std::net::{IpAddr, Ipv6Addr};

use pnet::packet::{
    icmpv6::ndp::{
        Icmpv6Codes, MutableNeighborAdvertPacket, NdpOption, NdpOptionPacket, NdpOptionTypes,
        NeighborAdvert, NeighborAdvertFlags, NeighborSolicitPacket,
    },
    icmpv6::{Icmpv6, Icmpv6Packet, Icmpv6Types, MutableIcmpv6Packet},
    Packet,
};

use crate::client::ClientInfo;
use crate::Masscanned;

pub fn nd_ns_repl<'a, 'b>(
    nd_ns_req: &'a NeighborSolicitPacket,
    masscanned: &Masscanned,
    _client_info: &ClientInfo,
) -> Option<MutableNeighborAdvertPacket<'b>> {
    debug!("receiving ND-NS packet: {:?}", nd_ns_req);
    /* If masscanned is configured with IP addresses, then
     * check that the dest. IP address of the packet is one of
     * those handled by masscanned - otherwise, drop the packet.
     **/
    if let Some(addresses) = masscanned.ip_addresses {
        if !addresses.contains(&IpAddr::V6(nd_ns_req.get_target_addr())) {
            return None;
        }
    }
    /* Set answer option to TargetLLAddr(2) */
    let ndp_opt = NdpOption {
        option_type: NdpOptionTypes::TargetLLAddr,
        /* From RFC 4861, section 4.6:
         * Length       8-bit unsigned integer.  The length of the option
         *              (including the type and length fields) in units of
         *              8 octets.  The value 0 is invalid.  Nodes MUST
         *              silently discard an ND packet that contains an
         *              option with length zero.
         **/
        length: 1,
        /* From RFC 4861, section 4.6:
         * Options should be padded when necessary to ensure that they end on
         * their natural 64-bit boundaries.
         * In this case, no need as 6 bytes (mac addr) + 2 bytes (option type
         * and length) = 8 bytes
         **/
        data: Vec::from(<[u8; 6]>::from(masscanned.mac)),
    };
    /* Compute site of options to construct ndp packet */
    let ndp_opt_size = NdpOptionPacket::packet_size(&ndp_opt);
    /* Neighbor advertisement response content */
    let ndp_na = NeighborAdvert {
        icmpv6_type: Icmpv6Types::NeighborAdvert,
        icmpv6_code: Icmpv6Codes::NoCode,
        checksum: 0,
        flags: NeighborAdvertFlags::Override | NeighborAdvertFlags::Solicited,
        reserved: 0,
        target_addr: nd_ns_req.get_target_addr(),
        options: vec![],
        payload: vec![],
    };
    /* Construct ND-NA response packet */
    let mut nd_na_repl = MutableNeighborAdvertPacket::owned(vec![
        0;
        /* Size includes the options */
        MutableNeighborAdvertPacket::packet_size(&ndp_na)
            + ndp_opt_size
    ])
    .expect("error constructing a ND-NA packet");
    /* Set content of response */
    nd_na_repl.populate(&ndp_na);
    /* Set content of options */
    nd_na_repl.set_options(&[ndp_opt]);
    warn!("ND-NA to ND-NS for {}", nd_ns_req.get_target_addr());
    debug!("sending ND-NA packet: {:?}", nd_na_repl);
    Some(nd_na_repl)
}

/* Because L3 may not know the dest. IPv6 address of the packet in the case
 * of a ND-NS packet, this function returns the reply *plus* the dest. IPv6
 * address in the case of a ND-NS, so that L3 knows to which masscanned IP
 * address the packet was targetting */
pub fn repl<'a, 'b>(
    icmp_req: &'a Icmpv6Packet,
    masscanned: &Masscanned,
    client_info: &ClientInfo,
) -> (Option<MutableIcmpv6Packet<'b>>, Option<Ipv6Addr>) {
    masscanned.log.icmpv6_recv(icmp_req, client_info);
    let mut dst_ip = None;
    if icmp_req.get_icmpv6_code() != Icmpv6Codes::NoCode {
        return (None, None);
    }
    let mut icmp_repl;
    match icmp_req.get_icmpv6_type() {
        /* Answer to a neighbor solicitation packet (aka ARP for IPv6) */
        Icmpv6Types::NeighborSolicit => {
            let nd_ns_req =
                NeighborSolicitPacket::new(icmp_req.packet()).expect("error parsing ND-NS packet");
            /* Construct the answer to the NS - should be a ND-NA */
            if let Some(nd_na_repl) = nd_ns_repl(&nd_ns_req, masscanned, &client_info) {
                dst_ip = Some(nd_ns_req.get_target_addr());
                icmp_repl = MutableIcmpv6Packet::owned(nd_na_repl.packet().to_vec())
                    .expect("error constructing an ICMPv6 packet");
            } else {
                masscanned.log.icmpv6_drop(icmp_req, client_info);
                return (None, None);
            }
        }
        /* Answer to an echo request packet */
        Icmpv6Types::EchoRequest => {
            /* Construct the echo reply packet */
            let echo_repl = Icmpv6 {
                icmpv6_type: Icmpv6Types::EchoReply,
                icmpv6_code: Icmpv6Codes::NoCode,
                checksum: 0,
                /* Same payload as the echo request */
                payload: icmp_req.payload().to_vec(),
            };
            icmp_repl = MutableIcmpv6Packet::owned(vec![0; Icmpv6Packet::packet_size(&echo_repl)])
                .expect("error constructing an ICMPv6 packet");
            icmp_repl.populate(&echo_repl);
        }
        _ => {
            masscanned.log.icmpv6_drop(icmp_req, client_info);
            return (None, None);
        }
    };
    masscanned.log.icmpv6_send(&icmp_repl, client_info);
    (Some(icmp_repl), dst_ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::net::Ipv6Addr;
    use std::str::FromStr;

    use pnet::packet::icmpv6::ndp::{MutableNeighborSolicitPacket, NeighborSolicit};
    use pnet::util::MacAddr;

    use crate::utils::MetaLogger;

    #[test]
    fn test_nd_na_reply() {
        let client_info = ClientInfo::new();
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
        /* Legitimate solicitation */
        let ndp_ns = NeighborSolicit {
            icmpv6_type: Icmpv6Types::NeighborSolicit,
            icmpv6_code: Icmpv6Codes::NoCode,
            checksum: 0,
            reserved: 0,
            target_addr: masscanned_ip_addr,
            options: vec![],
            payload: vec![],
        };
        let mut nd_ns = MutableNeighborSolicitPacket::owned(vec![
            0;
            /* Size includes the options */
            MutableNeighborSolicitPacket::packet_size(&ndp_ns)
                //+ ndp_opt_size
        ])
        .expect("error constructing ND-NS packet");
        nd_ns.populate(&ndp_ns);
        if let Some(nd_na) = nd_ns_repl(&nd_ns.to_immutable(), &masscanned, &client_info) {
            assert!(nd_na.get_icmpv6_code() == Icmpv6Codes::NoCode);
            assert!(nd_na.get_icmpv6_type() == Icmpv6Types::NeighborAdvert);
            assert!(nd_na.get_target_addr() == masscanned_ip_addr);
            assert!(nd_na.get_options().len() == 1);
            let nd_na_opt = &nd_na.get_options()[0];
            assert!(nd_na_opt.option_type == NdpOptionTypes::TargetLLAddr);
            assert!(nd_na_opt.data.len() == 6);
            assert!(nd_na_opt.length == 1);
            assert!(
                MacAddr::new(
                    nd_na_opt.data[0],
                    nd_na_opt.data[1],
                    nd_na_opt.data[2],
                    nd_na_opt.data[3],
                    nd_na_opt.data[4],
                    nd_na_opt.data[5]
                ) == masscanned.mac
            );
        } else {
            panic!("expected a ND NA answer, got None");
        }
        /* Solicitation for another IPv6 address */
        let ndp_ns = NeighborSolicit {
            icmpv6_type: Icmpv6Types::NeighborSolicit,
            icmpv6_code: Icmpv6Codes::NoCode,
            checksum: 0,
            reserved: 0,
            target_addr: Ipv6Addr::new(
                0x0000, 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x8888,
            ),
            options: vec![],
            payload: vec![],
        };
        nd_ns.populate(&ndp_ns);
        assert!(nd_ns_repl(&nd_ns.to_immutable(), &masscanned, &client_info) == None);
    }

    #[test]
    fn test_icmpv6_reply() {
        let payload = b"testpayload";
        let client_info = ClientInfo::new();
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
        let mut icmpv6_echo_req = MutableIcmpv6Packet::owned(vec![
            0;
            MutableIcmpv6Packet::minimum_packet_size()
                + payload.len()
        ])
        .expect("error constructing Icmpv6 packet");
        icmpv6_echo_req.set_icmpv6_code(Icmpv6Codes::NoCode);
        icmpv6_echo_req.set_icmpv6_type(Icmpv6Types::EchoRequest);
        icmpv6_echo_req.set_payload(payload);
        if let (Some(_icmpv6_echo_repl), _) =
            repl(&icmpv6_echo_req.to_immutable(), &masscanned, &client_info)
        {
        } else {
            panic!("expected ICMPv6 echo repy - got None");
        }
    }
}
