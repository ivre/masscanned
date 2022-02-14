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
use std::net::IpAddr;

use pnet::packet::{
    arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket},
    /* Import needed for traits */
    Packet as _,
};

use crate::Masscanned;

pub fn repl<'a, 'b>(
    arp_req: &'a ArpPacket,
    masscanned: &Masscanned,
) -> Option<MutableArpPacket<'b>> {
    masscanned.log.arp_recv(arp_req);
    let mut arp_repl =
        MutableArpPacket::owned(arp_req.packet().to_vec()).expect("error parsing ARP packet");
    /* Build ARP answer depending of the type of request */
    match arp_req.get_operation() {
        ArpOperations::Request => {
            masscanned.log.arp_recv(arp_req);
            let ip = IpAddr::V4(arp_req.get_target_proto_addr());
            /* Ignore ARP requests for IP addresses not handled by masscanned */
            if let Some(ip_addr_list) = masscanned.ip_addresses {
                if !ip_addr_list.contains(&ip) {
                    masscanned.log.arp_drop(arp_req);
                    return None;
                }
            }
            /* Fill ARP reply */
            arp_repl.set_operation(ArpOperations::Reply);
            arp_repl.set_hardware_type(ArpHardwareTypes::Ethernet);
            arp_repl.set_sender_hw_addr(masscanned.mac);
            arp_repl.set_target_hw_addr(arp_req.get_sender_hw_addr().to_owned());
            arp_repl.set_target_proto_addr(arp_req.get_sender_proto_addr().to_owned());
            arp_repl.set_sender_proto_addr(arp_req.get_target_proto_addr().to_owned());
            masscanned.log.arp_send(&arp_repl);
        }
        _ => {
            info!("ARP Operation not handled: {:?}", arp_repl.get_operation());
            masscanned.log.arp_drop(arp_req);
            return None;
        }
    };
    masscanned.log.arp_send(&arp_repl);
    Some(arp_repl)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    use pnet::util::MacAddr;

    use crate::logger::MetaLogger;

    #[test]
    fn test_arp_reply() {
        let mut ips = HashSet::new();
        ips.insert(IpAddr::V4(Ipv4Addr::new(0, 1, 2, 3)));
        /* Construct masscanned context object */
        let masscanned = Masscanned {
            synack_key: [0, 0],
            mac: MacAddr::from_str("00:11:22:33:44:55").expect("error parsing MAC address"),
            iface: None,
            ip_addresses: Some(&ips),
            log: MetaLogger::new(),
        };
        let mut arp_req =
            MutableArpPacket::owned([0; 28].to_vec()).expect("error constructing ARP request");
        arp_req.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_req.set_operation(ArpOperations::Request);
        arp_req.set_sender_hw_addr(
            MacAddr::from_str("55:44:33:22:11:00").expect("error parsing MAC address"),
        );
        arp_req.set_target_hw_addr(
            MacAddr::from_str("00:00:00:00:00:00").expect("error parsing MAC address"),
        );
        arp_req.set_sender_proto_addr(Ipv4Addr::new(3, 2, 1, 0));
        /* Test getting an ARP reply for a legitimate IP address */
        arp_req.set_target_proto_addr(Ipv4Addr::new(0, 1, 2, 3));
        if let Some(arp_repl) = repl(&arp_req.to_immutable(), &masscanned) {
            assert!(arp_repl.get_hardware_type() == ArpHardwareTypes::Ethernet);
            assert!(arp_repl.get_operation() == ArpOperations::Reply);
            assert!(arp_repl.get_sender_hw_addr() == masscanned.mac);
            assert!(arp_repl.get_sender_proto_addr() == Ipv4Addr::new(0, 1, 2, 3));
        } else {
            panic!("Expected ARP reply - got None");
        }
        /* Ensure no response is returned for an other IP address */
        arp_req.set_target_proto_addr(Ipv4Addr::new(1, 1, 2, 3));
        let arp_repl = repl(&arp_req.to_immutable(), &masscanned);
        assert!(arp_repl == None);
    }
}
