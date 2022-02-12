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
use std::collections::HashSet;
use std::net::IpAddr;

use pnet::packet::{
    arp::ArpPacket,
    ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
    ipv4::checksum as ipv4_checksum,
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    Packet as Pkt,
};
use pnet::util::MacAddr;

use crate::client::ClientInfo;
use crate::layer_3;
use crate::Masscanned;

pub mod arp;

/* representation of a 6-bytes Ethernet address */
type EtherAddr = [u8; 6];

/* This function builds the list of layer-2 destination addresses
 * that masscanned is authorized to answer to. It includes:
 * - masscanned own MAC address,
 * - layer 2 broadcast MAC addresses,
 * - layer 2 IPv6 multicast MAC address,
 * - layer 2 IPv6 solicited-node multicast addresses for each IPv6 address
 *      of masscanned
 **/
pub fn get_authorized_eth_addr(
    mac: &MacAddr,
    ip_addresses: Option<&HashSet<IpAddr>>,
) -> HashSet<MacAddr> {
    let mut auth_addr = HashSet::new();
    auth_addr.insert(MacAddr::broadcast());
    auth_addr.insert(*mac);
    /* add IPv6 multicast addr */
    auth_addr.insert(
        "33:33:00:00:00:01"
            .parse()
            .expect("error parsing generic MAC address"),
    );
    /* Add:
     * - IPv4 multicast address for every IPv4
     * - IPv6 Solicited-Node multicast address for every IPv6
     **/
    if let Some(ip_addr) = ip_addresses {
        for addr in ip_addr {
            match addr {
                IpAddr::V4(ipv4) => {
                    let mut eth_ma: EtherAddr = [0; 6];
                    eth_ma[0] = 0x01;
                    eth_ma[1] = 0x00;
                    eth_ma[2] = 0x5e;
                    /* RFC 1112 - https://datatracker.ietf.org/doc/html/rfc1112
                     * Section 6.4:
                     * An IP host group address is mapped to an Ethernet multicast address
                     * by placing the low-order 23-bits of the IP address into the low-order
                     * 23 bits of the Ethernet multicast address 01-00-5E-00-00-00 (hex).
                     **/
                    eth_ma[3] = ipv4.octets()[1] & 0x7f;
                    eth_ma[4] = ipv4.octets()[2];
                    eth_ma[5] = ipv4.octets()[3];
                    auth_addr.insert(MacAddr::from(eth_ma));
                }
                IpAddr::V6(ipv6) => {
                    let mut eth_snma: EtherAddr = [0; 6];
                    eth_snma[0] = 0x33;
                    eth_snma[1] = 0x33;
                    /* multicast MAC address corresponding to solicited-node
                     * multicast IPv6 address */
                    eth_snma[2] = 0xff;
                    eth_snma[3] = ipv6.octets()[13];
                    eth_snma[4] = ipv6.octets()[14];
                    eth_snma[5] = ipv6.octets()[15];
                    auth_addr.insert(MacAddr::from(eth_snma));
                }
            }
        }
    }
    auth_addr
}

pub fn reply<'a, 'b>(
    eth_req: &'a EthernetPacket,
    masscanned: &Masscanned,
    mut client_info: &mut ClientInfo,
) -> Option<MutableEthernetPacket<'b>> {
    masscanned.log.eth_recv(eth_req, &client_info);
    let mut eth_repl;
    /* First, check if the destination MAC address is one of those masscanned
     * is authorized to answer to (avoid answering to packets addressed to
     * other machines)
     **/
    if !get_authorized_eth_addr(&masscanned.mac, masscanned.ip_addresses)
        .contains(&eth_req.get_destination())
    {
        masscanned.log.eth_drop(eth_req, &client_info);
        return None;
    }
    /* Fill client information for this packet with MAC addresses (src and dst) */
    client_info.mac.src = Some(eth_req.get_source());
    client_info.mac.dst = Some(eth_req.get_destination());
    /* Build next layer payload for answer depending on the incoming packet */
    match eth_req.get_ethertype() {
        /* Construct answer to ARP request */
        EtherTypes::Arp => {
            let arp_req = ArpPacket::new(eth_req.payload()).expect("error parsing ARP packet");
            if let Some(arp_repl) = arp::repl(&arp_req, masscanned) {
                let arp_len = arp_repl.packet().len();
                let eth_len = EthernetPacket::minimum_packet_size() + arp_len;
                eth_repl = MutableEthernetPacket::owned(vec![0; eth_len])
                    .expect("error constructing an Ethernet Packet");
                eth_repl.set_ethertype(EtherTypes::Arp);
                eth_repl.set_payload(arp_repl.packet());
            } else {
                masscanned.log.eth_drop(eth_req, &client_info);
                return None;
            }
        }
        /* Construct answer to IPv4 packet */
        EtherTypes::Ipv4 => {
            let ipv4_req = if let Some(p) = Ipv4Packet::new(eth_req.payload()) {
                p
            } else {
                warn!("error parsing IPv4 packet");
                masscanned.log.eth_drop(eth_req, &client_info);
                return None;
            };
            if let Some(mut ipv4_repl) =
                layer_3::ipv4::repl(&ipv4_req, masscanned, &mut client_info)
            {
                ipv4_repl.set_checksum(ipv4_checksum(&ipv4_repl.to_immutable()));
                let ipv4_len = ipv4_repl.packet().len();
                let eth_len = EthernetPacket::minimum_packet_size() + ipv4_len;
                eth_repl = MutableEthernetPacket::owned(vec![0; eth_len])
                    .expect("error constructing an Ethernet Packet");
                eth_repl.set_ethertype(EtherTypes::Ipv4);
                eth_repl.set_payload(ipv4_repl.packet());
            } else {
                masscanned.log.eth_drop(eth_req, &client_info);
                return None;
            }
        }
        /* Construct answer to IPv6 packet */
        EtherTypes::Ipv6 => {
            let ipv6_req = Ipv6Packet::new(eth_req.payload()).expect("error parsing IPv6 packet");
            if let Some(ipv6_repl) = layer_3::ipv6::repl(&ipv6_req, masscanned, &mut client_info) {
                let ipv6_len = ipv6_repl.packet().len();
                let eth_len = EthernetPacket::minimum_packet_size() + ipv6_len;
                eth_repl = MutableEthernetPacket::owned(vec![0; eth_len])
                    .expect("error constructing an Ethernet Packet");
                eth_repl.set_ethertype(EtherTypes::Ipv6);
                eth_repl.set_payload(ipv6_repl.packet());
            } else {
                masscanned.log.eth_drop(eth_req, &client_info);
                return None;
            }
        }
        /* Log & drop unknown network protocol */
        _ => {
            info!("Ethernet type not handled: {:?}", eth_req.get_ethertype());
            masscanned.log.eth_drop(eth_req, &client_info);
            return None;
        }
    };
    eth_repl.set_source(masscanned.mac);
    eth_repl.set_destination(eth_req.get_source());
    masscanned.log.eth_send(&eth_repl, &client_info);
    Some(eth_repl)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    use crate::utils::MetaLogger;

    #[test]
    fn test_eth_reply() {
        /* test payload is IP(src="3.2.1.0", dst=".".join(str(b) for b in [0xaa, 0x99,
         * 0x88, 0x77]))/ICMP() */
        let payload = b"E\x00\x00\x1c\x00\x01\x00\x00@\x01C\xce\x03\x02\x01\x00\xaa\x99\x88w\x08\x00\xf7\xff\x00\x00\x00\x00";
        let test_mac_addr =
            MacAddr::from_str("55:44:33:22:11:00").expect("error parsing MAC address");
        let mut client_info = ClientInfo::new();
        let mut ips = HashSet::new();
        ips.insert(IpAddr::V4(Ipv4Addr::new(0xaa, 0x99, 0x88, 0x77)));
        ips.insert(IpAddr::V6(Ipv6Addr::new(
            0x7777, 0x7777, 0x7777, 0x7777, 0x7777, 0x7777, 0xaabb, 0xccdd,
        )));
        /* Construct masscanned context object */
        let masscanned = Masscanned {
            synack_key: [0, 0],
            mac: MacAddr::from_str("00:11:22:33:44:55").expect("error parsing MAC address"),
            iface: None,
            ip_addresses: Some(&ips),
            log: MetaLogger::new(),
        };
        let mut eth_req = MutableEthernetPacket::owned(vec![
            0;
            EthernetPacket::minimum_packet_size()
                + payload.len()
        ])
        .expect("error constructing ethernet packet");
        eth_req.set_source(test_mac_addr);
        eth_req.set_payload(payload);
        /* Test answer to legitimate dest. */
        let dest_mac = [
            masscanned.mac,
            MacAddr::from_str("ff:ff:ff:ff:ff:ff").unwrap(),
            MacAddr::from_str("01:00:5e:19:88:77").unwrap(),
            MacAddr::from_str("33:33:ff:bb:cc:dd").unwrap(),
        ];
        for mac in dest_mac.iter() {
            println!("testing mac: {:?}", mac);
            eth_req.set_ethertype(EtherTypes::Ipv4);
            eth_req.set_destination(*mac);
            if let Some(eth_repl) = reply(&eth_req.to_immutable(), &masscanned, &mut client_info) {
                assert!(eth_repl.get_source() == masscanned.mac);
                assert!(eth_repl.get_destination() == test_mac_addr);
                assert!(eth_repl.get_ethertype() == EtherTypes::Ipv4);
            } else {
                panic!("expected an Ethernet answer, got None");
            }
        }
        /* Test answer to non-legitimate dest. */
        let dest_mac = [
            MacAddr::from_str("aa:bb:cc:dd:ee:ff").unwrap(),
            MacAddr::from_str("ff:ff:ff:ff:ff:fe").unwrap(),
            MacAddr::from_str("01:00:5e:00:11:22").unwrap(),
            MacAddr::from_str("33:33:aa:bb:cc:de").unwrap(),
            MacAddr::from_str("01:00:5e:99:88:77").unwrap(),
            MacAddr::from_str("33:33:aa:bb:cc:dd").unwrap(),
        ];
        for mac in dest_mac.iter() {
            println!("testing mac: {:?}", mac);
            eth_req.set_ethertype(EtherTypes::Ipv4);
            eth_req.set_destination(*mac);
            let eth_repl = reply(&eth_req.to_immutable(), &masscanned, &mut client_info);
            assert!(eth_repl == None);
        }
    }
}
