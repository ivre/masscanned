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
    icmp::{IcmpCode, IcmpPacket, IcmpTypes, MutableIcmpPacket},
    Packet,
};

use crate::client::ClientInfo;
use crate::Masscanned;

pub fn repl<'a, 'b>(
    icmp_req: &'a IcmpPacket,
    masscanned: &Masscanned,
    client_info: &ClientInfo,
) -> Option<MutableIcmpPacket<'b>> {
    masscanned.log.icmpv4_recv(icmp_req, client_info);
    let mut icmp_repl;
    match icmp_req.get_icmp_type() {
        IcmpTypes::EchoRequest => {
            /* Check code of ICMP packet */
            if icmp_req.get_icmp_code() != IcmpCode(0) {
                masscanned.log.icmpv4_drop(icmp_req, client_info);
                return None;
            }
            /* Compute answer length */
            let payload_len = icmp_req.payload().len();
            let icmp_len = MutableIcmpPacket::minimum_packet_size() + payload_len;
            /* Construct answer packet */
            icmp_repl = MutableIcmpPacket::owned(vec![0; icmp_len])
                .expect("error constructing an ICMP packet");
            /* Set ICMP type and code */
            icmp_repl.set_icmp_type(IcmpTypes::EchoReply);
            icmp_repl.set_icmp_code(IcmpCode(0));
            /* Set payload identical to incoming packet
             * See RFC 792 - https://datatracker.ietf.org/doc/html/rfc792 p15
             * "The data received in the echo message must be returned in the echo
             * reply message."
             **/
            icmp_repl.set_payload(icmp_req.payload());
        }
        _ => {
            masscanned.log.icmpv4_drop(icmp_req, client_info);
            return None;
        }
    };
    masscanned.log.icmpv4_send(&icmp_repl, client_info);
    Some(icmp_repl)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    use pnet::util::MacAddr;

    use crate::logger::MetaLogger;

    #[test]
    fn test_icmpv4_reply() {
        /* test payload is scapy> ICMP() */
        let payload = b"testpayload";
        let mut client_info = ClientInfo::new();
        /* Construct masscanned context object */
        let masscanned = Masscanned {
            synack_key: [0, 0],
            mac: MacAddr::from_str("00:11:22:33:44:55").expect("error parsing MAC address"),
            iface: None,
            ip_addresses: None,
            log: MetaLogger::new(),
        };
        let mut icmp_req =
            MutableIcmpPacket::owned(vec![0; IcmpPacket::minimum_packet_size() + payload.len()])
                .expect("error constructing ICMPv4 packet");
        /* Set ICMP payload */
        icmp_req.set_payload(payload);
        /* Set legitimate ICMP type and code */
        icmp_req.set_icmp_type(IcmpTypes::EchoRequest);
        icmp_req.set_icmp_code(IcmpCode(0));
        if let Some(icmp_repl) = repl(&icmp_req.to_immutable(), &masscanned, &mut client_info) {
            assert!(icmp_repl.get_icmp_type() == IcmpTypes::EchoReply);
            assert!(icmp_repl.get_icmp_code() == IcmpCode(0));
            assert!(icmp_repl.payload() == payload);
        } else {
            panic!("expected an IP answer, got None");
        }
        /* Set wrong code */
        icmp_req.set_icmp_code(IcmpCode(1));
        assert!(repl(&icmp_req.to_immutable(), &masscanned, &mut client_info) == None);
        /* Set wrong type */
        icmp_req.set_icmp_code(IcmpCode(0));
        icmp_req.set_icmp_type(IcmpTypes::EchoReply);
        assert!(repl(&icmp_req.to_immutable(), &masscanned, &mut client_info) == None);
        /* Try with another payload */
        icmp_req.set_icmp_type(IcmpTypes::EchoRequest);
        let payload = b"newpayload!";
        icmp_req.set_payload(payload);
        if let Some(icmp_repl) = repl(&icmp_req.to_immutable(), &masscanned, &mut client_info) {
            assert!(icmp_repl.get_icmp_type() == IcmpTypes::EchoReply);
            assert!(icmp_repl.get_icmp_code() == IcmpCode(0));
            assert!(icmp_repl.payload() == payload);
        } else {
            panic!("expected an IP answer, got None");
        }
    }
}
