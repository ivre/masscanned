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

use pnet::packet::{
    tcp::{MutableTcpPacket, TcpFlags, TcpPacket},
    Packet,
};

use crate::client::ClientInfo;
use crate::proto;
use crate::synackcookie;
use crate::Masscanned;

pub fn repl<'a, 'b>(
    tcp_req: &'a TcpPacket,
    masscanned: &Masscanned,
    mut client_info: &mut ClientInfo,
) -> Option<MutableTcpPacket<'b>> {
    masscanned.log.tcp_recv(tcp_req, client_info);
    /* Fill client info with source and dest. TCP port */
    client_info.port.src = Some(tcp_req.get_source());
    client_info.port.dst = Some(tcp_req.get_destination());
    /* Construct response TCP packet */
    let mut tcp_repl;
    match tcp_req.get_flags() {
        /* Answer to data */
        flags if flags & (TcpFlags::PSH | TcpFlags::ACK) == (TcpFlags::PSH | TcpFlags::ACK) => {
            /* First check the synack cookie */
            let ackno = if tcp_req.get_acknowledgement() > 0 {
                tcp_req.get_acknowledgement() - 1
            } else {
                /* underflow hack */
                0xFFFFFFFF
            };
            /* Compute syncookie */
            if let Ok(cookie) = synackcookie::generate(&client_info, &masscanned.synack_key) {
                client_info.cookie = Some(cookie);
                if !proto::is_tcb_set(cookie) {
                    /* First Ack: check syncookie, create tcb */
                    if cookie != ackno {
                        masscanned.log.tcp_drop(tcp_req, client_info);
                        return None;
                    }
                    proto::add_tcb(cookie);
                }
            }
            warn!("ACK to PSH-ACK on port {}", tcp_req.get_destination());
            let payload = tcp_req.payload();
            /* Any answer to upper-layer protocol? */
            let mut payload_repl = None;
            proto::get_tcb(client_info.cookie.unwrap(), |tcb| {
                payload_repl = proto::repl(&payload, masscanned, &mut client_info, tcb);
            });
            if let Some(repl) = payload_repl {
                tcp_repl = MutableTcpPacket::owned(
                    [vec![0; MutableTcpPacket::minimum_packet_size()], repl].concat(),
                )
                .expect("error constructing a TCP packet");
                tcp_repl.set_flags(TcpFlags::ACK | TcpFlags::PSH);
            } else {
                tcp_repl =
                    MutableTcpPacket::owned(vec![0; MutableTcpPacket::minimum_packet_size()])
                        .expect("error constructing a TCP packet");
                tcp_repl.set_flags(TcpFlags::ACK);
            }
            tcp_repl.set_acknowledgement(tcp_req.get_sequence() + (tcp_req.payload().len() as u32));
            tcp_repl.set_sequence(tcp_req.get_acknowledgement());
        }
        /* Answer to ACK: nothing */
        flags if flags == TcpFlags::ACK => {
            /* answer here when server needs to speak first after handshake */
            masscanned.log.tcp_drop(tcp_req, client_info);
            return None;
        }
        /* Answer to RST: nothing */
        flags if flags == TcpFlags::RST => {
            masscanned.log.tcp_drop(tcp_req, client_info);
            return None;
        }
        /* Answer to FIN,ACK with FIN,ACK */
        flags if flags == (TcpFlags::FIN | TcpFlags::ACK) => {
            tcp_repl = MutableTcpPacket::owned(vec![0; MutableTcpPacket::minimum_packet_size()])
                .expect("error constructing a TCP packet");
            tcp_repl.set_flags(TcpFlags::FIN | TcpFlags::ACK);
            tcp_repl.set_acknowledgement(tcp_req.get_sequence() + 1);
            tcp_repl.set_sequence(tcp_req.get_acknowledgement());
        }
        /* Answer to SYN */
        flags if flags & TcpFlags::SYN == TcpFlags::SYN => {
            tcp_repl = MutableTcpPacket::owned(vec![0; MutableTcpPacket::minimum_packet_size()])
                .expect("error constructing a TCP packet");
            tcp_repl.set_flags(TcpFlags::ACK);
            tcp_repl.set_flags(TcpFlags::SYN | TcpFlags::ACK);
            tcp_repl.set_acknowledgement(tcp_req.get_sequence() + 1);
            /* generate a SYNACK-cookie (same as masscan) */
            tcp_repl.set_sequence(
                synackcookie::generate(&client_info, &masscanned.synack_key).unwrap(),
            );
        }
        _ => {
            masscanned.log.tcp_drop(tcp_req, client_info);
            return None;
        }
    }
    /* Set source and dest. port for response packet from client info */
    /* Note: client info could have been modified by upper layers (e.g., STUN) */
    tcp_repl.set_source(client_info.port.dst.unwrap());
    tcp_repl.set_destination(client_info.port.src.unwrap());
    /* Set TCP headers */
    tcp_repl.set_data_offset(5);
    tcp_repl.set_window(65535);
    masscanned.log.tcp_send(&tcp_repl, client_info);
    Some(tcp_repl)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::ClientInfoSrcDst;
    use pnet::util::MacAddr;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use crate::logger::MetaLogger;

    #[test]
    fn test_tcp_fin_ack() {
        let masscanned = Masscanned {
            mac: MacAddr(0, 0, 0, 0, 0, 0),
            ip_addresses: None,
            synack_key: [0x06a0a1d63f305e9b, 0xd4d4bcbb7304875f],
            iface: None,
            log: MetaLogger::new(),
        };
        /* reference */
        let ip_src = IpAddr::V4(Ipv4Addr::new(27, 198, 143, 1));
        let ip_dst = IpAddr::V4(Ipv4Addr::new(90, 64, 122, 203));
        let tcp_sport = 65500;
        let tcp_dport = 80;
        let seq = 1234567;
        let ack = 7654321;
        let mut client_info = ClientInfo {
            mac: ClientInfoSrcDst {
                src: None,
                dst: None,
            },
            ip: ClientInfoSrcDst {
                src: Some(ip_src),
                dst: Some(ip_dst),
            },
            transport: None,
            port: ClientInfoSrcDst {
                src: Some(tcp_sport),
                dst: Some(tcp_dport),
            },
            cookie: None,
        };
        let mut tcp_req =
            MutableTcpPacket::owned(vec![0; MutableTcpPacket::minimum_packet_size()]).unwrap();
        tcp_req.set_source(tcp_sport);
        tcp_req.set_destination(tcp_dport);
        tcp_req.set_sequence(seq);
        tcp_req.set_acknowledgement(ack);
        tcp_req.set_flags(TcpFlags::FIN | TcpFlags::ACK);
        let some_tcp_repl = repl(&tcp_req.to_immutable(), &masscanned, &mut client_info);
        if some_tcp_repl == None {
            panic!("expected a reply, got none");
        }
        let tcp_repl = some_tcp_repl.unwrap();
        /* check reply flags */
        assert!(tcp_repl.get_flags() == (TcpFlags::FIN | TcpFlags::ACK));
        /* check reply seq and ack */
        assert!(tcp_repl.get_sequence() == ack);
        assert!(tcp_repl.get_acknowledgement() == seq + 1);
    }

    #[test]
    fn test_synack_cookie_ipv4() {
        let masscanned = Masscanned {
            mac: MacAddr(0, 0, 0, 0, 0, 0),
            ip_addresses: None,
            synack_key: [0x06a0a1d63f305e9b, 0xd4d4bcbb7304875f],
            iface: None,
            log: MetaLogger::new(),
        };
        /* reference */
        let ip_src = IpAddr::V4(Ipv4Addr::new(27, 198, 143, 1));
        let ip_dst = IpAddr::V4(Ipv4Addr::new(90, 64, 122, 203));
        let tcp_sport = 65000;
        let tcp_dport = 80;
        let mut client_info = ClientInfo {
            mac: ClientInfoSrcDst {
                src: None,
                dst: None,
            },
            ip: ClientInfoSrcDst {
                src: Some(ip_src),
                dst: Some(ip_dst),
            },
            transport: None,
            port: ClientInfoSrcDst {
                src: Some(tcp_sport),
                dst: Some(tcp_dport),
            },
            cookie: None,
        };
        let cookie = synackcookie::generate(&client_info, &masscanned.synack_key).unwrap();
        let mut tcp_req =
            MutableTcpPacket::owned(vec![0; MutableTcpPacket::minimum_packet_size()]).unwrap();
        tcp_req.set_source(tcp_sport);
        tcp_req.set_destination(tcp_dport);
        tcp_req.set_flags(TcpFlags::SYN);
        let some_tcp_repl = repl(&tcp_req.to_immutable(), &masscanned, &mut client_info);
        if some_tcp_repl == None {
            assert!(false);
            return;
        }
        let tcp_repl = some_tcp_repl.unwrap();
        assert!(synackcookie::_check(
            &client_info,
            tcp_repl.get_sequence(),
            &masscanned.synack_key
        ));
        assert!(cookie == tcp_repl.get_sequence());
    }

    #[test]
    fn test_synack_cookie_ipv6() {
        let masscanned = Masscanned {
            mac: MacAddr(0, 0, 0, 0, 0, 0),
            ip_addresses: None,
            synack_key: [0x06a0a1d63f305e9b, 0xd4d4bcbb7304875f],
            iface: None,
            log: MetaLogger::new(),
        };
        /* reference */
        let ip_src = IpAddr::V6(Ipv6Addr::new(234, 52, 183, 47, 184, 172, 64, 141));
        let ip_dst = IpAddr::V6(Ipv6Addr::new(25, 179, 227, 231, 53, 216, 45, 144));
        let tcp_sport = 65000;
        let tcp_dport = 80;
        let mut client_info = ClientInfo {
            mac: ClientInfoSrcDst {
                src: None,
                dst: None,
            },
            ip: ClientInfoSrcDst {
                src: Some(ip_src),
                dst: Some(ip_dst),
            },
            transport: None,
            port: ClientInfoSrcDst {
                src: Some(tcp_sport),
                dst: Some(tcp_dport),
            },
            cookie: None,
        };
        let cookie = synackcookie::generate(&client_info, &masscanned.synack_key).unwrap();
        let mut tcp_req =
            MutableTcpPacket::owned(vec![0; MutableTcpPacket::minimum_packet_size()]).unwrap();
        tcp_req.set_source(tcp_sport);
        tcp_req.set_destination(tcp_dport);
        tcp_req.set_flags(TcpFlags::SYN);
        let some_tcp_repl = repl(&tcp_req.to_immutable(), &masscanned, &mut client_info);
        if some_tcp_repl == None {
            assert!(false);
            return;
        }
        let tcp_repl = some_tcp_repl.unwrap();
        assert!(synackcookie::_check(
            &client_info,
            tcp_repl.get_sequence(),
            &masscanned.synack_key
        ));
        assert!(cookie == tcp_repl.get_sequence());
    }
}
