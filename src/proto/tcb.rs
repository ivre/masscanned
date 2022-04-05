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

use lazy_static::lazy_static;

use std::collections::HashMap;
use std::sync::Mutex;

use super::http::ProtocolState as HTTPProtocolState;
use super::rpc::ProtocolState as RPCProtocolState;
use crate::proto::{BASE_STATE, PROTO_NONE};

pub enum ProtocolState {
    HTTP(HTTPProtocolState),
    RPC(RPCProtocolState),
}

pub struct TCPControlBlock {
    /* state used to detect protocols (not specific) */
    pub smack_state: usize,
    /* detected protocol */
    pub proto_id: usize,
    /* internal state of protocol parser (e.g., HTTP parsing) */
    pub proto_state: Option<ProtocolState>,
}

lazy_static! {
    static ref CONTABLE: Mutex<HashMap<u32, TCPControlBlock>> = Mutex::new(HashMap::new());
}

pub fn is_tcb_set(cookie: u32) -> bool {
    CONTABLE.lock().unwrap().contains_key(&cookie)
}

pub fn get_tcb<F>(cookie: u32, mut f: F)
where
    F: FnMut(Option<&mut TCPControlBlock>),
{
    f(CONTABLE.lock().unwrap().get_mut(&cookie));
}

pub fn add_tcb(cookie: u32) {
    let mut ct = CONTABLE.lock().unwrap();
    let tcb = TCPControlBlock {
        smack_state: BASE_STATE,
        proto_id: PROTO_NONE,
        proto_state: None,
    };
    if !ct.contains_key(&cookie) {
        ct.insert(cookie, tcb);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    use pnet::{
        packet::{ip::IpNextHeaderProtocols, tcp::TcpPacket},
        util::MacAddr,
    };

    use crate::client::ClientInfo;
    use crate::layer_4::tcp;
    use crate::logger::MetaLogger;
    use crate::proto::{PROTO_HTTP, PROTO_RPC_TCP};
    use crate::synackcookie;
    use crate::Masscanned;

    fn get_dummy_tcp(&client_info: &ClientInfo) -> Vec<u8> {
        /* Craft a TCP ACK+PUSH packet with correct ports and ack */
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&client_info.port.src.unwrap().to_be_bytes());
        pkt.extend_from_slice(&client_info.port.dst.unwrap().to_be_bytes());
        pkt.extend_from_slice(b"\x00\x00\x00\x00");
        pkt.extend_from_slice(&(client_info.cookie.unwrap() + 1).to_be_bytes());
        pkt.extend_from_slice(b"P\x18 \x00\x00\x00\x00\x00");
        pkt
    }

    #[test]
    fn test_proto_tcb_proto_id() {
        let mut client_info = ClientInfo::new();
        let test_ip_addr = Ipv4Addr::new(3, 2, 1, 0);
        client_info.ip.src = Some(IpAddr::V4(test_ip_addr));
        client_info.port.src = Some(65000);
        client_info.port.dst = Some(80);
        client_info.transport = Some(IpNextHeaderProtocols::Tcp);
        let masscanned_ip_addr = Ipv4Addr::new(0, 1, 2, 3);
        client_info.ip.dst = Some(IpAddr::V4(masscanned_ip_addr));
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
        let cookie = synackcookie::generate(&client_info, &masscanned.synack_key).unwrap();
        client_info.cookie = Some(cookie);
        assert!(!is_tcb_set(cookie), "expected no TCB entry, found one");
        /***** TEST PROTOCOL ID IN TCB *****/
        let payload = [get_dummy_tcp(&client_info), b"GET / HTTP/1.1\r\n".to_vec()].concat();
        tcp::repl(
            &TcpPacket::new(&payload).unwrap(),
            &masscanned,
            &mut client_info,
        );
        assert!(is_tcb_set(cookie), "expected a TCB entry, not found");
        get_tcb(cookie, |t| {
            let t = t.unwrap();
            assert!(t.proto_id == PROTO_HTTP);
        });

        /***** SENDING MORE DATA *****/
        let payload = [
            get_dummy_tcp(&client_info),
            b"garbage data with no specific format (no protocol)\r\n\r\n".to_vec(),
        ]
        .concat();
        tcp::repl(
            &TcpPacket::new(&payload).unwrap(),
            &masscanned,
            &mut client_info,
        );
        assert!(is_tcb_set(cookie), "expected a TCB entry, not found");
        get_tcb(cookie, |t| {
            let t = t.unwrap();
            assert!(t.proto_id == PROTO_HTTP);
        });
    }

    #[test]
    fn test_proto_tcb_proto_state_http() {
        let mut client_info = ClientInfo::new();
        let test_ip_addr = Ipv4Addr::new(3, 2, 1, 0);
        client_info.ip.src = Some(IpAddr::V4(test_ip_addr));
        client_info.port.src = Some(65001);
        client_info.port.dst = Some(80);
        client_info.transport = Some(IpNextHeaderProtocols::Tcp);
        let masscanned_ip_addr = Ipv4Addr::new(0, 1, 2, 3);
        client_info.ip.dst = Some(IpAddr::V4(masscanned_ip_addr));
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
        let cookie = synackcookie::generate(&client_info, &masscanned.synack_key).unwrap();
        client_info.cookie = Some(cookie);
        assert!(!is_tcb_set(cookie), "expected no TCB entry, found one");
        /***** TEST PROTOCOL ID IN TCB *****/
        let payload = [get_dummy_tcp(&client_info), b"GET / HTTP/1.1\r\n".to_vec()].concat();
        tcp::repl(
            &TcpPacket::new(&payload).unwrap(),
            &masscanned,
            &mut client_info,
        );
        assert!(is_tcb_set(cookie), "expected a TCB entry, not found");
        get_tcb(cookie, |t| {
            let t = t.unwrap();
            assert!(t.proto_id == PROTO_HTTP);
            if let Some(ProtocolState::HTTP(_)) = t.proto_state {
            } else {
                panic!("expected a HTTP protocole state, found None");
            }
        });
        /***** SENDING MORE DATA *****/
        let payload = [
            get_dummy_tcp(&client_info),
            b"Field: empty\r\n\r\n".to_vec(),
        ]
        .concat();
        /* Should have an answer here */
        if let None = tcp::repl(
            &TcpPacket::new(&payload).unwrap(),
            &masscanned,
            &mut client_info,
        ) {
            panic!("expected an HTTP response, got nothing");
        }
        assert!(is_tcb_set(cookie), "expected a TCB entry, not found");
        get_tcb(cookie, |t| {
            let t = t.unwrap();
            assert!(t.proto_id == PROTO_HTTP);
        })
    }

    #[test]
    fn test_proto_tcb_proto_state_rpc() {
        let mut client_info = ClientInfo::new();
        let test_ip_addr = Ipv4Addr::new(3, 2, 1, 0);
        client_info.ip.src = Some(IpAddr::V4(test_ip_addr));
        client_info.port.src = Some(65002);
        client_info.port.dst = Some(80);
        client_info.transport = Some(IpNextHeaderProtocols::Tcp);
        let masscanned_ip_addr = Ipv4Addr::new(0, 1, 2, 3);
        client_info.ip.dst = Some(IpAddr::V4(masscanned_ip_addr));
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
        let cookie = synackcookie::generate(&client_info, &masscanned.synack_key).unwrap();
        client_info.cookie = Some(cookie);
        assert!(!is_tcb_set(cookie), "expected no TCB entry, found one");
        /***** TEST PROTOCOL ID IN TCB *****/
        let full_payload = b"\x80\x00\x00\x28\x72\xfe\x1d\x13\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xa0\x00\x01\x97\x7c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let payload = [get_dummy_tcp(&client_info), full_payload[0..28].to_vec()].concat();
        tcp::repl(
            &TcpPacket::new(&payload).unwrap(),
            &masscanned,
            &mut client_info,
        );
        assert!(is_tcb_set(cookie), "expected a TCB entry, not found");
        get_tcb(cookie, |t| {
            let t = t.unwrap();
            assert!(t.proto_id == PROTO_RPC_TCP);
            if let Some(ProtocolState::RPC(_)) = t.proto_state {
            } else {
                panic!("expected a RPC protocole state, found None");
            }
        });
        /***** SENDING MORE DATA *****/
        /* Should have an answer here */
        let payload = [get_dummy_tcp(&client_info), full_payload[28..].to_vec()].concat();
        if let None = tcp::repl(
            &TcpPacket::new(&payload).unwrap(),
            &masscanned,
            &mut client_info,
        ) {
            panic!("expected a RPC response, got nothing");
        }
        assert!(is_tcb_set(cookie), "expected a TCB entry, not found");
        get_tcb(cookie, |t| {
            let t = t.unwrap();
            assert!(t.proto_id == PROTO_RPC_TCP);
        });
    }
}
