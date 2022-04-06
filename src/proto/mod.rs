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
use log::*;
use pnet::packet::ip::IpNextHeaderProtocols;

use crate::client::ClientInfo;
use crate::smack::{Smack, SmackFlags, BASE_STATE, NO_MATCH, SMACK_CASE_SENSITIVE};
use crate::Masscanned;

mod http;
use http::HTTP_VERBS;

mod stun;
use stun::{STUN_PATTERN_CHANGE_REQUEST, STUN_PATTERN_EMPTY, STUN_PATTERN_MAGIC};

mod ssh;
use ssh::SSH_PATTERN_CLIENT_PROTOCOL;

mod ghost;
use ghost::GHOST_PATTERN_SIGNATURE;

mod rpc;
use rpc::{RPC_CALL_TCP, RPC_CALL_UDP};

mod smb;
use smb::{SMB1_PATTERN_MAGIC, SMB2_PATTERN_MAGIC};

mod tcb;
pub use tcb::{add_tcb, get_tcb, is_tcb_set, ProtocolState, TCPControlBlock};

const PROTO_NONE: usize = 0;
const PROTO_HTTP: usize = 1;
const PROTO_STUN: usize = 2;
const PROTO_SSH: usize = 3;
const PROTO_GHOST: usize = 4;
const PROTO_RPC_TCP: usize = 5;
const PROTO_RPC_UDP: usize = 6;
const PROTO_SMB1: usize = 7;
const PROTO_SMB2: usize = 8;

lazy_static! {
    static ref PROTO_SMACK: Smack = proto_init();
}

fn proto_init() -> Smack {
    let mut smack = Smack::new("proto".to_string(), SMACK_CASE_SENSITIVE);
    /* HTTP markers */
    for (_, v) in HTTP_VERBS.iter().enumerate() {
        smack.add_pattern(
            format!("{} /", v).as_bytes(),
            PROTO_HTTP,
            SmackFlags::ANCHOR_BEGIN,
        );
    }
    smack.add_pattern(
        STUN_PATTERN_MAGIC,
        PROTO_STUN,
        SmackFlags::ANCHOR_BEGIN | SmackFlags::WILDCARDS,
    );
    smack.add_pattern(
        STUN_PATTERN_EMPTY,
        PROTO_STUN,
        SmackFlags::ANCHOR_BEGIN | SmackFlags::ANCHOR_END | SmackFlags::WILDCARDS,
    );
    smack.add_pattern(
        STUN_PATTERN_CHANGE_REQUEST,
        PROTO_STUN,
        SmackFlags::ANCHOR_BEGIN | SmackFlags::ANCHOR_END | SmackFlags::WILDCARDS,
    );
    smack.add_pattern(
        SSH_PATTERN_CLIENT_PROTOCOL,
        PROTO_SSH,
        SmackFlags::ANCHOR_BEGIN,
    );
    smack.add_pattern(
        GHOST_PATTERN_SIGNATURE,
        PROTO_GHOST,
        SmackFlags::ANCHOR_BEGIN,
    );
    smack.add_pattern(
        RPC_CALL_TCP,
        PROTO_RPC_TCP,
        SmackFlags::ANCHOR_BEGIN | SmackFlags::WILDCARDS,
    );
    smack.add_pattern(
        RPC_CALL_UDP,
        PROTO_RPC_UDP,
        SmackFlags::ANCHOR_BEGIN | SmackFlags::WILDCARDS,
    );
    smack.add_pattern(
        SMB1_PATTERN_MAGIC,
        PROTO_SMB1,
        SmackFlags::ANCHOR_BEGIN | SmackFlags::WILDCARDS,
    );
    smack.add_pattern(
        SMB2_PATTERN_MAGIC,
        PROTO_SMB2,
        SmackFlags::ANCHOR_BEGIN | SmackFlags::WILDCARDS,
    );
    smack.compile();
    smack
}

pub fn repl<'a>(
    data: &'a [u8],
    masscanned: &Masscanned,
    mut client_info: &mut ClientInfo,
    mut tcb: Option<&mut TCPControlBlock>,
) -> Option<Vec<u8>> {
    debug!("packet payload: {:?}", data);
    let mut id;
    if client_info.transport == Some(IpNextHeaderProtocols::Tcp) && client_info.cookie == None {
        error!("Unexpected empty cookie");
        return None;
    } else if let Some(t) = &mut tcb {
        /* proto over TCP */
        let mut i = 0;
        if t.proto_id == PROTO_NONE {
            let mut state = t.smack_state;
            t.proto_id = PROTO_SMACK.search_next(&mut state, data, &mut i);
            t.smack_state = state;
        }
        id = t.proto_id;
    } else {
        /* proto over else (e.g., UDP) */
        let mut i = 0;
        let mut state = BASE_STATE;
        id = PROTO_SMACK.search_next(&mut state, data, &mut i);
        /* because we are not over TCP, we can afford to assume end of pattern */
        if id == NO_MATCH {
            id = PROTO_SMACK.search_next_end(&mut state);
        }
    }
    /* proto over else (e.g., UDP) */
    match id {
        PROTO_HTTP => http::repl(data, masscanned, client_info, tcb),
        PROTO_STUN => stun::repl(data, masscanned, &mut client_info, tcb),
        PROTO_SSH => ssh::repl(data, masscanned, &mut client_info, tcb),
        PROTO_GHOST => ghost::repl(data, masscanned, &mut client_info, tcb),
        PROTO_RPC_TCP => rpc::repl_tcp(data, masscanned, &mut client_info, tcb),
        PROTO_RPC_UDP => rpc::repl_udp(data, masscanned, &mut client_info, tcb),
        PROTO_SMB1 => smb::repl_smb1(data, masscanned, &mut client_info, tcb),
        PROTO_SMB2 => smb::repl_smb2(data, masscanned, &mut client_info, tcb),
        _ => {
            if let Some(t) = &mut tcb {
                t.proto_id = PROTO_NONE;
            }
            debug!("id: {}", id);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    use pnet::util::MacAddr;

    use crate::logger::MetaLogger;

    use crate::proto::ssh::SSH_SERVER_BANNER;

    #[test]
    fn test_proto_dispatch_stun() {
        let mut client_info = ClientInfo::new();
        let test_ip_addr = Ipv4Addr::new(3, 2, 1, 0);
        client_info.ip.src = Some(IpAddr::V4(test_ip_addr));
        client_info.port.src = Some(65000);
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
        /***** TEST STUN - MAGIC *****/
        /* test payload is:
         * - bind request: 0x0001
         * - length: 0x0000
         * - magic cookie: 0x2112a442
         * - message: empty
         */
        let payload =
            b"\x00\x01\x00\x00\x21\x12\xa4\x42\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let _stun_resp = if let Some(r) = repl(payload, &masscanned, &mut client_info, None) {
            r
        } else {
            panic!("expected an answer, got nothing");
        };
        /***** TEST STUN - EMPTY  *****/
        /* test payload is:
         * - bind request: 0x0001
         * - length: 0x0000
         * - magic cookie: 0xaabbccdd
         * - message: empty
         */
        let payload =
            b"\x00\x01\x00\x00\xaa\xbb\xcc\xdd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let _stun_resp = if let Some(r) = repl(payload, &masscanned, &mut client_info, None) {
            r
        } else {
            panic!("expected an answer, got nothing");
        };
        /***** TEST STUN - CHANGE_REQUEST  *****/
        /* test payload is:
         * - bind request: 0x0001
         * - length: 0x0008
         * - message: change request
         */
        let payload =
            b"\x00\x01\x00\x08\x01\xdb\xd4]4\x9f\xe2RQ\x19\x05,\x93\x14f4\x00\x03\x00\x04\x00\x00\x00\x00";
        let _stun_resp = if let Some(r) = repl(payload, &masscanned, &mut client_info, None) {
            r
        } else {
            panic!("expected an answer, got nothing");
        };
    }

    #[test]
    fn test_proto_dispatch_ssh() {
        let mut client_info = ClientInfo::new();
        let test_ip_addr = Ipv4Addr::new(3, 2, 1, 0);
        client_info.ip.src = Some(IpAddr::V4(test_ip_addr));
        client_info.port.src = Some(65000);
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
        /***** TEST SSH *****/
        let payloads = [
            "SSH-2.0-PUTTY",
            "SSH-2.0-Go",
            "SSH-2.0-libssh2_1.4.3",
            "SSH-2.0-PuTTY",
            "SSH-2.0-AsyncSSH_2.1.0",
            "SSH-2.0-libssh2_1.9.0",
            "SSH-2.0-libssh2_1.7.0",
            "SSH-2.0-8.35 FlowSsh: FlowSshNet_SftpStress54.38.116.473",
            "SSH-2.0-libssh_0.9.5",
            "SSH-2.0-OpenSSH_6.7p1 Raspbian-5+deb8u3",
        ];
        for payload in payloads.iter() {
            let _ssh_resp =
                if let Some(r) = repl(payload.as_bytes(), &masscanned, &mut client_info, None) {
                    r
                } else {
                    panic!("expected an answer, got nothing");
                };
        }
    }

    #[test]
    fn test_proto_dispatch_ghost() {
        let mut client_info = ClientInfo::new();
        let test_ip_addr = Ipv4Addr::new(3, 2, 1, 0);
        client_info.ip.src = Some(IpAddr::V4(test_ip_addr));
        client_info.port.src = Some(65000);
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
        /***** TEST GHOST *****/
        let payloads = [
            b"Gh0st\xad\x00\x00\x00\xe0\x00\x00\x00x\x9cKS``\x98\xc3\xc0\xc0\xc0\x06\xc4\x8c@\xbcQ\x96\x81\x81\tH\x07\xa7\x16\x95e&\xa7*\x04$&g+\x182\x94\xf6\xb000\xac\xa8rc\x00\x01\x11\xa0\x82\x1f\\`&\x83\xc7K7\x86\x19\xe5n\x0c9\x95n\x0c;\x84\x0f3\xac\xe8sch\xa8^\xcf4'J\x97\xa9\x82\xe30\xc3\x91h]&\x90\xf8\xce\x97S\xcbA4L?2=\xe1\xc4\x92\x86\x0b@\xf5`\x0cT\x1f\xae\xaf]\nr\x0b\x03#\xa3\xdc\x02~\x06\x86\x03+\x18m\xc2=\xfdtC,C\xfdL<<==\\\x9d\x19\x88\x00\xe5 \x02\x00T\xf5+\\"
        ];
        for payload in payloads.iter() {
            let _ghost_resp =
                if let Some(r) = repl(&payload.to_vec(), &masscanned, &mut client_info, None) {
                    r
                } else {
                    panic!("expected an answer, got nothing");
                };
        }
    }

    #[test]
    fn test_proto_repl_http() {
        /* ensure that HTTP FSM does not answer until completion of request
         * (at least headers) */
        let mut client_info = ClientInfo::new();
        let test_ip_addr = Ipv4Addr::new(3, 2, 1, 0);
        client_info.ip.src = Some(IpAddr::V4(test_ip_addr));
        client_info.port.src = Some(65000);
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
        /***** TEST COMPLETE REQUEST *****/
        let payload = b"GET / HTTP/1.1\r\n\r\n";
        if let None = repl(&payload.to_vec(), &masscanned, &mut client_info, None) {
            panic!("expected an answer, got nothing");
        }
        /***** TEST INCOMPLETE REQUEST *****/
        let payload = b"GET / HTTP/1.1\r\n";
        if let Some(_) = repl(&payload.to_vec(), &masscanned, &mut client_info, None) {
            panic!("expected no answer, got one");
        }
    }

    #[test]
    fn test_proto_repl_ssh() {
        /* ensure that SSH proto returns a banner after the client's banner
         * but only once */
        let mut client_info = ClientInfo::new();
        let test_ip_addr = Ipv4Addr::new(3, 2, 1, 0);
        client_info.ip.src = Some(IpAddr::V4(test_ip_addr));
        client_info.port.src = Some(65000);
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
        /***** SEND BANNER A FIRST TIME *****/
        let payload = b"SSH-2.0-PUTTY";
        match repl(&payload.to_vec(), &masscanned, &mut client_info, None) {
            None => { panic!("expected an answer, got nothing") }
            Some(banner) => { if banner != SSH_SERVER_BANNER { panic!("unexpected banner: {:?}", banner); } }
        } 
        /***** SEND ONE ADDITIONAL BYTE *****/
        let payload = b"X";
        if let Some(banner) = repl(&payload.to_vec(), &masscanned, &mut client_info, None) {
            panic!("unexpected banner: {:?}", banner); 
        } 
        /***** SEND A SECOND BANNER *****/
        let payload = b"SSH-2.0-PUTTY";
        if let Some(banner) = repl(&payload.to_vec(), &masscanned, &mut client_info, None) {
            panic!("unexpected banner: {:?}", banner); 
        } 
    }
}
