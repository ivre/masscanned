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
use std::collections::HashMap;
use std::sync::Mutex;

use crate::client::ClientInfo;
use crate::smack::{Smack, SmackFlags, BASE_STATE, NO_MATCH, SMACK_CASE_SENSITIVE};
use crate::Masscanned;

mod http;
use http::HTTP_VERBS;

mod stun;
use stun::{STUN_PATTERN_CHANGE_REQUEST, STUN_PATTERN_EMPTY, STUN_PATTERN_MAGIC};

mod ssh;
use ssh::SSH_PATTERN_CLIENT_PROTOCOL;

const PROTO_HTTP: usize = 1;
const PROTO_STUN: usize = 2;
const PROTO_SSH: usize = 3;

struct TCPControlBlock {
    proto_state: usize,
}

lazy_static! {
    static ref PROTO_SMACK: Smack = proto_init();
    static ref CONTABLE: Mutex<HashMap<u32, TCPControlBlock>> = Mutex::new(HashMap::new());
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
    smack.compile();
    smack
}

pub fn repl<'a>(
    data: &'a [u8],
    masscanned: &Masscanned,
    mut client_info: &mut ClientInfo,
) -> Option<Vec<u8>> {
    debug!("packet payload: {:?}", data);
    let mut id;
    if client_info.transport == Some(IpNextHeaderProtocols::Tcp) && client_info.cookie == None {
        error!("Unexpected empty cookie");
        return None;
    } else if client_info.cookie != None {
        /* proto over TCP */
        let cookie = client_info.cookie.unwrap();
        let mut ct = CONTABLE.lock().unwrap();
        if !ct.contains_key(&cookie) {
            ct.insert(
                cookie,
                TCPControlBlock {
                    proto_state: BASE_STATE,
                },
            );
        }
        let mut i = 0;
        let mut tcb = ct.get_mut(&cookie).unwrap();
        let mut state = tcb.proto_state;
        id = PROTO_SMACK.search_next(&mut state, &data.to_vec(), &mut i);
        tcb.proto_state = state;
    } else {
        /* proto over else (e.g., UDP) */
        let mut i = 0;
        let mut state = BASE_STATE;
        id = PROTO_SMACK.search_next(&mut state, &data.to_vec(), &mut i);
        /* because we are not over TCP, we can afford to assume end of pattern */
        if id == NO_MATCH {
            id = PROTO_SMACK.search_next_end(&mut state);
        }
    }
    /* proto over else (e.g., UDP) */
    if id == PROTO_HTTP {
        return http::repl(data, masscanned, client_info);
    } else if id == PROTO_STUN {
        return stun::repl(data, masscanned, &mut client_info);
    } else if id == PROTO_SSH {
        return ssh::repl(data, masscanned, &mut client_info);
    } else {
        debug!("id: {}", id);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    use pnet::util::MacAddr;

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
        let _stun_resp = if let Some(r) = repl(payload, &masscanned, &mut client_info) {
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
        let _stun_resp = if let Some(r) = repl(payload, &masscanned, &mut client_info) {
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
        let _stun_resp = if let Some(r) = repl(payload, &masscanned, &mut client_info) {
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
            let _ssh_resp = if let Some(r) = repl(payload.as_bytes(), &masscanned, &mut client_info)
            {
                r
            } else {
                panic!("expected an answer, got nothing");
            };
        }
    }
}
