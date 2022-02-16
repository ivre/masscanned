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

use log::warn;
use std::convert::TryInto;
use std::net::IpAddr;

use crate::client::ClientInfo;
use crate::proto::{ProtocolState as GenericProtocolState, TCPControlBlock};
use crate::Masscanned;

// last fragment (1 bit) + fragment len (31 bits) / length XID (random) / message type: call (0) / RPC version (0-255) / Program: Portmap (99840 - 100095) / Program version (*, random versions used, see below) / / Procedure: ??? (0-255)
pub const RPC_CALL_TCP: &[u8; 28] =
    b"********\x00\x00\x00\x00\x00\x00\x00*\x00\x01\x86*****\x00\x00\x00*";
// UDP: last fragment and fragment len are missing
pub const RPC_CALL_UDP: &[u8; 24] =
    b"****\x00\x00\x00\x00\x00\x00\x00*\x00\x01\x86*****\x00\x00\x00*";

#[derive(Debug)]
enum RpcState {
    Frag,
    Xid,
    MessageType,
    RpcVersion,
    Program,
    ProgramVersion,
    Procedure,
    CredsFlavor,
    CredsLen,
    Creds,
    VerifFlavor,
    VerifLen,
    Verif,
    End,
}

#[derive(Debug)]
pub struct ProtocolState {
    state: RpcState,
    last_frag: bool,
    frag_len: u32,
    xid: u32,
    message_type: u32,
    rpc_version: u32,
    program: u32,
    prog_version: u32,
    procedure: u32,
    creds_flavor: u32,
    creds_data: Vec<u8>,
    verif_flavor: u32,
    verif_data: Vec<u8>,
    payload: Vec<u8>,
    cur_len: u32,
    data_len: u32,
}

struct Rpcb {
    program: u32,
    version: u32,
    netid: String,
    addr: String,
    port: u16,
    owner: String,
}

impl ProtocolState {
    fn new() -> Self {
        ProtocolState {
            state: RpcState::Frag,
            last_frag: false,
            frag_len: 0,
            xid: 0,
            message_type: 0,
            rpc_version: 0,
            program: 0,
            prog_version: 0,
            procedure: 0,
            creds_flavor: 0,
            creds_data: Vec::<u8>::new(),
            verif_flavor: 0,
            verif_data: Vec::<u8>::new(),
            payload: Vec::<u8>::new(),
            cur_len: 0,
            data_len: 0,
        }
    }
}

fn read_u32(pstate: &mut ProtocolState, byte: u8, value: u32, next_state: RpcState) -> u32 {
    pstate.cur_len += 1;
    if pstate.cur_len == 4 {
        pstate.state = next_state;
        pstate.cur_len = 0;
    }
    value * 256 + byte as u32
}

fn read_string(pstate: &mut ProtocolState, next_state: RpcState) {
    pstate.data_len -= 1;
    if pstate.data_len == 0 {
        pstate.state = next_state;
    }
}

fn rpc_parse(pstate: &mut ProtocolState, data: &[u8]) {
    for byte in data {
        match pstate.state {
            RpcState::Frag => {
                if pstate.cur_len == 0 {
                    match byte & 128 {
                        0 => pstate.last_frag = false,
                        _ => pstate.last_frag = true,
                    };
                    pstate.frag_len = (*byte & 127) as u32;
                } else {
                    pstate.frag_len = *byte as u32;
                }
                pstate.cur_len += 1;
                if pstate.cur_len == 4 {
                    pstate.state = RpcState::Xid;
                    pstate.cur_len = 0;
                }
            }
            RpcState::Xid => {
                pstate.xid = read_u32(pstate, *byte, pstate.xid, RpcState::MessageType)
            }
            RpcState::MessageType => {
                pstate.message_type =
                    read_u32(pstate, *byte, pstate.message_type, RpcState::RpcVersion)
            }
            RpcState::RpcVersion => {
                pstate.rpc_version = read_u32(pstate, *byte, pstate.rpc_version, RpcState::Program)
            }
            RpcState::Program => {
                pstate.program = read_u32(pstate, *byte, pstate.program, RpcState::ProgramVersion)
            }
            RpcState::ProgramVersion => {
                pstate.prog_version =
                    read_u32(pstate, *byte, pstate.prog_version, RpcState::Procedure)
            }
            RpcState::Procedure => {
                pstate.procedure = read_u32(pstate, *byte, pstate.procedure, RpcState::CredsFlavor)
            }
            RpcState::CredsFlavor => {
                pstate.creds_flavor =
                    read_u32(pstate, *byte, pstate.creds_flavor, RpcState::CredsLen)
            }
            RpcState::CredsLen => {
                pstate.data_len = read_u32(pstate, *byte, pstate.data_len, RpcState::Creds);
                if matches!(pstate.state, RpcState::Creds) && pstate.data_len == 0 {
                    pstate.state = RpcState::VerifFlavor
                }
            }
            RpcState::Creds => {
                pstate.creds_data.push(*byte);
                read_string(pstate, RpcState::VerifFlavor)
            }
            RpcState::VerifFlavor => {
                pstate.verif_flavor =
                    read_u32(pstate, *byte, pstate.verif_flavor, RpcState::VerifLen)
            }
            RpcState::VerifLen => {
                pstate.data_len = read_u32(pstate, *byte, pstate.data_len, RpcState::Verif);
                if matches!(pstate.state, RpcState::Verif) && pstate.cur_len == 0 {
                    pstate.state = RpcState::End
                }
            }
            RpcState::Verif => {
                pstate.verif_data.push(*byte);
                read_string(pstate, RpcState::End)
            }
            RpcState::End => {
                pstate.payload.push(*byte);
            }
        };
    }
}

fn get_nth_byte(value: u32, nth: u8) -> u8 {
    let shift = 8 * (3 - nth);
    ((value & (0xff << shift)) >> shift).try_into().unwrap()
}

fn push_u32(buffer: &mut Vec<u8>, data: u32) {
    for i in 0..4 {
        buffer.push(get_nth_byte(data, i));
    }
}

fn push_string_pad(buffer: &mut Vec<u8>, data: String) {
    let len: u32 = data.len().try_into().unwrap();
    push_u32(buffer, len);
    buffer.append(&mut data.as_bytes().to_vec());
    if len % 4 != 0 {
        for _ in 0..(4 - (len % 4)) {
            buffer.append(&mut b"\x00".to_vec());
        }
    }
}

fn build_repl_portmap(pstate: &mut ProtocolState, client_info: &ClientInfo) -> Vec<u8> {
    let mut resp = Vec::<u8>::new();
    match pstate.procedure {
        // 0 => {}
        3 => {
            // getaddr / getport
            // accepted state: 0 (RPC executed successfully)
            resp.extend([0, 0, 0, 0]);
            let localport = client_info.port.dst.unwrap();
            match pstate.prog_version {
                2 => {
                    push_u32(&mut resp, localport as u32);
                }
                3 | 4 => {
                    let addr = format!(
                        "{}.{}.{}",
                        client_info.ip.dst.unwrap(),
                        localport >> 8,
                        localport % 256
                    );
                    push_string_pad(&mut resp, addr);
                }
                _ => panic!("Wrong RPC version"),
            }
        }
        4 => {
            // dump
            // accepted state: 0 (RPC executed successfully)
            resp.extend([0, 0, 0, 0]);
            let localaddr = client_info.ip.dst.unwrap();
            let localport = client_info.port.dst.unwrap();
            let netid = match localaddr {
                IpAddr::V4(_) => "tcp",
                IpAddr::V6(_) => "tcp6",
            };
            for rpcb in [
                Rpcb {
                    program: 100000,
                    version: 2,
                    netid: netid.to_string(),
                    addr: format!("{}", localaddr),
                    port: localport,
                    owner: "superuser".to_string(),
                },
                Rpcb {
                    program: 100000,
                    version: 3,
                    netid: netid.to_string(),
                    addr: format!("{}", localaddr),
                    port: localport,
                    owner: "superuser".to_string(),
                },
                Rpcb {
                    program: 100000,
                    version: 4,
                    netid: netid.to_string(),
                    addr: format!("{}", localaddr),
                    port: localport,
                    owner: "superuser".to_string(),
                },
            ] {
                resp.append(&mut b"\x00\x00\x00\x01".to_vec()); // value follows: yes
                push_u32(&mut resp, rpcb.program);
                push_u32(&mut resp, rpcb.version);
                match pstate.prog_version {
                    2 => {
                        push_u32(
                            &mut resp,
                            match rpcb.netid.as_str() {
                                "tcp" => 6,
                                "tcp6" => 6,
                                "udp" => 17,
                                "udp6" => 17,
                                _ => 0,
                            },
                        );
                        push_u32(&mut resp, localport as u32);
                    }
                    3 | 4 => {
                        push_string_pad(&mut resp, rpcb.netid);
                        push_string_pad(
                            &mut resp,
                            format!("{}.{}.{}", rpcb.addr, rpcb.port >> 8, rpcb.port & 0xff),
                        );
                        push_string_pad(&mut resp, rpcb.owner);
                    }
                    _ => panic!("Wrong RPC version"),
                }
            }
            resp.append(&mut b"\x00\x00\x00\x00".to_vec()); // value follows: no
        }
        _ => {
            // accepted state: 5 (program can't support procedure)
            resp.extend([0, 0, 0, 5]);
        }
    }
    warn!(
        "RPC: Portmap version {}, procedure {}",
        pstate.prog_version, pstate.procedure
    );
    resp
}

fn build_repl_unknownprog(pstate: &mut ProtocolState, _client_info: &ClientInfo) -> Vec<u8> {
    warn!(
        "Unknown program {}, procedure {}: accepted state 1",
        pstate.program, pstate.procedure
    );
    // accepted state: 1 (remote hasn't exported program)
    vec![0, 0, 0, 1]
}

fn build_repl(pstate: &mut ProtocolState, client_info: &ClientInfo) -> Vec<u8> {
    // TODO: test RPC versions, drop non calls?
    let mut resp = Vec::<u8>::new();
    push_u32(&mut resp, pstate.xid);
    // message_type: 1 (reply)
    // reply_state: 0 (accepted)
    // verifier: 0 (auth null)
    // verifier length: 0
    resp.extend([0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    if pstate.prog_version < 2 || pstate.prog_version > 4 {
        /*
         * Scanners (e.g., Nmap script rpc-grind) often use random
         * values for program version to find out if a program is
         * supported, so for any program, we answer with "remote can't
         * support version" accepted state.
         */
        // accepted state: 2 (remote can't support version)
        // prog_version min: 2
        // prog_version max: 4
        let prog_version = match pstate.prog_version {
            104316 => "104316 (Nmap probe TCP RPCCheck)".to_string(),
            x => x.to_string(),
        };
        warn!(
            "RPC: unsupported version {} for program {}",
            prog_version, pstate.program
        );
        resp.extend([0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 4]);
    } else if pstate.procedure == 0 {
        /*
         * RPC clients (e.g., Linux kernel NFS client, rpcbind CLI
         * tool) would often send a NULL procedure (0) call before any
         * real operation .
         */
        // accepted state: 0 (RPC executed successfully)
        warn!("RPC: NULL procedure call for program {}", pstate.program);
        resp.extend([0, 0, 0, 0]);
    } else {
        let mut specif_resp = match pstate.program {
            100000 => build_repl_portmap(pstate, client_info),
            _ => build_repl_unknownprog(pstate, client_info),
        };
        resp.append(&mut specif_resp);
    }
    resp
}

pub fn repl_tcp<'a>(
    data: &'a [u8],
    _masscanned: &Masscanned,
    client_info: &ClientInfo,
    tcb: Option<&mut TCPControlBlock>,
) -> Option<Vec<u8>> {
    let mut state = ProtocolState::new();
    let mut pstate = {
        if let Some(t) = tcb {
            match t.proto_state {
                None => t.proto_state = Some(GenericProtocolState::RPC(ProtocolState::new())),
                Some(GenericProtocolState::RPC(_)) => {}
                _ => {
                    panic!()
                }
            };
            if let Some(GenericProtocolState::RPC(p)) = &mut t.proto_state {
                p
            } else {
                panic!();
            }
        } else {
            &mut state
        }
    };
    rpc_parse(&mut pstate, data);
    // warn!("RPC {:#?}", pstate);
    let resp = match pstate.state {
        RpcState::End => Some(build_repl(pstate, client_info)),
        _ => None,
    };
    match resp {
        Some(mut resp) => {
            let length: u32 = resp.len().try_into().unwrap();
            let mut final_resp = Vec::<u8>::new();
            for i in 0..4 {
                match i {
                    0 => final_resp.push(get_nth_byte(length, i) | 0x80),
                    _ => final_resp.push(get_nth_byte(length, i)),
                };
            }
            final_resp.append(&mut resp);
            Some(final_resp)
        }
        _ => None,
    }
}

pub fn repl_udp<'a>(
    data: &'a [u8],
    _masscanned: &Masscanned,
    client_info: &ClientInfo,
    _tcb: Option<&mut TCPControlBlock>,
) -> Option<Vec<u8>> {
    let mut pstate = ProtocolState::new();
    pstate.state = RpcState::Xid;
    pstate.last_frag = true;
    pstate.frag_len = data.len().try_into().unwrap();
    rpc_parse(&mut pstate, data);
    // warn!("RPC {:#?}", pstate);
    match pstate.state {
        RpcState::End => Some(build_repl(&mut pstate, client_info)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::ClientInfoSrcDst;
    use std::net::Ipv4Addr;

    const CLIENT_INFO: ClientInfo = ClientInfo {
        mac: ClientInfoSrcDst {
            src: None,
            dst: None,
        },
        ip: ClientInfoSrcDst {
            src: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 0, 0))),
            dst: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 0, 1))),
        },
        transport: None,
        port: ClientInfoSrcDst {
            src: Some(12345),
            dst: Some(111),
        },
        cookie: None,
    };

    #[test]
    fn test_probe_nmap() {
        let mut pstate = ProtocolState::new();
        rpc_parse(&mut pstate, b"\x80\x00\x00\x28\x72\xfe\x1d\x13\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xa0\x00\x01\x97\x7c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
        assert!(matches!(pstate.state, RpcState::End));
        assert!(pstate.xid == 0x72fe1d13);
        assert!(pstate.rpc_version == 2);
        assert!(pstate.program == 100000);
        assert!(pstate.prog_version == 104316);
        assert!(pstate.procedure == 0);
        assert!(pstate.creds_flavor == 0);
        assert!(pstate.creds_data.len() == 0);
        assert!(pstate.verif_flavor == 0);
        assert!(pstate.verif_data.len() == 0);
        let resp = build_repl(&mut pstate, &CLIENT_INFO);
        assert!(resp == b"\x72\xfe\x1d\x13\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x04");
    }

    #[test]
    fn test_probe_nmap_udp() {
        let mut pstate = ProtocolState::new();
        pstate.state = RpcState::Xid;
        rpc_parse(&mut pstate, b"\x72\xfe\x1d\x13\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xa0\x00\x01\x97\x7c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
        assert!(matches!(pstate.state, RpcState::End));
        assert!(pstate.xid == 0x72fe1d13);
        assert!(pstate.rpc_version == 2);
        assert!(pstate.program == 100000);
        assert!(pstate.prog_version == 104316);
        assert!(pstate.procedure == 0);
        assert!(pstate.creds_flavor == 0);
        assert!(pstate.creds_data.len() == 0);
        assert!(pstate.verif_flavor == 0);
        assert!(pstate.verif_data.len() == 0);
        let resp = build_repl(&mut pstate, &CLIENT_INFO);
        assert!(resp == b"\x72\xfe\x1d\x13\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x04");
    }

    #[test]
    fn test_probe_nmap_split1() {
        let mut pstate = ProtocolState::new();
        for byte in b"\x80\x00\x00\x28\x72\xfe\x1d\x13\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xa0\x00\x01\x97\x7c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" {
            rpc_parse(&mut pstate, &[*byte]);
        }
        assert!(matches!(pstate.state, RpcState::End));
        assert!(pstate.xid == 0x72fe1d13);
        assert!(pstate.rpc_version == 2);
        assert!(pstate.program == 100000);
        assert!(pstate.prog_version == 104316);
        assert!(pstate.procedure == 0);
        assert!(pstate.creds_flavor == 0);
        assert!(pstate.creds_data.len() == 0);
        assert!(pstate.verif_flavor == 0);
        assert!(pstate.verif_data.len() == 0);
        let resp = build_repl(&mut pstate, &CLIENT_INFO);
        assert!(resp == b"\x72\xfe\x1d\x13\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x04");
    }

    #[test]
    fn test_probe_nmap_split2() {
        let mut pstate = ProtocolState::new();
        for data in [
            b"\x80\x00\x00\x28\x72\xfe\x1d",
            b"\x13\x00\x00\x00\x00\x00\x00",
            b"\x00\x02\x00\x01\x86\xa0\x00",
            b"\x01\x97\x7c\x00\x00\x00\x00",
            b"\x00\x00\x00\x00\x00\x00\x00",
            b"\x00\x00\x00\x00\x00\x00\x00",
        ] {
            rpc_parse(&mut pstate, data);
        }
        rpc_parse(&mut pstate, b"\x00\x00");
        assert!(matches!(pstate.state, RpcState::End));
        assert!(pstate.xid == 0x72fe1d13);
        assert!(pstate.rpc_version == 2);
        assert!(pstate.program == 100000);
        assert!(pstate.prog_version == 104316);
        assert!(pstate.procedure == 0);
        assert!(pstate.creds_flavor == 0);
        assert!(pstate.creds_data.len() == 0);
        assert!(pstate.verif_flavor == 0);
        assert!(pstate.verif_data.len() == 0);
        let resp = build_repl(&mut pstate, &CLIENT_INFO);
        assert!(resp == b"\x72\xfe\x1d\x13\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x04");
    }

    #[test]
    fn test_probe_portmap_v4_dump() {
        let mut pstate = ProtocolState::new();
        rpc_parse(&mut pstate, b"\x80\x00\x00\x28\x01\x1b\x60\xa6\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xa0\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
        assert!(matches!(pstate.state, RpcState::End));
        assert!(pstate.rpc_version == 2);
        assert!(pstate.program == 100000);
        assert!(pstate.prog_version == 4);
        assert!(pstate.procedure == 4); // dump
        assert!(pstate.creds_flavor == 0);
        assert!(pstate.creds_data.len() == 0);
        assert!(pstate.verif_flavor == 0);
        assert!(pstate.verif_data.len() == 0);
    }
}
