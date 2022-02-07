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
use std::convert::TryInto;

use chrono;

use crate::client::ClientInfo;
use crate::Masscanned;

// NBTSession + SMB Header
// netbios type (1 byte) + reserved (1 byte) + length (2 bytes) + SMB MAGIC (4 bytes)
//
pub const SMB1_PATTERN_MAGIC: &[u8; 8] = b"\x00\x00**\xffSMB";
pub const SMB2_PATTERN_MAGIC: &[u8; 8] = b"\x00\x00**\xfeSMB";

// Build/Dissect secblob with Scapy using: GSSAPI_BLOB(b"`\x82.....")
const SECURITY_BLOB: &[u8; 320] = b"`\x82\x01<\x06\x06+\x06\x01\x05\x05\x02\xa0\x82\x0100\x82\x01,\xa0\x1a0\x18\x06\n+\x06\x01\x04\x01\x827\x02\x02\x1e\x06\n+\x06\x01\x04\x01\x827\x02\x02\n\xa2\x82\x01\x0c\x04\x82\x01\x08NEGOEXTS\x01\x00\x00\x00\x00\x00\x00\x00`\x00\x00\x00p\x00\x00\x001<*:\xc7+<\xa9m\xac8t\xa7\xdd\x1d[\xf4Rk\x17\x03\x8aK\x91\xc2\t}\x9a\x8f\xe6,\x96\\Q$/\x90MG\xc7\xad\x8f\x87k\"\x02\xbf\xc6\x00\x00\x00\x00\x00\x00\x00\x00`\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\\3S\r\xea\xf9\rM\xb2\xecJ\xe3xn\xc3\x08NEGOEXTS\x03\x00\x00\x00\x01\x00\x00\x00@\x00\x00\x00\x98\x00\x00\x001<*:\xc7+<\xa9m\xac8t\xa7\xdd\x1d[\\3S\r\xea\xf9\rM\xb2\xecJ\xe3xn\xc3\x08@\x00\x00\x00X\x00\x00\x000V\xa0T0R0'\x80%0#1!0\x1f\x06\x03U\x04\x03\x13\x18Token Signing Public Key0'\x80%0#1!0\x1f\x06\x03U\x04\x03\x13\x18Token Signing Public Key";

////////////
// Common //
////////////

pub trait Packet {
    type PacketState;

    fn new() -> Self;
    fn i(&self) -> usize;
    fn set_i(&mut self, i: usize);
    fn state(&self) -> Self::PacketState;
    fn set_state(&mut self, state: Self::PacketState);
    fn repl(&self) -> Option<Vec<u8>>;
    fn parse(&mut self, byte: &u8);

    fn parse_all(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.parse(byte);
        }
    }

    fn next_state(&mut self, state: Self::PacketState) {
        self.set_state(state);
        self.set_i(0);
    }
    fn next_state_when_i_reaches(&mut self, state: Self::PacketState, i: usize) {
        if self.i() == i {
            self.next_state(state);
        }
    }
    fn _read_u(
        &mut self,
        byte: &u8,
        value: usize,
        next_state: Self::PacketState,
        size: usize,
    ) -> usize {
        self.set_i(self.i() + 1);
        self.next_state_when_i_reaches(next_state, size);
        (value << 8) + *byte as usize
    }
    fn _read_ule(
        &mut self,
        byte: &u8,
        value: usize,
        next_state: Self::PacketState,
        size: usize,
    ) -> usize {
        let ret = value + ((*byte as usize) << (8 * self.i()));
        self.set_i(self.i() + 1);
        self.next_state_when_i_reaches(next_state, size);
        ret
    }
    fn read_u16(&mut self, byte: &u8, value: u16, next_state: Self::PacketState) -> u16 {
        self._read_u(byte, value as usize, next_state, 2) as u16
    }
    fn read_ule16(&mut self, byte: &u8, value: u16, next_state: Self::PacketState) -> u16 {
        self._read_ule(byte, value as usize, next_state, 2) as u16
    }
    fn read_ule32(&mut self, byte: &u8, value: u32, next_state: Self::PacketState) -> u32 {
        self._read_ule(byte, value as usize, next_state, 4) as u32
    }
    fn read_ule64(&mut self, byte: &u8, value: u64, next_state: Self::PacketState) -> u64 {
        self._read_ule(byte, value as usize, next_state, 8) as u64
    }
}

/////////////
// Netbios //
/////////////

#[derive(Debug, Clone, Copy)]
enum NBTSessionState {
    NBType,
    Reserved,
    Length,
    End,
}

#[derive(Debug, Clone)]
struct NBTSession<T: Packet> {
    // DISSECTION
    state: NBTSessionState,
    i: usize,
    // STRUCT
    nb_type: u8,
    length: u16,
    payload: Option<T>,
}

impl<T: Packet> Packet for NBTSession<T> {
    type PacketState = NBTSessionState;

    fn i(&self) -> usize {
        self.i
    }
    fn set_i(&mut self, i: usize) {
        self.i = i;
    }
    fn state(&self) -> Self::PacketState {
        self.state
    }
    fn set_state(&mut self, state: Self::PacketState) {
        self.state = state;
    }

    fn new() -> NBTSession<T> {
        Self {
            state: NBTSessionState::NBType,
            i: 0,
            nb_type: 0,
            length: 0,
            payload: None,
        }
    }

    fn parse(&mut self, byte: &u8) {
        match self.state {
            NBTSessionState::NBType => {
                self.nb_type = *byte;
                self.next_state(NBTSessionState::Reserved);
            }
            NBTSessionState::Reserved => {
                self.next_state(NBTSessionState::Length);
            }
            NBTSessionState::Length => {
                self.length = self.read_u16(byte, self.length, NBTSessionState::End)
            }
            NBTSessionState::End => match self.get_payload() {
                Some(pay) => pay.parse(byte),
                None => return,
            },
        }
    }

    fn repl(&self) -> Option<Vec<u8>> {
        let payload_resp = self.payload.as_ref()?.repl()?;
        let mut resp: Vec<u8> = Vec::new();
        let size = payload_resp.len() & 0x1ffff; // 7 first bits are 0
        resp.push(0x0);
        // 7 bits reserved + 17 bits length
        resp.push(((size as u32 >> 16) & 0xff).try_into().unwrap());
        resp.extend_from_slice(&((size & 0xffff) as u16).to_be_bytes());
        resp.extend(payload_resp);
        Some(resp)
    }
}

impl<T: Packet> NBTSession<T> {
    fn get_payload(&mut self) -> Option<&mut T> {
        if self.payload.is_some() {
            return self.payload.as_mut();
        }
        self.payload = Some(T::new());
        self.payload.as_mut()
    }
}

//////////
// SMB1 //
//////////

#[derive(Debug, Clone, Copy)]
enum SMB1HeaderState {
    Start,
    Command,
    Status,
    Flags,
    Flags2,
    PIDHigh,
    SecuritySignature,
    Reserved,
    TID,
    PIDLow,
    UID,
    MID,
    End,
}

#[derive(Debug, Clone)]
struct SMB1Header {
    // DISSECTION
    state: SMB1HeaderState,
    i: usize,
    // STRUCT
    start: [u8; 4],
    command: u8,
    status: u32,
    flags: u8,
    flags2: u16,
    pid_high: u16,
    security_signature: [u8; 8],
    tid: u16,
    pid_low: u16,
    uid: u16,
    mid: u16,
    payload: Option<SMB1Payload>,
}

impl Packet for SMB1Header {
    type PacketState = SMB1HeaderState;

    fn i(&self) -> usize {
        self.i
    }
    fn set_i(&mut self, i: usize) {
        self.i = i;
    }
    fn state(&self) -> Self::PacketState {
        self.state
    }
    fn set_state(&mut self, state: Self::PacketState) {
        self.state = state;
    }

    fn new() -> SMB1Header {
        Self {
            state: SMB1HeaderState::Start,
            i: 0,
            start: [0; 4],
            command: 0,
            status: 0,
            flags: 0,
            flags2: 0,
            pid_high: 0,
            security_signature: [0; 8],
            tid: 0,
            pid_low: 0,
            uid: 0,
            mid: 0,
            payload: None,
        }
    }

    fn parse(&mut self, byte: &u8) {
        match self.state {
            SMB1HeaderState::Start => {
                self.start[self.i] = *byte;
                self.i += 1;
                self.next_state_when_i_reaches(SMB1HeaderState::Command, 4);
            }
            SMB1HeaderState::Command => {
                self.command = *byte;
                self.next_state(SMB1HeaderState::Status);
            }
            SMB1HeaderState::Status => {
                self.status = self.read_ule32(byte, self.status, SMB1HeaderState::Flags);
            }
            SMB1HeaderState::Flags => {
                self.flags = *byte;
                self.next_state(SMB1HeaderState::Flags2);
            }
            SMB1HeaderState::Flags2 => {
                self.flags2 = self.read_ule16(byte, self.flags2, SMB1HeaderState::PIDHigh);
            }
            SMB1HeaderState::PIDHigh => {
                self.pid_high =
                    self.read_ule16(byte, self.pid_high, SMB1HeaderState::SecuritySignature);
            }
            SMB1HeaderState::SecuritySignature => {
                self.security_signature[self.i] = *byte;
                self.i += 1;
                self.next_state_when_i_reaches(SMB1HeaderState::Reserved, 8);
            }
            SMB1HeaderState::Reserved => {
                self.i += 1;
                self.next_state_when_i_reaches(SMB1HeaderState::TID, 2);
            }
            SMB1HeaderState::TID => {
                self.tid = self.read_ule16(byte, self.tid, SMB1HeaderState::PIDLow);
            }
            SMB1HeaderState::PIDLow => {
                self.pid_low = self.read_ule16(byte, self.pid_low, SMB1HeaderState::UID);
            }
            SMB1HeaderState::UID => {
                self.uid = self.read_ule16(byte, self.uid, SMB1HeaderState::MID);
            }
            SMB1HeaderState::MID => {
                self.mid = self.read_ule16(byte, self.mid, SMB1HeaderState::End);
            }
            SMB1HeaderState::End => match self.get_payload() {
                Some(pay) => pay.parse(byte),
                None => return,
            },
        }
    }

    fn repl(&self) -> Option<Vec<u8>> {
        let payload_resp = self.payload.as_ref()?.repl()?;
        let mut resp: Vec<u8> = Vec::new();
        resp.extend_from_slice(b"\xffSMB"); // Start
        resp.push(self.command); // Command
        resp.extend_from_slice(&0_u32.to_le_bytes()); // Status
        resp.push(0x98); // Flags = CASE_INSENSITIVE+CANONICALIZED_PATHS+REPLY
        resp.extend_from_slice(&0xc807_u16.to_le_bytes()); // Flags2 = LONG_NAMES+EAS+SMB_SECURITY_SIGNATURE+EXTENDED_SECURITY+NT_STATUS+UNICODE
        resp.extend_from_slice(&self.pid_high.to_le_bytes()); // PIDHigh
        resp.extend_from_slice(&[0; 8]); // SecuritySignature
        resp.extend_from_slice(&[0; 2]); // Reserved
        resp.extend_from_slice(&self.tid.to_le_bytes()); // TID
        resp.extend_from_slice(&self.pid_low.to_le_bytes()); // PIDLOW
        resp.extend_from_slice(&self.uid.to_le_bytes()); // UID
        resp.extend_from_slice(&self.mid.to_le_bytes()); // MID
        resp.extend(payload_resp);
        Some(resp)
    }
}

impl SMB1Header {
    fn get_payload(&mut self) -> Option<&mut SMB1Payload> {
        if self.payload.is_some() {
            return self.payload.as_mut();
        }
        if self.flags & 0x80 == 0x80 {
            // Response
            return None;
        }
        self.payload = Some(match self.command {
            0x72 => {
                // Negotiate
                SMB1Payload::NegotiateRequest(SMB1NegotiateRequest::new())
            }
            // 0x73 => {
            //     // Setup
            //     SMB1Payload::SetupRequest(SMB2SetupRequest::new())
            // }
            _ => None?,
        });
        self.payload.as_mut()
    }
}

#[derive(Debug, Clone, PartialEq)]
struct SMB1Dialect {
    buffer_format: u8,
    dialect_string: String,
}

#[derive(Debug, Clone, Copy)]
enum SMB1NegotiateRequestState {
    WordCount,
    ByteCount,
    Dialects,
    End,
}

#[derive(Debug, Clone)]
struct SMB1NegotiateRequest {
    // DISSECTION
    state: SMB1NegotiateRequestState,
    i: usize,
    _tmp_dialect: Option<SMB1Dialect>,
    // STRUCT
    word_count: u8,
    byte_count: u16,
    dialects: Vec<SMB1Dialect>,
}

impl Packet for SMB1NegotiateRequest {
    type PacketState = SMB1NegotiateRequestState;

    fn i(&self) -> usize {
        self.i
    }
    fn set_i(&mut self, i: usize) {
        self.i = i;
    }
    fn state(&self) -> Self::PacketState {
        self.state
    }
    fn set_state(&mut self, state: Self::PacketState) {
        self.state = state;
    }

    fn new() -> SMB1NegotiateRequest {
        Self {
            state: SMB1NegotiateRequestState::WordCount,
            i: 0,
            _tmp_dialect: None,
            word_count: 0,
            byte_count: 0,
            dialects: Vec::new(),
        }
    }

    fn parse(&mut self, byte: &u8) {
        match self.state {
            SMB1NegotiateRequestState::WordCount => {
                self.word_count = *byte;
                self.next_state(SMB1NegotiateRequestState::ByteCount);
            }
            SMB1NegotiateRequestState::ByteCount => {
                self.byte_count =
                    self.read_ule16(byte, self.byte_count, SMB1NegotiateRequestState::Dialects);
            }
            SMB1NegotiateRequestState::Dialects => {
                self.i += 1;
                match self._tmp_dialect.as_mut() {
                    Some(dial) => {
                        if *byte == 0 {
                            // Final nul byte: dialect is finished
                            self.dialects.push(dial.clone());
                            self._tmp_dialect = None;
                            self.next_state_when_i_reaches(
                                SMB1NegotiateRequestState::End,
                                self.byte_count as usize,
                            );
                        } else {
                            dial.dialect_string.push(*byte as char);
                        }
                    }
                    None => {
                        self._tmp_dialect = Some(SMB1Dialect {
                            buffer_format: *byte,
                            dialect_string: String::new(),
                        });
                    }
                }
            }
            SMB1NegotiateRequestState::End => {}
        }
    }

    // fn new(data: &[u8]) -> Option<Self> {
    //     if data.len() < 15 {
    //         return None;
    //     }
    //     let word_count = data[0];
    //     let byte_count = LittleEndian::read_u16(&data[1..3]);
    //     let mut dialects = Vec::new();
    //     let mut i: usize = 3;
    //     while i < 3 + byte_count as usize {
    //         if i + 1 > data.len() {
    //             break;
    //         };
    //         // dialect_string is a string that ends with a \0 char
    //         let string_term = match data[i + 1..].iter().position(|&x| x == b'\0') {
    //             Some(x) => x,
    //             None => break,
    //         };
    //         let dialect_string = match std::str::from_utf8(&data[i + 1..i + 1 + string_term]) {
    //             Ok(x) => x,
    //             _ => break,
    //         };
    //         dialects.push(SMB1Dialect {
    //             buffer_format: data[i],
    //             dialect_string: String::from(dialect_string),
    //         });
    //         i += 2 + string_term;
    //     }
    //     Some(SMB1NegotiateRequest {
    //         word_count,
    //         byte_count,
    //         dialects,
    //     })
    // }

    fn repl(&self) -> Option<Vec<u8>> {
        if !matches!(self.state, SMB1NegotiateRequestState::End) {
            return None;
        }
        let mut resp: Vec<u8> = Vec::new();
        let time: u64 = (EPOCH_1601 + chrono::Utc::now().timestamp() as u64) * (1e7 as u64);
        let mut dialect_index: u16 = 0;
        let mut dialect_name = "Unknown";
        for dialect in ["NT LM 0.12", "SMB 2.???", "SMB 2.002"] {
            dialect_index = match self
                .dialects
                .iter()
                .position(|x| x.dialect_string.eq(dialect))
            {
                Some(x) => {
                    dialect_name = dialect;
                    x as u16
                }
                None => continue,
            };
            break;
        }
        resp.push(17); // WordCount
        resp.extend_from_slice(&dialect_index.to_le_bytes()); // DialectIndex
        resp.push(3); // SecurityMode
        resp.extend_from_slice(&50_u16.to_le_bytes()); // MaxMPXCount
        resp.extend_from_slice(&50_u16.to_le_bytes()); // MaxNumberVC
        resp.extend_from_slice(&0x10000_u32.to_le_bytes()); // MaxBufferSize
        resp.extend_from_slice(&0x10000_u32.to_le_bytes()); // MaxRawSize
        resp.extend_from_slice(&0x0_u32.to_le_bytes()); // SessionKey
        resp.extend_from_slice(&0x8001e3fc_u32.to_le_bytes()); // ServerCapabilities = UNICODE+LARGE_FILES+NT_SMBS+RPC_REMOTE_APIS+STATUS32+LEVEL_II_OPLOCKS+LOCK_AND_READ+NT_FIND+INFOLEVEL_PASSTHRU+LARGE_READX+LARGE_WRITEX+LWIO+EXTENDED_SECURITY
        resp.extend_from_slice(&time.to_le_bytes()); // ServerTime
        resp.extend_from_slice(&0x3c_u16.to_le_bytes()); // ServerTimeZone
        resp.push(0); // ChallengeLength
        resp.extend_from_slice(&((SECURITY_BLOB.len() + 16) as u16).to_le_bytes()); // ByteCount
                                                                                    // Challenge: Empty
        resp.extend_from_slice(&[0_u8; 16]); // GUID
        resp.extend_from_slice(SECURITY_BLOB); // SecurityBlob
        warn!("SMB1 Negotiate-Protocol-Reply ({})", dialect_name);
        Some(resp)
    }
}

// #[derive(Debug, Clone)]
// struct SMB1SetupRequest {
//
// }

// impl SMB1SetupRequest {
//     // TODO
//     fn new(data: &[u8]) -> Option<Self> {
//         if data.len() < 38 {
//             return None;
//         }
//         None
//     }

//     fn repl(&self) -> Option<Vec<u8>> {
//         None
//     }
// }

#[derive(Debug, Clone)]
enum SMB1Payload {
    NegotiateRequest(SMB1NegotiateRequest),
    // SetupRequest(SMB1SetupRequest),
}

impl SMB1Payload {
    fn repl(&self) -> Option<Vec<u8>> {
        match self {
            SMB1Payload::NegotiateRequest(x) => x.repl(),
            // SMB1Payload::SetupRequest(x) => x.repl(),
        }
    }
    fn parse(&mut self, byte: &u8) {
        match self {
            SMB1Payload::NegotiateRequest(x) => x.parse(byte),
            // SMB1Payload::SetupRequest(x) => x.repl(),
        }
    }
}

//////////
// SMB2 //
//////////

#[derive(Debug, Clone, Copy)]
enum SMB2HeaderState {
    Start,
    StructureSize,
    CreditsCharge,
    Status,
    Command,
    CreditsRequested,
    Flags,
    NextCommand,
    MessageId,
    AsyncId,
    SessionId,
    SecuritySignature,
    End,
}

#[derive(Debug, Clone)]
struct SMB2Header {
    // DISSECTION
    state: SMB2HeaderState,
    i: usize,
    // STRUCT
    start: [u8; 4],
    structure_size: u16,
    credit_charge: u16,
    status: u32,
    command: u16,
    credits_requested: u16,
    flags: u32,
    next_command: u32,
    message_id: u64,
    async_id: u64,
    session_id: u64,
    security_signature: [u8; 16],
    // Payload
    payload: Option<SMB2Payload>,
}

impl Packet for SMB2Header {
    type PacketState = SMB2HeaderState;

    fn i(&self) -> usize {
        self.i
    }
    fn set_i(&mut self, i: usize) {
        self.i = i;
    }
    fn state(&self) -> Self::PacketState {
        self.state
    }
    fn set_state(&mut self, state: Self::PacketState) {
        self.state = state;
    }

    fn new() -> SMB2Header {
        SMB2Header {
            state: SMB2HeaderState::Start,
            i: 0,
            start: [0; 4],
            structure_size: 0,
            credit_charge: 0,
            status: 0,
            command: 0,
            credits_requested: 0,
            flags: 0,
            next_command: 0,
            message_id: 0,
            async_id: 0,
            session_id: 0,
            security_signature: [0; 16],
            payload: None,
        }
    }

    fn parse(&mut self, byte: &u8) {
        match self.state {
            SMB2HeaderState::Start => {
                self.start[self.i] = *byte;
                self.i += 1;
                self.next_state_when_i_reaches(SMB2HeaderState::StructureSize, 4);
            }
            SMB2HeaderState::StructureSize => {
                self.structure_size =
                    self.read_ule16(byte, self.structure_size, SMB2HeaderState::CreditsCharge)
            }
            SMB2HeaderState::CreditsCharge => {
                self.credit_charge =
                    self.read_ule16(byte, self.credit_charge, SMB2HeaderState::Status)
            }
            SMB2HeaderState::Status => {
                self.status = self.read_ule32(byte, self.status, SMB2HeaderState::Command)
            }
            SMB2HeaderState::Command => {
                self.command =
                    self.read_ule16(byte, self.command, SMB2HeaderState::CreditsRequested)
            }
            SMB2HeaderState::CreditsRequested => {
                self.credits_requested =
                    self.read_ule16(byte, self.credits_requested, SMB2HeaderState::Flags)
            }
            SMB2HeaderState::Flags => {
                self.flags = self.read_ule32(byte, self.flags, SMB2HeaderState::NextCommand)
            }
            SMB2HeaderState::NextCommand => {
                self.next_command =
                    self.read_ule32(byte, self.next_command, SMB2HeaderState::MessageId)
            }
            SMB2HeaderState::MessageId => {
                self.message_id = self.read_ule64(byte, self.message_id, SMB2HeaderState::AsyncId)
            }
            SMB2HeaderState::AsyncId => {
                self.async_id = self.read_ule64(byte, self.async_id, SMB2HeaderState::SessionId)
            }
            SMB2HeaderState::SessionId => {
                self.session_id =
                    self.read_ule64(byte, self.session_id, SMB2HeaderState::SecuritySignature)
            }
            SMB2HeaderState::SecuritySignature => {
                self.security_signature[self.i] = *byte;
                self.i += 1;
                self.next_state_when_i_reaches(SMB2HeaderState::End, 16);
            }
            SMB2HeaderState::End => match self.get_payload() {
                Some(pay) => pay.parse(byte),
                None => return,
            },
        }
    }

    fn repl(&self) -> Option<Vec<u8>> {
        let payload_resp = self.payload.as_ref()?.repl()?;
        let mut resp: Vec<u8> = Vec::new();
        resp.extend_from_slice(b"\xfeSMB"); // Start
        resp.extend_from_slice(&64_u16.to_le_bytes()); // StructureSize
        resp.extend_from_slice(&0_u16.to_le_bytes()); // CreditCharge
        resp.extend_from_slice(&0_u32.to_le_bytes()); // Status
        resp.extend_from_slice(&self.command.to_le_bytes()); // Command
        resp.extend_from_slice(&1_u16.to_le_bytes()); // CreditsRequested
        resp.extend_from_slice(&1_u32.to_le_bytes()); // Flags = Response
        resp.extend_from_slice(&0_u32.to_le_bytes()); // NextCommand
        resp.extend_from_slice(&self.message_id.to_le_bytes()); // MessageId
        resp.extend_from_slice(&self.async_id.to_le_bytes()); // AsyncId
        resp.extend_from_slice(&self.session_id.to_le_bytes()); // SessionId
        resp.extend_from_slice(&[0; 16]); // SecuritySignature
                                          // Payload
        resp.extend(payload_resp);
        Some(resp)
    }
}

impl SMB2Header {
    fn get_payload(&mut self) -> Option<&mut SMB2Payload> {
        if let Some(_) = &self.payload {
            return self.payload.as_mut();
        }
        if self.flags & 1 == 1 {
            // Response
            return None;
        }
        self.payload = Some(match self.command {
            0x0000 => {
                // Negotiate
                SMB2Payload::NegotiateRequest(SMB2NegotiateRequest::new())
            }
            // 0x0001 => {
            //     // Setup
            //     SMB2Payload::SetupRequest(SMB2SetupRequest::new())
            // }
            _ => None?,
        });
        self.payload.as_mut()
    }
}

#[derive(Debug, Clone, Copy)]
enum SMB2NegotiateRequestState {
    StructureSize,
    DialectCount,
    SecurityMode,
    Reserved,
    Capabilities,
    ClientGUID,
    NegotiateAndReserved2,
    Dialects,
    End,
}

#[derive(Debug, Clone)]
struct SMB2NegotiateRequest {
    // DISSECTION
    state: SMB2NegotiateRequestState,
    i: usize,
    _tmp_dialect: u16,
    // STRUCT
    structure_size: u16,
    dialect_count: u16,
    security_mode: u16,
    capabilities: u32,
    client_guid: [u8; 16],
    dialects: HashSet<u16>,
}
const EPOCH_1601: u64 = 11644473600;

impl Packet for SMB2NegotiateRequest {
    type PacketState = SMB2NegotiateRequestState;

    fn i(&self) -> usize {
        self.i
    }
    fn set_i(&mut self, i: usize) {
        self.i = i;
    }
    fn state(&self) -> Self::PacketState {
        self.state
    }
    fn set_state(&mut self, state: Self::PacketState) {
        self.state = state;
    }

    fn new() -> Self {
        SMB2NegotiateRequest {
            state: SMB2NegotiateRequestState::StructureSize,
            i: 0,
            _tmp_dialect: 0,
            structure_size: 0,
            dialect_count: 0,
            security_mode: 0,
            capabilities: 0,
            client_guid: [0; 16],
            dialects: HashSet::new(),
        }
    }

    fn parse(&mut self, byte: &u8) {
        match self.state {
            SMB2NegotiateRequestState::StructureSize => {
                self.structure_size = self.read_ule16(
                    byte,
                    self.structure_size,
                    SMB2NegotiateRequestState::DialectCount,
                );
            }
            SMB2NegotiateRequestState::DialectCount => {
                self.dialect_count = self.read_ule16(
                    byte,
                    self.dialect_count,
                    SMB2NegotiateRequestState::SecurityMode,
                );
            }
            SMB2NegotiateRequestState::SecurityMode => {
                self.security_mode = self.read_ule16(
                    byte,
                    self.security_mode,
                    SMB2NegotiateRequestState::Reserved,
                );
            }
            SMB2NegotiateRequestState::Reserved => {
                self.i += 1;
                self.next_state_when_i_reaches(SMB2NegotiateRequestState::Capabilities, 2);
            }
            SMB2NegotiateRequestState::Capabilities => {
                self.capabilities = self.read_ule32(
                    byte,
                    self.capabilities,
                    SMB2NegotiateRequestState::ClientGUID,
                );
            }
            SMB2NegotiateRequestState::ClientGUID => {
                self.client_guid[self.i] = *byte;
                self.i += 1;
                self.next_state_when_i_reaches(
                    SMB2NegotiateRequestState::NegotiateAndReserved2,
                    16,
                );
            }
            SMB2NegotiateRequestState::NegotiateAndReserved2 => {
                self.i += 1;
                self.next_state_when_i_reaches(SMB2NegotiateRequestState::Dialects, 8);
            }
            SMB2NegotiateRequestState::Dialects => {
                self._tmp_dialect =
                    self.read_ule16(byte, self._tmp_dialect, SMB2NegotiateRequestState::Dialects);
                if self.i == 0 {
                    // Add to dialects list when finished
                    self.dialects.insert(self._tmp_dialect);
                    self._tmp_dialect = 0;
                    // Check if dialects list is finished
                    if self.dialects.len() == self.dialect_count as usize {
                        self.state = SMB2NegotiateRequestState::End;
                    }
                }
            }
            SMB2NegotiateRequestState::End => {
                return;
            }
        }
    }
    fn repl(&self) -> Option<Vec<u8>> {
        if !matches!(self.state, SMB2NegotiateRequestState::End) {
            return None;
        }
        let mut resp: Vec<u8> = Vec::new();
        let time: u64 = (EPOCH_1601 + chrono::Utc::now().timestamp() as u64) * (1e7 as u64);
        // Chose dialect
        let smb2_versions = [
            (0x0202, "SMB 2.002"),
            (0x0210, "SMB 2.1"),
            (0x02ff, "SMB 2.???"),
            (0x0300, "SMB 3.0"),
            (0x0302, "SMB 2.0.2"),
            (0x0310, "SMB 3.1.0"),
            (0x0311, "SMB 3.1.1"),
        ];
        let mut dialect = None;
        let mut dialect_name = "Unknown";
        if let Some(smb_ver) = smb2_versions
            .iter()
            .find(|(d, _)| self.dialects.contains(d))
        {
            dialect = Some(smb_ver.0);
            dialect_name = smb_ver.1;
        }
        resp.extend_from_slice(&0x41_u16.to_le_bytes()); // StructureSize
        resp.extend_from_slice(&0x1_u16.to_le_bytes()); // SecurityMode
        resp.extend_from_slice(&dialect?.to_le_bytes()); // DialectRevision
        resp.extend_from_slice(&0x1_u16.to_le_bytes()); // NegotiateCount
        resp.extend_from_slice(&self.client_guid); // GUID
        resp.extend_from_slice(&0x1_u32.to_le_bytes()); // Capabilities
        resp.extend_from_slice(&0x10000_u32.to_le_bytes()); // MaxTransactionSize
        resp.extend_from_slice(&0x10000_u32.to_le_bytes()); // MaxReadSize
        resp.extend_from_slice(&0x10000_u32.to_le_bytes()); // MaxWriteSize
        resp.extend_from_slice(&time.to_le_bytes()); // ServerTime
        resp.extend_from_slice(&time.to_le_bytes()); // ServerStartTime
        resp.extend_from_slice(&0x80_u16.to_le_bytes()); // SecurityBloboffset
        resp.extend_from_slice(&(SECURITY_BLOB.len() as u16).to_le_bytes()); // SecurityBlobLength
        resp.extend_from_slice(&0x0_u32.to_le_bytes()); // NegotiateContextOffset
        resp.extend_from_slice(SECURITY_BLOB); // SecurityBlob
        warn!("SMB2 Negotiate-Protocol-Reply ({})", dialect_name);
        Some(resp)
    }
}

// #[derive(Debug, Clone)]
// struct SMB2SetupRequest {}
// impl SMB2SetupRequest {
//     fn new() -> Self {
//         SMB2SetupRequest {}
//     }

//     fn repl(&self) -> Option<Vec<u8>> {
//         (None, None)
//     }
// }

#[derive(Debug, Clone)]
enum SMB2Payload {
    NegotiateRequest(SMB2NegotiateRequest),
    // SetupRequest(SMB2SetupRequest),
}

impl SMB2Payload {
    fn repl(&self) -> Option<Vec<u8>> {
        match self {
            SMB2Payload::NegotiateRequest(x) => x.repl(),
            // SMB2Payload::SetupRequest(x) => x.repl(),
        }
    }
    fn parse(&mut self, byte: &u8) {
        match self {
            SMB2Payload::NegotiateRequest(x) => x.parse(byte),
            // SMB2Payload::SetupRequest(x) => x.repl(),
        }
    }
}

//////////////
// Handlers //
//////////////

pub fn repl_smb1<'a>(
    data: &'a [u8],
    _masscanned: &Masscanned,
    _client_info: &ClientInfo,
) -> Option<Vec<u8>> {
    let mut nbtsession: NBTSession<SMB1Header> = NBTSession::new();
    for byte in data {
        nbtsession.parse(byte);
    }
    return nbtsession.repl();
}

pub fn repl_smb2<'a>(
    data: &'a [u8],
    _masscanned: &Masscanned,
    _client_info: &ClientInfo,
) -> Option<Vec<u8>> {
    let mut nbtsession: NBTSession<SMB2Header> = NBTSession::new();
    for byte in data {
        nbtsession.parse(byte);
    }
    return nbtsession.repl();
}

///////////
// Tests //
///////////

#[cfg(test)]
mod tests {
    use super::*;
    use itertools::assert_equal;
    use pnet::util::MacAddr;
    use std::str::FromStr;

    // Sent by `smbclient -U "" -N -L 10.1.1.1 -d10 --option='client min protocol=NT1'`
    const SMB1_REQ_PAYLOAD: &[u8] = b"\x00\x00\x00T\xffSMBr\x00\x00\x00\x00\x18C\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfe\xff\x00\x00\x00\x00\x001\x00\x02NT LANMAN 1.0\x00\x02NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00";
    // Sent by `smbclient -U "" -N -L 10.1.1.1 -d10`
    const SMB2_REQ_PAYLOAD: &[u8] = b"\x00\x00\x00\xd0\xfeSMB@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$\x00\x08\x00\x01\x00\x00\x00\x7f\x00\x00\x00\rr3\x97\"c\x8fA\x9f\xe0\xbawQ\x87rbx\x00\x00\x00\x03\x00\x00\x00\x02\x02\x10\x02\"\x02$\x02\x00\x03\x02\x03\x10\x03\x11\x03\x00\x00\x00\x00\x01\x00&\x00\x00\x00\x00\x00\x01\x00 \x00\x01\x00\xd5Z\x89\x87>\x80\xcd\x02\xc2\xab\x08\xa3\xf4\x94\xb6A\x05\x11V\xeeE\x19p\x19\xed\x17v\xda\x9b\x08\x99V\x00\x00\x02\x00\x06\x00\x00\x00\x00\x00\x02\x00\x02\x00\x01\x00\x00\x00\x05\x00\x10\x00\x00\x00\x00\x001\x000\x00.\x001\x00.\x001\x00.\x001\x00";
    // You can dissect any of those payloads with Scapy using NBTSession(b"...")

    #[test]
    fn test_smb1_protocol_nego_parsing() {
        let mut nbtsession: NBTSession<SMB1Header> = NBTSession::new();
        nbtsession.parse_all(SMB1_REQ_PAYLOAD);
        assert_eq!(nbtsession.nb_type, 0);
        assert_eq!(nbtsession.length, 0x54);
        let smb1 = nbtsession.payload.expect("Error while unpacking SMB");
        assert_eq!(&smb1.start, b"\xffSMB");
        assert_eq!(smb1.command, 0x72);
        assert_eq!(smb1.status, 0);
        assert_eq!(smb1.flags, 24);
        assert_eq!(smb1.flags2, 51267);
        assert_eq!(smb1.pid_high, 0);
        assert_eq!(smb1.security_signature, [0; 8]);
        assert_eq!(smb1.tid, 0);
        assert_eq!(smb1.pid_low, 65534);
        assert_eq!(smb1.uid, 0);
        assert_eq!(smb1.mid, 0);
        let neg_request = match smb1.payload.expect("Error while reading payload") {
            SMB1Payload::NegotiateRequest(x) => x,
        };
        assert_eq!(neg_request.word_count, 0);
        assert_eq!(neg_request.byte_count, 49);
        assert_equal(
            neg_request.dialects,
            Vec::from([
                SMB1Dialect {
                    buffer_format: 2,
                    dialect_string: "NT LANMAN 1.0".to_string(),
                },
                SMB1Dialect {
                    buffer_format: 2,
                    dialect_string: "NT LM 0.12".to_string(),
                },
                SMB1Dialect {
                    buffer_format: 2,
                    dialect_string: "SMB 2.002".to_string(),
                },
                SMB1Dialect {
                    buffer_format: 2,
                    dialect_string: "SMB 2.???".to_string(),
                },
            ]),
        );
    }
    #[test]
    fn test_smb1_protocol_nego_reply() {
        let masscanned = Masscanned {
            synack_key: [0, 0],
            mac: MacAddr::from_str("00:00:00:00:00:00").expect("error parsing default MAC address"),
            iface: None,
            ip_addresses: None,
        };
        let client_info = ClientInfo::new();
        let answer =
            repl_smb1(SMB1_REQ_PAYLOAD, &masscanned, &client_info).expect("Error: no answer");
        let expected = [
            0, 0, 1, 149, 255, 83, 77, 66, 114, 0, 0, 0, 0, 152, 7, 200, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 254, 255, 0, 0, 0, 0, 17, 1, 0, 3, 50, 0, 50, 0, 0, 0, 1, 0, 0, 0, 1, 0,
            0, 0, 0, 0, 252, 227, 1, 128, 0, 250, 218, 34, 238, 28, 216, 1, 60, 0, 0, 80, 1, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 96, 130, 1, 60, 6, 6, 43, 6, 1, 5, 5, 2, 160,
            130, 1, 48, 48, 130, 1, 44, 160, 26, 48, 24, 6, 10, 43, 6, 1, 4, 1, 130, 55, 2, 2, 30,
            6, 10, 43, 6, 1, 4, 1, 130, 55, 2, 2, 10, 162, 130, 1, 12, 4, 130, 1, 8, 78, 69, 71,
            79, 69, 88, 84, 83, 1, 0, 0, 0, 0, 0, 0, 0, 96, 0, 0, 0, 112, 0, 0, 0, 49, 60, 42, 58,
            199, 43, 60, 169, 109, 172, 56, 116, 167, 221, 29, 91, 244, 82, 107, 23, 3, 138, 75,
            145, 194, 9, 125, 154, 143, 230, 44, 150, 92, 81, 36, 47, 144, 77, 71, 199, 173, 143,
            135, 107, 34, 2, 191, 198, 0, 0, 0, 0, 0, 0, 0, 0, 96, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 92, 51, 83, 13, 234, 249, 13, 77, 178, 236, 74, 227, 120, 110, 195, 8, 78,
            69, 71, 79, 69, 88, 84, 83, 3, 0, 0, 0, 1, 0, 0, 0, 64, 0, 0, 0, 152, 0, 0, 0, 49, 60,
            42, 58, 199, 43, 60, 169, 109, 172, 56, 116, 167, 221, 29, 91, 92, 51, 83, 13, 234,
            249, 13, 77, 178, 236, 74, 227, 120, 110, 195, 8, 64, 0, 0, 0, 88, 0, 0, 0, 48, 86,
            160, 84, 48, 82, 48, 39, 128, 37, 48, 35, 49, 33, 48, 31, 6, 3, 85, 4, 3, 19, 24, 84,
            111, 107, 101, 110, 32, 83, 105, 103, 110, 105, 110, 103, 32, 80, 117, 98, 108, 105,
            99, 32, 75, 101, 121, 48, 39, 128, 37, 48, 35, 49, 33, 48, 31, 6, 3, 85, 4, 3, 19, 24,
            84, 111, 107, 101, 110, 32, 83, 105, 103, 110, 105, 110, 103, 32, 80, 117, 98, 108,
            105, 99, 32, 75, 101, 121,
        ];
        assert_eq!(answer[..0x3c], expected[..0x3c]); // Test equality except "ServerTime" field
        assert_eq!(answer[0x3c + 8..], expected[0x3c + 8..]);
    }
    #[test]
    fn test_smb2_protocol_nego_parsing() {
        let mut nbtsession: NBTSession<SMB2Header> = NBTSession::new();
        nbtsession.parse_all(SMB2_REQ_PAYLOAD);
        assert_eq!(nbtsession.nb_type, 0);
        assert_eq!(nbtsession.length, 0xd0);
        let smb2 = nbtsession.payload.expect("No SMB2 payload found !");
        assert_eq!(&smb2.start, b"\xfeSMB");
        assert_eq!(smb2.structure_size, 64);
        assert_eq!(smb2.credit_charge, 0);
        assert_eq!(smb2.status, 0);
        assert_eq!(smb2.command, 0);
        assert_eq!(smb2.credits_requested, 31);
        assert_eq!(smb2.flags, 0);
        assert_eq!(smb2.next_command, 0);
        assert_eq!(smb2.message_id, 0);
        assert_eq!(smb2.async_id, 0);
        assert_eq!(smb2.session_id, 0);
        assert_eq!(smb2.security_signature, [0; 16]);
        let neg_request = match smb2.payload.expect("Error while reading payload") {
            SMB2Payload::NegotiateRequest(x) => x,
        };
        assert_eq!(neg_request.structure_size, 36);
        assert_eq!(neg_request.dialect_count, 8);
        assert_eq!(neg_request.security_mode, 1);
        assert_eq!(neg_request.capabilities, 127);
        assert_eq!(
            neg_request.client_guid,
            [13, 114, 51, 151, 34, 99, 143, 65, 159, 224, 186, 119, 81, 135, 114, 98]
        );
        assert_eq!(
            neg_request.dialects,
            HashSet::from([514, 528, 546, 548, 768, 770, 784, 785])
        );
    }
    #[test]
    fn test_smb2_protocol_nego_reply() {
        let masscanned = Masscanned {
            synack_key: [0, 0],
            mac: MacAddr::from_str("00:00:00:00:00:00").expect("error parsing default MAC address"),
            iface: None,
            ip_addresses: None,
        };
        let client_info = ClientInfo::new();
        let answer =
            repl_smb2(SMB2_REQ_PAYLOAD, &masscanned, &client_info).expect("Error: no answer");
        let expected = [
            0, 0, 1, 192, 254, 83, 77, 66, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 65, 0, 1, 0, 2, 2, 1, 0, 13, 114, 51, 151, 34,
            99, 143, 65, 159, 224, 186, 119, 81, 135, 114, 98, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0,
            0, 0, 1, 0, 0, 103, 222, 3, 242, 28, 216, 1, 0, 103, 222, 3, 242, 28, 216, 1, 128, 0,
            64, 1, 0, 0, 0, 0, 96, 130, 1, 60, 6, 6, 43, 6, 1, 5, 5, 2, 160, 130, 1, 48, 48, 130,
            1, 44, 160, 26, 48, 24, 6, 10, 43, 6, 1, 4, 1, 130, 55, 2, 2, 30, 6, 10, 43, 6, 1, 4,
            1, 130, 55, 2, 2, 10, 162, 130, 1, 12, 4, 130, 1, 8, 78, 69, 71, 79, 69, 88, 84, 83, 1,
            0, 0, 0, 0, 0, 0, 0, 96, 0, 0, 0, 112, 0, 0, 0, 49, 60, 42, 58, 199, 43, 60, 169, 109,
            172, 56, 116, 167, 221, 29, 91, 244, 82, 107, 23, 3, 138, 75, 145, 194, 9, 125, 154,
            143, 230, 44, 150, 92, 81, 36, 47, 144, 77, 71, 199, 173, 143, 135, 107, 34, 2, 191,
            198, 0, 0, 0, 0, 0, 0, 0, 0, 96, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 92, 51,
            83, 13, 234, 249, 13, 77, 178, 236, 74, 227, 120, 110, 195, 8, 78, 69, 71, 79, 69, 88,
            84, 83, 3, 0, 0, 0, 1, 0, 0, 0, 64, 0, 0, 0, 152, 0, 0, 0, 49, 60, 42, 58, 199, 43, 60,
            169, 109, 172, 56, 116, 167, 221, 29, 91, 92, 51, 83, 13, 234, 249, 13, 77, 178, 236,
            74, 227, 120, 110, 195, 8, 64, 0, 0, 0, 88, 0, 0, 0, 48, 86, 160, 84, 48, 82, 48, 39,
            128, 37, 48, 35, 49, 33, 48, 31, 6, 3, 85, 4, 3, 19, 24, 84, 111, 107, 101, 110, 32,
            83, 105, 103, 110, 105, 110, 103, 32, 80, 117, 98, 108, 105, 99, 32, 75, 101, 121, 48,
            39, 128, 37, 48, 35, 49, 33, 48, 31, 6, 3, 85, 4, 3, 19, 24, 84, 111, 107, 101, 110,
            32, 83, 105, 103, 110, 105, 110, 103, 32, 80, 117, 98, 108, 105, 99, 32, 75, 101, 121,
        ];
        assert_eq!(answer[..0x6c], expected[..0x6c]); // Test equality except the 2 "ServerTime" fields
        assert_eq!(answer[0x6c + 16..], expected[0x6c + 16..]);
    }
}
