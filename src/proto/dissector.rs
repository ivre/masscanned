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

use crate::proto::ClientInfo;
use crate::proto::TCPControlBlock;
use crate::Masscanned;

////////////
// Common //
////////////

/// ### PacketDissector
/// A util class used to dissect fields.
#[derive(Debug, Clone)]
pub struct PacketDissector<T> {
    pub i: usize,
    pub state: T,
}

impl<T> PacketDissector<T> {
    pub fn new(initial_state: T) -> PacketDissector<T> {
        return PacketDissector {
            i: 0,
            state: initial_state,
        };
    }
    pub fn next_state(&mut self, state: T) {
        self.state = state;
        self.i = 0;
    }
    pub fn next_state_when_i_reaches(&mut self, state: T, i: usize) {
        if self.i == i {
            self.next_state(state);
        }
    }
    fn _read_usize(&mut self, byte: &u8, value: usize, next_state: T, size: usize) -> usize {
        self.i += 1;
        self.next_state_when_i_reaches(next_state, size);
        (value << 8) + *byte as usize
    }
    fn _read_ulesize(&mut self, byte: &u8, value: usize, next_state: T, size: usize) -> usize {
        let ret = value + ((*byte as usize) << (8 * self.i));
        self.i += 1;
        self.next_state_when_i_reaches(next_state, size);
        ret
    }
    pub fn read_u16(&mut self, byte: &u8, value: u16, next_state: T) -> u16 {
        self._read_usize(byte, value as usize, next_state, 2) as u16
    }
    pub fn read_ule16(&mut self, byte: &u8, value: u16, next_state: T) -> u16 {
        self._read_ulesize(byte, value as usize, next_state, 2) as u16
    }
    pub fn read_u32(&mut self, byte: &u8, value: u32, next_state: T) -> u32 {
        self._read_usize(byte, value as usize, next_state, 4) as u32
    }
    pub fn read_ule32(&mut self, byte: &u8, value: u32, next_state: T) -> u32 {
        self._read_ulesize(byte, value as usize, next_state, 4) as u32
    }
    pub fn read_ule64(&mut self, byte: &u8, value: u64, next_state: T) -> u64 {
        self._read_ulesize(byte, value as usize, next_state, 8) as u64
    }
}

pub trait MPacket {
    fn new() -> Self;
    fn repl(
        &self,
        _masscanned: &Masscanned,
        _client_info: &ClientInfo,
        _tcb: Option<&mut TCPControlBlock>,
    ) -> Option<Vec<u8>>;
    fn parse(&mut self, byte: &u8);

    fn parse_all(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.parse(byte);
        }
    }
}
