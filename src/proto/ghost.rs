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
use std::io::Write;

use flate2::write::ZlibEncoder;
use flate2::Compression;

use crate::client::ClientInfo;
use crate::Masscanned;

pub const GHOST_PATTERN_SIGNATURE: &[u8; 5] = b"Gh0st";

pub fn repl<'a>(
    _data: &'a [u8],
    _masscanned: &Masscanned,
    _client_info: &mut ClientInfo,
) -> Option<Vec<u8>> {
    debug!("receiving Gh0st data, sending one null byte payload");
    // Packet structure:
    // GHOST_PATTERN_SIGNATURE + [ packet size ] + [ uncompressed payload size ] + payload
    let mut result = GHOST_PATTERN_SIGNATURE.to_vec();
    let uncompressed_data = b"\x00";
    let mut compressed_data = ZlibEncoder::new(Vec::new(), Compression::default());
    compressed_data
        .write_all(uncompressed_data)
        .expect("Ghost: cannot decompress payload");
    let mut compressed_data = compressed_data
        .finish()
        .expect("Ghost: cannot decompress payload");
    let mut packet_len = compressed_data.len() + GHOST_PATTERN_SIGNATURE.len() + 4 * 2;
    for _ in 0..4 {
        result.push((packet_len % 256) as u8);
        packet_len /= 256;
    }
    let mut uncompressed_len = uncompressed_data.len();
    for _ in 0..4 {
        result.push((uncompressed_len % 256) as u8);
        uncompressed_len /= 256;
    }
    result.append(&mut compressed_data);
    Some(result)
}
