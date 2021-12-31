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

use std::str;

use crate::client::ClientInfo;
use crate::proto::TCPControlBlock;
use crate::Masscanned;

pub const SSH_PATTERN_CLIENT_PROTOCOL: &[u8; 7] = b"SSH-2.0";

pub fn repl<'a>(
    data: &'a [u8],
    _masscanned: &Masscanned,
    mut _client_info: &mut ClientInfo,
    _tcb: Option<&mut TCPControlBlock>,
) -> Option<Vec<u8>> {
    debug!("receiving SSH data");
    let repl_data = b"SSH-2.0-1\r\n".to_vec();
    debug!("sending SSH answer");
    warn!(
        "SSH server banner to {}",
        str::from_utf8(&data).unwrap().trim_end()
    );
    return Some(repl_data);
}
