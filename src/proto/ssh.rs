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

use crate::client::ClientInfo;
use crate::proto::TCPControlBlock;
use crate::utils::byte2str;
use crate::Masscanned;

pub const SSH_PATTERN_CLIENT_PROTOCOL: &[u8; 7] = b"SSH-2.0";

pub fn repl<'a>(
    data: &'a [u8],
    _masscanned: &Masscanned,
    mut _client_info: &ClientInfo,
    _tcb: Option<&mut TCPControlBlock>,
) -> Option<Vec<u8>> {
    debug!("receiving SSH data");
    let repl_data = b"SSH-2.0-1\r\n".to_vec();
    debug!("sending SSH answer");
    warn!("SSH server banner to {}", byte2str(data));
    return Some(repl_data);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::ClientInfoSrcDst;
    use crate::MetaLogger;
    use pnet::util::MacAddr;
    use std::net::IpAddr;
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
    fn test_ssh_wrong_banner() {
        let masscanned = Masscanned {
            synack_key: [0, 0],
            mac: MacAddr(0, 1, 2, 3, 4, 5),
            iface: None,
            ip_addresses: None,
            log: MetaLogger::new(),
        };
        stderrlog::new()
            .module(module_path!())
            .verbosity(1)
            .init()
            .expect("error while initializing logging module");
        let req = b"\xff";
        repl(req, &masscanned, &CLIENT_INFO, None);
    }
}
