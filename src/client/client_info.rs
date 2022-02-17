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

use std::fmt::{Display, Error};
use std::hash::Hash;
use std::net::IpAddr;

use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::util::MacAddr;

#[derive(PartialEq, Hash, Copy, Clone, Debug)]
pub struct ClientInfoSrcDst<A: Hash + PartialEq + Clone> {
    pub src: Option<A>,
    pub dst: Option<A>,
}

/* Structure to describe useful information
 * about a client connection, such as:
 * - source mac address
 * - source and dest. IP address
 * - transport layer protocol
 * - source and dest. transport port
 * - syn cookie
 **/
#[derive(Copy, Clone, PartialEq, Debug)]
pub struct ClientInfo {
    pub mac: ClientInfoSrcDst<MacAddr>,
    pub ip: ClientInfoSrcDst<IpAddr>,
    pub transport: Option<IpNextHeaderProtocol>,
    pub port: ClientInfoSrcDst<u16>,
    pub cookie: Option<u32>,
}

impl ClientInfo {
    pub fn new() -> Self {
        ClientInfo {
            mac: ClientInfoSrcDst::<MacAddr> {
                src: None,
                dst: None,
            },
            ip: ClientInfoSrcDst::<IpAddr> {
                src: None,
                dst: None,
            },
            transport: None,
            port: ClientInfoSrcDst::<u16> {
                src: None,
                dst: None,
            },
            cookie: None,
        }
    }
}

impl Eq for ClientInfo {}

impl Display for ClientInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), Error> {
        write!(
            f,
            "{:>width_ip$}:{:<width_port$} > {:>width_port$}:{:<width_ip$}",
            self.ip.src.unwrap(),
            self.port.src.unwrap(),
            self.port.dst.unwrap(),
            self.ip.dst.unwrap(),
            width_ip = 15,
            width_port = 5
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::packet::ip::IpNextHeaderProtocols;
    use std::net::Ipv4Addr;

    impl ClientInfo {
        pub fn new_test() -> Self {
            ClientInfo {
                mac: ClientInfoSrcDst {
                    src: Some(MacAddr::new(0, 0, 0, 0, 0, 0)),
                    dst: Some(MacAddr::new(0, 0, 0, 0, 0, 0)),
                },
                ip: ClientInfoSrcDst {
                    src: Some(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
                    dst: Some(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
                },
                transport: Some(IpNextHeaderProtocols::Tcp),
                port: ClientInfoSrcDst {
                    src: Some(0),
                    dst: Some(0),
                },
                cookie: Some(0),
            }
        }
    }

    #[test]
    fn test_client_info_eq() {
        let client_ref = ClientInfo::new_test();
        /* two clients with different mac addr should be different */
        let mut client_test = ClientInfo::new_test();
        assert!(client_test == client_ref);
        client_test.mac.src = Some(MacAddr::new(1, 0, 0, 0, 0, 0));
        assert!(client_test != client_ref);
        client_test.mac.src = Some(MacAddr::new(0, 0, 0, 0, 0, 0));
        client_test.mac.dst = Some(MacAddr::new(1, 0, 0, 0, 0, 0));
        assert!(client_test != client_ref);
        client_test.mac.dst = Some(MacAddr::new(0, 0, 0, 0, 0, 0));
        assert!(client_test == client_ref);
        /* two clients with different ip addr should be different */
        let mut client_test = ClientInfo::new_test();
        assert!(client_test == client_ref);
        client_test.ip.src = Some(IpAddr::V4(Ipv4Addr::new(1, 0, 0, 0)));
        assert!(client_test != client_ref);
        client_test.ip.src = Some(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
        client_test.ip.dst = Some(IpAddr::V4(Ipv4Addr::new(1, 0, 0, 0)));
        assert!(client_test != client_ref);
        /* two clients with different tranport layer should be different */
        let mut client_test = ClientInfo::new_test();
        assert!(client_test == client_ref);
        client_test.transport = Some(IpNextHeaderProtocols::Udp);
        assert!(client_test != client_ref);
        client_test.transport = Some(IpNextHeaderProtocols::Tcp);
        assert!(client_test == client_ref);
        /* two clients with different tranport ports should be different */
        let mut client_test = ClientInfo::new_test();
        assert!(client_test == client_ref);
        client_test.port.src = Some(1);
        assert!(client_test != client_ref);
        client_test.port.src = Some(0);
        client_test.port.dst = Some(1);
        assert!(client_test != client_ref);
        client_test.port.dst = Some(0);
        assert!(client_test == client_ref);
        /* two clients with different cookies should be different */
        let mut client_test = ClientInfo::new_test();
        assert!(client_test == client_ref);
        client_test.cookie = Some(1);
        assert!(client_test != client_ref);
        client_test.cookie = Some(0);
        assert!(client_test == client_ref);
    }
}
