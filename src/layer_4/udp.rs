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

use pnet::packet::{
    udp::{MutableUdpPacket, UdpPacket},
    Packet,
};

use crate::client::ClientInfo;
use crate::proto;
use crate::Masscanned;

pub fn repl<'a, 'b>(
    udp_req: &'a UdpPacket,
    masscanned: &Masscanned,
    mut client_info: &mut ClientInfo,
) -> Option<MutableUdpPacket<'b>> {
    masscanned.log.udp_recv(udp_req, client_info);
    /* Fill client info with source and dest. UDP port */
    client_info.port.src = Some(udp_req.get_source());
    client_info.port.dst = Some(udp_req.get_destination());
    let payload = udp_req.payload();
    let mut udp_repl;
    if let Some(repl) = proto::repl(&payload, masscanned, &mut client_info, None) {
        udp_repl = MutableUdpPacket::owned(
            [vec![0; MutableUdpPacket::minimum_packet_size()], repl].concat(),
        )
        .expect("error constructing a UDP packet");
        udp_repl.set_length(udp_repl.packet().len() as u16);
    } else {
        masscanned.log.udp_drop(udp_req, client_info);
        return None;
    }
    /* Set source and dest. port for response packet from client info */
    /* Note: client info could have been modified by upper layers (e.g., STUN) */
    udp_repl.set_source(client_info.port.dst.unwrap());
    udp_repl.set_destination(client_info.port.src.unwrap());
    masscanned.log.udp_send(&udp_repl, client_info);
    Some(udp_repl)
}
