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

#[macro_use]
extern crate bitflags;
extern crate lazy_static;

use std::boxed::Box;
use std::collections::HashSet;
use std::fs::File;
use std::net::IpAddr;
use std::str::FromStr;

use clap::{App, Arg};
use log::*;
use pnet::{
    datalink::{self, Channel::Ethernet, DataLinkReceiver, DataLinkSender, NetworkInterface},
    packet::{
        ethernet::{EthernetPacket, MutableEthernetPacket},
        Packet,
    },
    util::MacAddr,
};

use crate::logger::{ConsoleLogger, MetaLogger};
use crate::utils::IpAddrParser;

mod client;
mod layer_2;
mod layer_3;
mod layer_4;
mod logger;
mod proto;
mod smack;
mod synackcookie;
mod utils;

const VERSION: &str = "0.2.0";
const DEFAULT_MAC_ADDR: &str = "c0:ff:ee:c0:ff:ee";

pub struct Masscanned<'a> {
    pub synack_key: [u64; 2],
    pub mac: MacAddr,
    /* iface is an Option to make tests easier */
    pub iface: Option<&'a NetworkInterface>,
    pub ip_addresses: Option<&'a HashSet<IpAddr>>,
    /* loggers */
    pub log: MetaLogger,
}

/* Get the L2 network interface from its name */
// TODO testme
// TODO handle errors
fn get_interface(iface_name: &str) -> Option<NetworkInterface> {
    let interface_names_match = |iface: &NetworkInterface| iface.name == iface_name;
    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    interfaces.into_iter().find(interface_names_match)
}

/* Get two L2 channels:
 * - one to send data
 * - one to receive data
 */
// TODO testme
// TODO handle errors
fn get_channel(
    interface: &NetworkInterface,
) -> (
    Box<(dyn DataLinkSender + 'static)>,
    Box<(dyn DataLinkReceiver + 'static)>,
) {
    // Create a new channel, dealing with layer 2 packets
    match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    }
}

fn reply<'a, 'b>(packet: &'a [u8], masscanned: &Masscanned) -> Option<MutableEthernetPacket<'b>> {
    let mut client_info = client::ClientInfo::new();
    let eth_req = EthernetPacket::new(packet).expect("impossible to parse Ethernet packet");
    layer_2::reply(&eth_req, masscanned, &mut client_info)
}

fn main() {
    /* parse arguments from CLI */
    let args = App::new("Network responder - answer them all")
        .version(VERSION)
        .about("Network answering machine for various network protocols (L2-L3-L4 + applications)")
        .arg(
            Arg::new("interface")
                .short('i')
                .long("iface")
                .value_name("iface")
                .help("the interface to use for receiving/sending packets")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::new("mac")
                .short('a')
                .long("mac-addr")
                .help("MAC address to use in the response packets")
                .takes_value(true),
        )
        .arg(
            Arg::new("ip")
                .short('f')
                .long("ip-addr-file")
                .help("File with the list of IP addresses to impersonate")
                .takes_value(true),
        )
        .arg(
            Arg::new("verbosity")
                .short('v')
                .multiple_occurrences(true)
                .help("Increase message verbosity"),
        )
        .get_matches();
    let verbose = args.occurrences_of("verbosity") as usize;
    /* initialise logger */
    stderrlog::new()
        .module(module_path!())
        .verbosity(verbose)
        .init()
        .expect("error while initializing logging module");
    warn!("warn messages enabled");
    info!("info messages enabled");
    debug!("debug messages enabled");
    trace!("trace messages enabled");
    info!("Command line arguments:");
    let iface = if let Some(i) = get_interface(
        args.value_of("interface")
            .expect("error parsing iface argument"),
    ) {
        i
    } else {
        error!(
            "Cannot open interface \"{}\" - are you sure it exists?",
            args.value_of("interface")
                .expect("error parsing iface argument")
        );
        return;
    };
    if iface.flags & (netdevice::IFF_UP.bits() as u32) == 0 {
        error!("specified interface is DOWN");
        return;
    }
    let mac = if let Some(m) = args.value_of("mac") {
        MacAddr::from_str(m).expect("error parsing provided MAC address")
    } else if let Some(m) = iface.mac {
        m
    } else {
        MacAddr::from_str(DEFAULT_MAC_ADDR).expect("error parsing default MAC address")
    };
    /* Parse ip address file specified */
    /* FIXME: .and_then(|path| File::open(path).map(|file| )).unwrap_or_default() ? */
    let ip_list = if let Some(ref path) = args.value_of("ip") {
        if let Ok(file) = File::open(path) {
            info!("parsing ip address file: {}", &path);
            file.extract_ip_addresses_only(None)
        } else {
            HashSet::new()
        }
    } else {
        HashSet::new()
    };
    let ip_addresses = if !ip_list.is_empty() {
        Some(&ip_list)
    } else {
        None
    };
    let mut masscanned = Masscanned {
        synack_key: [0, 0],
        mac,
        iface: Some(&iface),
        ip_addresses,
        log: MetaLogger::new(),
    };
    info!("interface......{}", masscanned.iface.unwrap().name);
    info!("mac address....{}", masscanned.mac);
    masscanned.log.add(Box::new(ConsoleLogger::new()));
    masscanned.log.init();
    let (mut tx, mut rx) = get_channel(masscanned.iface.unwrap());
    loop {
        /* check if network interface is still up */
        if masscanned.iface.unwrap().flags & (netdevice::IFF_UP.bits() as u32) == 0 {
            error!("interface is DOWN - aborting");
            break;
        }
        match rx.next() {
            Ok(packet) => {
                if let Some(pkt_rep) = reply(packet, &masscanned) {
                    tx.send_to(pkt_rep.packet(), None);
                } else {
                    info!("packet not handled: {:?}", packet);
                }
            }
            Err(e) => {
                error!("An error occurred while reading: {}", e);
            }
        }
    }
}
