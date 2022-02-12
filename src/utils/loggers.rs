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

use std::time::SystemTime;

use pnet::packet::{
    arp::{ArpPacket, MutableArpPacket},
    ethernet::{EthernetPacket, MutableEthernetPacket},
};

use crate::client::ClientInfo;

pub trait Logger {
    fn init(&self);
    /* list of notifications that a logger might or might not implement */
    /* ARP */
    fn arp_enabled(&self) -> bool {
        true
    }
    fn arp_recv(&self, _p: &ArpPacket) {}
    fn arp_drop(&self, _p: &ArpPacket) {}
    fn arp_send(&self, _p: &MutableArpPacket) {}
    /* Ethernet */
    fn eth_enabled(&self) -> bool {
        true
    }
    fn eth_recv(&self, _p: &EthernetPacket, _c: &ClientInfo) {}
    fn eth_drop(&self, _p: &EthernetPacket, _c: &ClientInfo) {}
    fn eth_send(&self, _p: &MutableEthernetPacket, _c: &ClientInfo) {}
}

pub struct ConsoleLogger {
    arp: bool,
    eth: bool,
}

impl ConsoleLogger {
    pub fn new() -> Self {
        ConsoleLogger {
            arp: true,
            eth: true,
        }
    }
    fn prolog(&self, proto: &str, verb: &str, crlf: bool) {
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
        print!("{}.{}\t{}\t{}{}",
            now.as_secs(),
            now.subsec_millis(),
            proto,
            verb,
            if crlf { "\n" } else { "\t" },
          );
    }
}

impl Logger for ConsoleLogger {
    fn init(&self) {
        self.prolog("arp", "init", true);
        self.prolog("eth", "init", true);
    }
    fn arp_enabled(&self) -> bool {
        self.arp
    }
    fn eth_enabled(&self) -> bool {
        self.eth
    }
    fn arp_recv(&self, p: &ArpPacket) {
        self.prolog("arp", "recv", false);
        println!(
            "{:?}\t{:}\t{:}\t{:}\t{:}",
            p.get_operation(),
            p.get_sender_hw_addr(),
            p.get_sender_proto_addr(),
            p.get_target_hw_addr(),
            p.get_target_proto_addr(),
        );
    }
    fn arp_send(&self, p: &MutableArpPacket) {
        self.prolog("arp", "send", false);
        println!(
            "{:?}\t{:}\t{:}\t{:}\t{:}",
            p.get_operation(),
            p.get_target_hw_addr(),
            p.get_target_proto_addr(),
            p.get_sender_hw_addr(),
            p.get_sender_proto_addr(),
        );
    }
    fn arp_drop(&self, p: &ArpPacket) {
        self.prolog("arp", "drop", false);
        println!(
            "{:?}\t{:}\t{:}\t{:}\t{:}",
            p.get_operation(),
            p.get_target_hw_addr(),
            p.get_target_proto_addr(),
            p.get_sender_hw_addr(),
            p.get_sender_proto_addr(),
        );
    }
    fn eth_recv(&self, p: &EthernetPacket, _c: &ClientInfo) {
        self.prolog("eth", "recv", false);
        println!(
            "{:}\t{:}\t{:}",
            p.get_ethertype(),
            p.get_source(),
            p.get_destination(),
        );
    }
    fn eth_drop(&self, p: &EthernetPacket, _c: &ClientInfo) {
        self.prolog("eth", "drop", false);
        println!(
            "{:}\t{:}\t{:}",
            p.get_ethertype(),
            p.get_source(),
            p.get_destination(),
        );
    }
    fn eth_send(&self, p: &MutableEthernetPacket, _c: &ClientInfo) {
        self.prolog("eth", "send", false);
        println!(
            "{:}\t{:}\t{:}",
            p.get_ethertype(),
            p.get_destination(),
            p.get_source(),
        );
    }
}

pub struct MetaLogger {
    loggers: Vec<Box<dyn Logger>>,
}

impl MetaLogger {
    pub fn new() -> Self {
        MetaLogger {
            loggers: Vec::new(),
        }
    }
    pub fn add(&mut self, log: Box<dyn Logger>) {
        self.loggers.push(log);
    }
    pub fn init(&self) {
        for l in &self.loggers {
            l.init();
        }
    }
    pub fn arp_recv(&self, p: &ArpPacket) {
        for l in &self.loggers {
            if l.arp_enabled() {
                l.arp_recv(p);
            }
        }
    }
    pub fn arp_drop(&self, p: &ArpPacket) {
        for l in &self.loggers {
            if l.arp_enabled() {
                l.arp_drop(p);
            }
        }
    }
    pub fn arp_send(&self, p: &MutableArpPacket) {
        for l in &self.loggers {
            if l.arp_enabled() {
                l.arp_send(p);
            }
        }
    }
    pub fn eth_recv(&self, p: &EthernetPacket, c: &ClientInfo) {
        for l in &self.loggers {
            if l.eth_enabled() {
                l.eth_recv(p, c);
            }
        }
    }
    pub fn eth_drop(&self, p: &EthernetPacket, c: &ClientInfo) {
        for l in &self.loggers {
            if l.eth_enabled() {
                l.eth_drop(p, c);
            }
        }
    }
    pub fn eth_send(&self, p: &MutableEthernetPacket, c: &ClientInfo) {
        for l in &self.loggers {
            if l.eth_enabled() {
                l.eth_send(p, c);
            }
        }
    }
}
