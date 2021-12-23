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
    fn arp_recv_whohas(&self, _p: &ArpPacket) {}
    fn arp_drop(&self, _p: &ArpPacket) {}
    fn arp_send(&self, _p: &MutableArpPacket) {}
    fn arp_send_isat(&self, _p: &MutableArpPacket) {}
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
    _eth: bool,
}

impl ConsoleLogger {
    pub fn new() -> Self {
        ConsoleLogger {
            arp: true,
            _eth: false,
        }
    }
}

impl Logger for ConsoleLogger {
    fn init(&self) {
        println!("arp::init");
    }
    fn arp_enabled(&self) -> bool {
        self.arp
    }
    fn eth_enabled(&self) -> bool {
        self.arp
    }
    fn arp_recv_whohas(&self, p: &ArpPacket) {
        println!(
            "arp::recv\twho-has\t{:}\t{:}\t{:}",
            p.get_sender_hw_addr(),
            p.get_target_hw_addr(),
            p.get_target_proto_addr()
        );
    }
    fn arp_send_isat(&self, p: &MutableArpPacket) {
        println!(
            "arp::send\tis-at\t{:}\t{:}\t{:}\t{:}",
            p.get_sender_hw_addr(),
            p.get_sender_proto_addr(),
            p.get_target_hw_addr(),
            p.get_target_proto_addr()
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
    pub fn arp_recv_whohas(&self, p: &ArpPacket) {
        for l in &self.loggers {
            if l.arp_enabled() {
                l.arp_recv_whohas(p);
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
    pub fn arp_send_isat(&self, p: &MutableArpPacket) {
        for l in &self.loggers {
            if l.arp_enabled() {
                l.arp_send_isat(p);
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
