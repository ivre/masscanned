use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use log::*;
use pcap_file::pcap::{PcapPacket, PcapReader};
use pnet::packet::{
    ethernet::{EtherTypes, EthernetPacket},
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    Packet,
};

/* Generic IP packet (either IPv4 or IPv6) */
pub enum IpPacket<'a> {
    V4(Ipv4Packet<'a>),
    V6(Ipv6Packet<'a>),
}

/* Get source or dest. IP address from a packet (IPv4 or IPv6) */
impl<'a> IpPacket<'a> {
    // Macro ?
    pub fn src(&self) -> IpAddr {
        match self {
            IpPacket::V4(p) => IpAddr::V4(p.get_source()),
            IpPacket::V6(p) => IpAddr::V6(p.get_source()),
        }
    }
    pub fn dst(&self) -> IpAddr {
        match self {
            IpPacket::V4(p) => IpAddr::V4(p.get_destination()),
            IpPacket::V6(p) => IpAddr::V6(p.get_destination()),
        }
    }
}

pub trait IpAddrParser {
    fn extract_ip_addresses_with_count(
        self,
        blacklist: Option<HashSet<IpAddr>>,
    ) -> HashMap<IpAddr, u32>;
    fn extract_ip_addresses_only(self, blacklist: Option<HashSet<IpAddr>>) -> HashSet<IpAddr>;
}

/* Parse IP addresses from a text file */
impl IpAddrParser for File {
    fn extract_ip_addresses_with_count(
        self,
        blacklist: Option<HashSet<IpAddr>>,
    ) -> HashMap<IpAddr, u32> {
        let mut ip_addresses = HashMap::new();
        let buf = BufReader::new(self);
        for (i, line) in buf.lines().enumerate() {
            let entry: Vec<&str> = match &line {
                Ok(l) => l.split('\t').collect(),
                Err(e) => {
                    warn!("cannot read line {} - {}", i, e);
                    continue;
                }
            };
            /* Should never occur */
            if entry.is_empty() {
                warn!("cannot parse line: {}", line.expect("error reading line"));
                continue;
            }
            let ip: IpAddr;
            if let Ok(val) = entry[0].parse::<Ipv4Addr>() {
                ip = IpAddr::V4(val);
            } else if let Ok(val) = entry[0].parse::<Ipv6Addr>() {
                ip = IpAddr::V6(val);
            } else {
                warn!(
                    "cannot parse IP address from line: {}",
                    line.expect("error reading line")
                );
                continue;
            }
            if let Some(ref b) = blacklist {
                if b.contains(&ip) {
                    info!("[blacklist] ignoring {}", &ip);
                    continue;
                }
            }
            let ip_entry = ip_addresses.entry(ip).or_insert(0);
            if entry.len() < 2 {
                continue;
            }
            if let Ok(count) = entry[1].parse::<u32>() {
                *ip_entry += count;
            }
        }
        ip_addresses
    }

    fn extract_ip_addresses_only(self, blacklist: Option<HashSet<IpAddr>>) -> HashSet<IpAddr> {
        let mut ip_addresses = HashSet::new();
        let buf = BufReader::new(self);
        for (i, line) in buf.lines().enumerate() {
            let entry: Vec<&str> = match &line {
                Ok(l) => l.split('\t').collect(),
                Err(e) => {
                    warn!("cannot read line {} - {}", i, e);
                    continue;
                }
            };
            /* Should never occur */
            if entry.is_empty() {
                warn!("cannot parse line: {}", line.expect("error reading line"));
                continue;
            }
            let ip: IpAddr;
            if let Ok(val) = entry[0].parse::<Ipv4Addr>() {
                ip = IpAddr::V4(val);
            } else if let Ok(val) = entry[0].parse::<Ipv6Addr>() {
                ip = IpAddr::V6(val);
            } else {
                warn!(
                    "cannot parse IP address from line: {}",
                    line.expect("error reading line")
                );
                continue;
            }
            if let Some(ref b) = blacklist {
                if b.contains(&ip) {
                    info!("[blacklist] ignoring {}", &ip);
                    continue;
                }
            }
            ip_addresses.insert(ip);
        }
        ip_addresses
    }
}

/* Parse IP addresses from a comma-separated list in a string */
impl IpAddrParser for &str {
    fn extract_ip_addresses_with_count(
        self,
        _blacklist: Option<HashSet<IpAddr>>,
    ) -> HashMap<IpAddr, u32> {
        panic!("not implemented");
    }

    fn extract_ip_addresses_only(self, blacklist: Option<HashSet<IpAddr>>) -> HashSet<IpAddr> {
        let mut ip_addresses = HashSet::new();
        for line in self.split(",") {
            /* Should never occur */
            if line.is_empty() {
                warn!("cannot parse line: {}", line);
                continue;
            }
            let ip: IpAddr;
            if let Ok(val) = line.parse::<Ipv4Addr>() {
                ip = IpAddr::V4(val);
            } else if let Ok(val) = line.parse::<Ipv6Addr>() {
                ip = IpAddr::V6(val);
            } else {
                warn!("cannot parse IP address from line: {}", line);
                continue;
            }
            if let Some(ref b) = blacklist {
                if b.contains(&ip) {
                    info!("[blacklist] ignoring {}", &ip);
                    continue;
                }
            }
            ip_addresses.insert(ip);
        }
        ip_addresses
    }
}
/* Get the IP address of source and dest. from an IP packet.
 * works with both IPv4 and IPv6 packets/addresses */
fn extract_ip(pkt: PcapPacket) -> Option<(IpAddr, IpAddr)> {
    let eth = EthernetPacket::new(&pkt.data).expect("error parsing Ethernet packet");
    let payload = eth.payload();
    let ip = match eth.get_ethertype() {
        EtherTypes::Ipv4 => match Ipv4Packet::new(payload) {
            Some(p) => IpPacket::V4(p),
            None => {
                warn!("error parsing IPv4 packet - {:?}", pkt);
                return None;
            }
        },
        EtherTypes::Ipv6 => match Ipv6Packet::new(payload) {
            Some(p) => IpPacket::V6(p),
            None => {
                warn!("error parsing IPv6 packet - {:?}", pkt);
                return None;
            }
        },
        EtherTypes::Arp => {
            return None;
        }
        t => {
            warn!("unknown layer 2: {}", t);
            return None;
        }
    };
    Some((ip.src(), ip.dst()))
}

impl IpAddrParser for PcapReader<std::fs::File> {
    /* Extract IP addresses (v4 and v6) from a capture and count occurrences of
     * each. */
    fn extract_ip_addresses_with_count(
        mut self: PcapReader<std::fs::File>,
        blacklist: Option<HashSet<IpAddr>>,
    ) -> HashMap<IpAddr, u32> {
        let mut ip_addresses = HashMap::new();
        // pcap.map(fn) , map_Ok
        // .iter, into_iter
        while let Some(pkt) = self.next_packet() {
            match pkt {
                Ok(pkt) => {
                    // map_Some map_None
                    if let Some((s, d)) = extract_ip(pkt) {
                        match blacklist {
                            Some(ref b) if b.contains(&s) => {
                                info!("[blacklist] ignoring {}", &s);
                            }
                            _ => {
                                let ip = ip_addresses.entry(s).or_insert(0);
                                *ip += 1;
                            }
                        }
                        match blacklist {
                            Some(ref b) if b.contains(&d) => {
                                info!("[blacklist] ignoring {}", &d);
                            }
                            _ => {
                                let ip = ip_addresses.entry(d).or_insert(0);
                                *ip += 1;
                            }
                        }
                    };
                }
                Err(e) => {
                    warn!("error reading packet - {}", e);
                    continue;
                }
            }
        }
        ip_addresses
    }
    fn extract_ip_addresses_only(
        mut self: PcapReader<std::fs::File>,
        blacklist: Option<HashSet<IpAddr>>,
    ) -> HashSet<IpAddr> {
        let mut ip_addresses = HashSet::new();
        // pcap.map(fn) , map_Ok
        // .iter, into_iter
        while let Some(pkt) = self.next_packet() {
            match pkt {
                Ok(pkt) => {
                    // map_Some map_None
                    if let Some((s, d)) = extract_ip(pkt) {
                        match blacklist {
                            Some(ref b) if b.contains(&s) => {
                                info!("[blacklist] ignoring {}", &s);
                            }
                            _ => {
                                ip_addresses.insert(s);
                            }
                        }
                        match blacklist {
                            Some(ref b) if b.contains(&d) => {
                                info!("[blacklist] ignoring {}", &d);
                            }
                            _ => {
                                ip_addresses.insert(d);
                            }
                        }
                    };
                }
                Err(e) => {
                    warn!("error reading packet - {}", e);
                    continue;
                }
            }
        }
        ip_addresses
    }
}
