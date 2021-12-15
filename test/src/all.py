# This file is part of masscanned.
# Copyright 2021 - The IVRE project
#
# Masscanned is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Masscanned is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
# License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Masscanned. If not, see <http://www.gnu.org/licenses/>.

import logging
from socket import AF_INET6
import struct
import zlib

from scapy.compat import raw
from scapy.data import ETHER_BROADCAST
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import (
    ICMPv6EchoReply,
    ICMPv6EchoRequest,
    ICMPv6ND_NA,
    ICMPv6ND_NS,
    ICMPv6NDOptDstLLAddr,
    IPv6,
)
from scapy.layers.l2 import ARP, Ether
from scapy.pton_ntop import inet_pton
from scapy.packet import Raw
from scapy.volatile import RandInt

from .conf import IPV4_ADDR, IPV6_ADDR, MAC_ADDR


def setup_logs():
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(levelname)s\t%(message)s"))
    ch.setLevel(logging.DEBUG)
    log = logging.getLogger(__name__)
    log.setLevel(logging.DEBUG)
    log.addHandler(ch)
    return log


LOG = setup_logs()
TESTS = []
ERRORS = []


# decorator to automatically add a function to tests
def test(f):
    global ERRORS, TESTS
    OK = "\033[1mOK\033[0m"
    KO = "\033[1m\033[1;%dmKO\033[0m" % 31
    fname = f.__name__.ljust(50, ".")

    def w(iface):
        try:
            f(iface)
            LOG.info("{}{}".format(fname, OK))
        except AssertionError as e:
            LOG.error("{}{}: {}".format(fname, KO, e))
            ERRORS.append(fname)

    TESTS.append(w)
    return w


def multicast(ip6):
    a, b = ip6.split(":")[-2:]
    mac = ["33", "33", "ff"]
    if len(a) == 4:
        mac.append(a[2:])
    else:
        mac.append("00")
    if len(b) >= 2:
        mac.append(b[:2])
    else:
        mac.append("00")
    if len(b) >= 4:
        mac.append(b[2:])
    else:
        mac.append("00")
    return ":".join(mac)


def check_ip_checksum(pkt):
    assert IP in pkt, "no IP layer found"
    ip_pkt = pkt[IP]
    chksum = ip_pkt.chksum
    del ip_pkt.chksum
    assert IP(raw(ip_pkt)).chksum == chksum, "bad IPv4 checksum"


def check_ipv6_checksum(pkt):
    assert IPv6 in pkt, "no IP layer found"
    ip_pkt = pkt[IPv6]
    chksum = ip_pkt.chksum
    del ip_pkt.chksum
    assert IPv6(raw(ip_pkt)).chksum == chksum, "bad IPv6 checksum"


@test
def test_arp_req(iface):
    ##### ARP #####
    arp_req = Ether(dst=ETHER_BROADCAST) / ARP(pdst=IPV4_ADDR)
    arp_repl = iface.sr1(arp_req, timeout=1)
    assert arp_repl is not None, "expecting answer, got nothing"
    assert ARP in arp_repl, "no ARP layer found"
    arp_repl = arp_repl[ARP]
    # check answer
    ## op is "is-at"
    assert arp_repl.op == 2, "unexpected ARP op: {}".format(arp_repl.op)
    ## answer for the requested IP
    assert arp_repl.psrc == arp_req.pdst, "unexpected ARP psrc: {}".format(
        arp_repl.psrc
    )
    assert arp_repl.pdst == arp_req.psrc, "unexpected ARP pdst: {}".format(
        arp_repl.pdst
    )
    ## answer is expected MAC address
    assert arp_repl.hwsrc == MAC_ADDR, "unexpected ARP hwsrc: {}".format(arp_repl.hwsrc)


@test
def test_arp_req_other_ip(iface):
    ##### ARP #####
    arp_req = Ether(dst=ETHER_BROADCAST) / ARP(pdst="1.2.3.4")
    arp_repl = iface.sr1(arp_req, timeout=1)
    assert arp_repl is None, "responding to ARP requests for other IP addresses"


@test
def test_ipv4_req(iface):
    ##### IP #####
    ip_req = Ether(dst=MAC_ADDR) / IP(dst=IPV4_ADDR, id=0x1337) / ICMP(type=8, code=0)
    ip_repl = iface.sr1(ip_req, timeout=1)
    assert ip_repl is not None, "expecting answer, got nothing"
    check_ip_checksum(ip_repl)
    assert IP in ip_repl, "no IP layer in response"
    ip_repl = ip_repl[IP]
    assert ip_repl.id == 0, "IP identification unexpected"


@test
def test_eth_req_other_mac(iface):
    #### ETH ####
    ip_req = Ether(dst="00:00:00:11:11:11") / IP(dst=IPV4_ADDR) / ICMP(type=8, code=0)
    ip_repl = iface.sr1(ip_req, timeout=1)
    assert ip_repl is None, "responding to other MAC addresses"


@test
def test_ipv4_req_other_ip(iface):
    ##### IP #####
    ip_req = Ether(dst=MAC_ADDR) / IP(dst="1.2.3.4") / ICMP(type=8, code=0)
    ip_repl = iface.sr1(ip_req, timeout=1)
    assert ip_repl is None, "responding to other IP addresses"


@test
def test_icmpv4_echo_req(iface):
    ##### ICMPv4 #####
    icmp_req = (
        Ether(dst=MAC_ADDR)
        / IP(dst=IPV4_ADDR)
        / ICMP(type=8, code=0)
        / Raw("idrinkwaytoomuchcoffee")
    )
    icmp_repl = iface.sr1(icmp_req, timeout=1)
    assert icmp_repl is not None, "expecting answer, got nothing"
    check_ip_checksum(icmp_repl)
    assert ICMP in icmp_repl
    icmp_repl = icmp_repl[ICMP]
    # check answer
    ## type is "echo-reply"
    assert icmp_repl.type == 0
    assert icmp_repl.code == 0
    ## data is the same as sent
    assert icmp_repl.load == icmp_req.load


@test
def test_icmpv6_neighbor_solicitation(iface):
    ##### IPv6 Neighbor Solicitation #####
    for mac in [
        "ff:ff:ff:ff:ff:ff",
        "33:33:00:00:00:01",
        MAC_ADDR,
        multicast(IPV6_ADDR),
    ]:
        nd_ns = Ether(dst=mac) / IPv6() / ICMPv6ND_NS(tgt=IPV6_ADDR)
        nd_na = iface.sr1(nd_ns, timeout=1)
        assert nd_na is not None, "expecting answer, got nothing"
        assert ICMPv6ND_NA in nd_na
        nd_na = nd_na[ICMPv6ND_NA]
        # check answer content
        assert nd_na.code == 0
        assert nd_na.R == 0
        assert nd_na.S == 1
        assert nd_na.O == 1  # noqa: E741
        assert nd_na.tgt == IPV6_ADDR
        # check ND Option
        assert nd_na.haslayer(ICMPv6NDOptDstLLAddr)
        assert nd_na.getlayer(ICMPv6NDOptDstLLAddr).lladdr == MAC_ADDR
    for mac in ["00:00:00:00:00:00", "33:33:33:00:00:01"]:
        nd_ns = Ether(dst="ff:ff:ff:ff:ff:ff") / IPv6() / ICMPv6ND_NS(tgt=IPV6_ADDR)
        nd_na = iface.sr1(nd_ns, timeout=1)
        assert nd_na is not None, "expecting no answer, got one"


@test
def test_icmpv6_neighbor_solicitation_other_ip(iface):
    ##### IPv6 Neighbor Solicitation #####
    nd_ns = (
        Ether(dst="ff:ff:ff:ff:ff:ff")
        / IPv6()
        / ICMPv6ND_NS(tgt="2020:4141:3030:2020::bdbd")
    )
    nd_na = iface.sr1(nd_ns, timeout=1)
    assert nd_na is None, "responding to ND_NS for other IP addresses"


@test
def test_icmpv6_echo_req(iface):
    ##### IPv6 Ping #####
    echo_req = (
        Ether(dst=MAC_ADDR)
        / IPv6(dst=IPV6_ADDR)
        / ICMPv6EchoRequest(data="waytoomanynapkins")
    )
    echo_repl = iface.sr1(echo_req, timeout=1)
    assert echo_repl is not None, "expecting answer, got nothing"
    assert ICMPv6EchoReply in echo_repl
    echo_repl = echo_repl[ICMPv6EchoReply]
    # check answer content
    assert echo_repl.code == 0
    assert echo_repl.data == echo_req.data


@test
def test_tcp_syn(iface):
    ##### SYN-ACK #####
    # test a list of ports, randomly generated once
    ports_to_test = [
        1152,
        2003,
        2193,
        3709,
        4054,
        6605,
        6737,
        6875,
        7320,
        8898,
        9513,
        9738,
        10623,
        10723,
        11253,
        12125,
        12189,
        12873,
        14648,
        14659,
        16242,
        16243,
        17209,
        17492,
        17667,
        17838,
        18081,
        18682,
        18790,
        19124,
        19288,
        19558,
        19628,
        19789,
        20093,
        21014,
        21459,
        21740,
        24070,
        24312,
        24576,
        26939,
        27136,
        27165,
        27361,
        29971,
        31088,
        33011,
        33068,
        34990,
        35093,
        35958,
        36626,
        36789,
        37130,
        37238,
        37256,
        37697,
        37890,
        38958,
        42131,
        43864,
        44420,
        44655,
        44868,
        45157,
        46213,
        46497,
        46955,
        49049,
        49067,
        49452,
        49480,
        50498,
        50945,
        51181,
        52890,
        53301,
        53407,
        53417,
        53980,
        55827,
        56483,
        58552,
        58713,
        58836,
        59362,
        59560,
        60534,
        60555,
        60660,
        61615,
        62402,
        62533,
        62941,
        63240,
        63339,
        63616,
        64380,
        65438,
    ]
    for p in ports_to_test:
        seq_init = int(RandInt())
        syn = (
            Ether(dst=MAC_ADDR)
            / IP(dst=IPV4_ADDR)
            / TCP(flags="S", dport=p, seq=seq_init)
        )
        syn_ack = iface.sr1(syn, timeout=1)
        assert syn_ack is not None, "expecting answer, got nothing"
        check_ip_checksum(syn_ack)
        assert TCP in syn_ack, "expecting TCP, got %r" % syn_ack.summary()
        syn_ack = syn_ack[TCP]
        assert syn_ack.flags == "SA", "expecting TCP SA, got %r" % syn_ack.flags
        assert syn_ack.ack == seq_init + 1, "wrong TCP ack value (%r != %r)" % (
            syn_ack.ack,
            seq_init + 1,
        )


@test
def test_ipv4_tcp_psh_ack(iface):
    ##### PSH-ACK #####
    sport = 26695
    port = 445
    seq_init = int(RandInt())
    # send PSH-ACK first
    psh_ack = (
        Ether(dst=MAC_ADDR)
        / IP(dst=IPV4_ADDR)
        / TCP(flags="PA", sport=sport, dport=port, seq=seq_init)
        / Raw("payload")
    )
    syn_ack = iface.sr1(psh_ack, timeout=1)
    assert syn_ack is None, "no answer expected, got one"
    # test the anti-injection mechanism
    seq_init = int(RandInt())
    syn = (
        Ether(dst=MAC_ADDR)
        / IP(dst=IPV4_ADDR)
        / TCP(flags="S", sport=sport, dport=port, seq=seq_init)
    )
    syn_ack = iface.sr1(syn, timeout=1)
    assert syn_ack is not None, "expecting answer, got nothing"
    check_ip_checksum(syn_ack)
    assert TCP in syn_ack, "expecting TCP, got %r" % syn_ack.summary()
    syn_ack = syn_ack[TCP]
    assert syn_ack.flags == "SA", "expecting TCP SA, got %r" % syn_ack.flags
    assert syn_ack.ack == seq_init + 1, "wrong TCP ack value (%r != %r)" % (
        syn_ack.ack,
        seq_init + 1,
    )
    ack = Ether(dst=MAC_ADDR) / IP(dst=IPV4_ADDR) / TCP(flags="A", dport=port)
    # should fail because no ack given
    psh_ack = (
        Ether(dst=MAC_ADDR)
        / IP(dst=IPV4_ADDR)
        / TCP(flags="PA", sport=sport, dport=port, ack=0, seq=seq_init + 1)
    )
    ack = iface.sr1(psh_ack, timeout=1)
    assert ack is None, "no answer expected, got one"
    # should get an answer this time
    psh_ack = (
        Ether(dst=MAC_ADDR)
        / IP(dst=IPV4_ADDR)
        / TCP(
            flags="PA", sport=sport, dport=port, ack=syn_ack.seq + 1, seq=seq_init + 1
        )
    )
    ack = iface.sr1(psh_ack, timeout=1)
    assert ack is not None, "expecting answer, got nothing"
    check_ip_checksum(ack)
    assert TCP in ack, "expecting TCP, got %r" % ack.summary()
    ack = ack[TCP]
    assert ack.flags == "A", "expecting TCP A, got %r" % syn_ack.flags


@test
def test_ipv6_tcp_psh_ack(iface):
    ##### PSH-ACK #####
    sport = 26695
    port = 445
    seq_init = int(RandInt())
    # send PSH-ACK first
    psh_ack = (
        Ether(dst=MAC_ADDR)
        / IPv6(dst=IPV6_ADDR)
        / TCP(flags="PA", sport=sport, dport=port, seq=seq_init)
        / Raw("payload")
    )
    syn_ack = iface.sr1(psh_ack, timeout=1)
    assert syn_ack is None, "no answer expected, got one"
    # test the anti-injection mechanism
    syn = (
        Ether(dst=MAC_ADDR)
        / IPv6(dst=IPV6_ADDR)
        / TCP(flags="S", sport=sport, dport=port, seq=seq_init)
    )
    syn_ack = iface.sr1(syn, timeout=1)
    assert syn_ack is not None, "expecting answer, got nothing"
    check_ipv6_checksum(syn_ack)
    assert TCP in syn_ack, "expecting TCP, got %r" % syn_ack.summary()
    syn_ack = syn_ack[TCP]
    assert syn_ack.flags == "SA", "expecting TCP SA, got %r" % syn_ack.flags
    assert syn_ack.ack == seq_init + 1, "wrong TCP ack value (%r != %r)" % (
        syn_ack.ack,
        seq_init + 1,
    )
    ack = Ether(dst=MAC_ADDR) / IPv6(dst=IPV6_ADDR) / TCP(flags="A", dport=port)
    # should fail because no ack given
    psh_ack = (
        Ether(dst=MAC_ADDR)
        / IPv6(dst=IPV6_ADDR)
        / TCP(flags="PA", sport=sport, dport=port, ack=0, seq=seq_init + 1)
    )
    ack = iface.sr1(psh_ack, timeout=1)
    assert ack is None, "no answer expected, got one"
    # should get an answer this time
    psh_ack = (
        Ether(dst=MAC_ADDR)
        / IPv6(dst=IPV6_ADDR)
        / TCP(
            flags="PA", sport=sport, dport=port, ack=syn_ack.seq + 1, seq=seq_init + 1
        )
    )
    ack = iface.sr1(psh_ack, timeout=1)
    assert ack is not None, "expecting answer, got nothing"
    check_ipv6_checksum(ack)
    assert TCP in ack, "expecting TCP, got %r" % ack.summary()
    ack = ack[TCP]
    assert ack.flags == "A", "expecting TCP A, got %r" % syn_ack.flags


@test
def test_ipv4_tcp_http(iface):
    sport = 24592
    dports = [80, 443, 5000, 53228]
    for dport in dports:
        seq_init = int(RandInt())
        syn = (
            Ether(dst=MAC_ADDR)
            / IP(dst=IPV4_ADDR)
            / TCP(flags="S", sport=sport, dport=dport, seq=seq_init)
        )
        syn_ack = iface.sr1(syn, timeout=1)
        assert syn_ack is not None, "expecting answer, got nothing"
        check_ip_checksum(syn_ack)
        assert TCP in syn_ack, "expecting TCP, got %r" % syn_ack.summary()
        syn_ack = syn_ack[TCP]
        assert syn_ack.flags == "SA", "expecting TCP SA, got %r" % syn_ack.flags
        ack = (
            Ether(dst=MAC_ADDR)
            / IP(dst=IPV4_ADDR)
            / TCP(
                flags="A",
                sport=sport,
                dport=dport,
                seq=seq_init + 1,
                ack=syn_ack.seq + 1,
            )
        )
        _ = iface.sr1(ack, timeout=1)
        req = (
            Ether(dst=MAC_ADDR)
            / IP(dst=IPV4_ADDR)
            / TCP(
                flags="PA",
                sport=sport,
                dport=dport,
                seq=seq_init + 1,
                ack=syn_ack.seq + 1,
            )
            / Raw("GET / HTTP/1.1\r\n\r\n")
        )
        resp = iface.sr1(req, timeout=1)
        assert resp is not None, "expecting answer, got nothing"
        check_ip_checksum(resp)
        assert TCP in resp, "expecting TCP, got %r" % resp.summary()
        tcp = resp[TCP]
        assert tcp.payload.load.startswith(b"HTTP/1.1 401 Unauthorized\n")


@test
def test_ipv6_tcp_http(iface):
    sport = 24592
    dports = [80, 443, 5000, 53228]
    for dport in dports:
        seq_init = int(RandInt())
        syn = (
            Ether(dst=MAC_ADDR)
            / IPv6(dst=IPV6_ADDR)
            / TCP(flags="S", sport=sport, dport=dport, seq=seq_init)
        )
        syn_ack = iface.sr1(syn, timeout=1)
        assert syn_ack is not None, "expecting answer, got nothing"
        check_ipv6_checksum(syn_ack)
        assert TCP in syn_ack, "expecting TCP, got %r" % syn_ack.summary()
        syn_ack = syn_ack[TCP]
        assert syn_ack.flags == "SA"
        ack = (
            Ether(dst=MAC_ADDR)
            / IPv6(dst=IPV6_ADDR)
            / TCP(
                flags="A",
                sport=sport,
                dport=dport,
                seq=seq_init + 1,
                ack=syn_ack.seq + 1,
            )
        )
        _ = iface.sr1(ack, timeout=1)
        req = (
            Ether(dst=MAC_ADDR)
            / IPv6(dst=IPV6_ADDR)
            / TCP(
                flags="PA",
                sport=sport,
                dport=dport,
                seq=seq_init + 1,
                ack=syn_ack.seq + 1,
            )
            / Raw("GET / HTTP/1.1\r\n\r\n")
        )
        resp = iface.sr1(req, timeout=1)
        assert resp is not None, "expecting answer, got nothing"
        check_ipv6_checksum(resp)
        assert TCP in resp, "expecting TCP, got %r" % resp.summary()
        tcp = resp[TCP]
        assert tcp.payload.load.startswith(b"HTTP/1.1 401 Unauthorized\n")


@test
def test_ipv4_udp_http(iface):
    sport = 24592
    dports = [80, 443, 5000, 53228]
    for dport in dports:
        req = (
            Ether(dst=MAC_ADDR)
            / IP(dst=IPV4_ADDR)
            / UDP(sport=sport, dport=dport)
            / Raw("GET / HTTP/1.1\r\n\r\n")
        )
        resp = iface.sr1(req, timeout=1)
        assert resp is not None, "expecting answer, got nothing"
        check_ip_checksum(resp)
        assert UDP in resp
        udp = resp[UDP]
        assert udp.payload.load.startswith(b"HTTP/1.1 401 Unauthorized\n")


@test
def test_ipv6_udp_http(iface):
    sport = 24592
    dports = [80, 443, 5000, 53228]
    for dport in dports:
        req = (
            Ether(dst=MAC_ADDR)
            / IPv6(dst=IPV6_ADDR)
            / UDP(sport=sport, dport=dport)
            / Raw("GET / HTTP/1.1\r\n\r\n")
        )
        resp = iface.sr1(req, timeout=1)
        assert resp is not None, "expecting answer, got nothing"
        check_ipv6_checksum(resp)
        assert UDP in resp
        udp = resp[UDP]
        assert udp.payload.load.startswith(b"HTTP/1.1 401 Unauthorized\n")


@test
def test_ipv4_tcp_http_ko(iface):
    sport = 24592
    dports = [80, 443, 5000, 53228]
    for dport in dports:
        seq_init = int(RandInt())
        syn = (
            Ether(dst=MAC_ADDR)
            / IP(dst=IPV4_ADDR)
            / TCP(flags="S", sport=sport, dport=dport, seq=seq_init)
        )
        syn_ack = iface.sr1(syn, timeout=1)
        assert syn_ack is not None, "expecting answer, got nothing"
        check_ip_checksum(syn_ack)
        assert TCP in syn_ack, "expecting TCP, got %r" % syn_ack.summary()
        syn_ack = syn_ack[TCP]
        assert syn_ack.flags == "SA"
        ack = (
            Ether(dst=MAC_ADDR)
            / IP(dst=IPV4_ADDR)
            / TCP(
                flags="A",
                sport=sport,
                dport=dport,
                seq=seq_init + 1,
                ack=syn_ack.seq + 1,
            )
        )
        _ = iface.sr1(ack, timeout=1)
        req = (
            Ether(dst=MAC_ADDR)
            / IP(dst=IPV4_ADDR)
            / TCP(
                flags="PA",
                sport=sport,
                dport=dport,
                seq=seq_init + 1,
                ack=syn_ack.seq + 1,
            )
            / Raw(bytes.fromhex("4f5054494f4e53"))
        )
        resp = iface.sr1(req, timeout=1)
        assert resp is not None, "expecting answer, got nothing"
        check_ip_checksum(resp)
        assert TCP in resp, "expecting TCP, got %r" % resp.summary()
        assert "P" not in resp[TCP].flags
        assert len(resp[TCP].payload) == 0


@test
def test_ipv4_udp_http_ko(iface):
    sport = 24592
    dports = [80, 443, 5000, 53228]
    for dport in dports:
        req = (
            Ether(dst=MAC_ADDR)
            / IP(dst=IPV4_ADDR)
            / UDP(sport=sport, dport=dport)
            / Raw(bytes.fromhex("4f5054494f4e53"))
        )
        resp = iface.sr1(req, timeout=1)
        assert resp is None, "expecting no answer, got one"


@test
def test_ipv6_tcp_http_ko(iface):
    sport = 24592
    dports = [80, 443, 5000, 53228]
    for dport in dports:
        seq_init = int(RandInt())
        syn = (
            Ether(dst=MAC_ADDR)
            / IPv6(dst=IPV6_ADDR)
            / TCP(flags="S", sport=sport, dport=dport, seq=seq_init)
        )
        syn_ack = iface.sr1(syn, timeout=1)
        assert syn_ack is not None, "expecting answer, got nothing"
        check_ipv6_checksum(syn_ack)
        assert TCP in syn_ack, "expecting TCP, got %r" % syn_ack.summary()
        syn_ack = syn_ack[TCP]
        assert syn_ack.flags == "SA"
        ack = (
            Ether(dst=MAC_ADDR)
            / IPv6(dst=IPV6_ADDR)
            / TCP(
                flags="A",
                sport=sport,
                dport=dport,
                seq=seq_init + 1,
                ack=syn_ack.seq + 1,
            )
        )
        _ = iface.sr1(ack, timeout=1)
        req = (
            Ether(dst=MAC_ADDR)
            / IPv6(dst=IPV6_ADDR)
            / TCP(
                flags="PA",
                sport=sport,
                dport=dport,
                seq=seq_init + 1,
                ack=syn_ack.seq + 1,
            )
            / Raw(bytes.fromhex("4f5054494f4e53"))
        )
        resp = iface.sr1(req, timeout=1)
        assert resp is not None, "expecting answer, got nothing"
        check_ipv6_checksum(resp)
        assert TCP in resp, "expecting TCP, got %r" % resp.summary()
        assert "P" not in resp[TCP].flags
        assert len(resp[TCP].payload) == 0


@test
def test_ipv6_udp_http_ko(iface):
    sport = 24592
    dports = [80, 443, 5000, 53228]
    for dport in dports:
        req = (
            Ether(dst=MAC_ADDR)
            / IPv6(dst=IPV6_ADDR)
            / UDP(sport=sport, dport=dport)
            / Raw(bytes.fromhex("4f5054494f4e53"))
        )
        resp = iface.sr1(req, timeout=1)
        assert resp is None, "expecting no answer, got one"


@test
def test_ipv4_udp_stun(iface):
    sports = [12345, 55555, 80, 43273]
    dports = [80, 800, 8000, 3478]
    payload = bytes.fromhex("000100002112a442000000000000000000000000")
    for sport in sports:
        for dport in dports:
            req = (
                Ether(dst=MAC_ADDR)
                / IP(dst=IPV4_ADDR)
                / UDP(sport=sport, dport=dport)
                / Raw(payload)
            )
            resp = iface.sr1(req, timeout=1)
            assert resp is not None, "expecting answer, got nothing"
            check_ip_checksum(resp)
            assert UDP in resp, "no UDP layer found"
            udp = resp[UDP]
            assert udp.sport == dport, "unexpected UDP sport: {}".format(udp.sport)
            assert udp.dport == sport, "unexpected UDP dport: {}".format(udp.dport)
            resp_payload = udp.payload.load
            type_, length, magic = struct.unpack(">HHI", resp_payload[:8])
            tid = resp_payload[8:20]
            data = resp_payload[20:]
            assert type_ == 0x0101, "expected type 0X0101, got 0x{:04x}".format(type_)
            assert length == 12, "expected length 12, got {}".format(length)
            assert (
                magic == 0x2112A442
            ), "expected magic 0x2112a442, got 0x{:08x}".format(magic)
            assert (
                tid == b"\x00" * 12
            ), "expected tid 0x000000000000000000000000, got {:x}".format(tid)
            expected_data = b"\x00\x01\x00\x08\x00\x01" + struct.pack(
                ">HBBBB", sport, 192, 0, 0, 0
            )
            assert (
                data == expected_data
            ), f"unexpected data {data!r} != {expected_data!r}"


@test
def test_ipv6_udp_stun(iface):
    sports = [12345, 55555, 80, 43273]
    dports = [80, 800, 8000, 3478]
    payload = bytes.fromhex("000100002112a442000000000000000000000000")
    for sport in sports:
        for dport in dports:
            req = (
                Ether(dst=MAC_ADDR)
                / IPv6(dst=IPV6_ADDR)
                / UDP(sport=sport, dport=dport)
                / Raw(payload)
            )
            resp = iface.sr1(req, timeout=1)
            assert resp is not None, "expecting answer, got nothing"
            check_ipv6_checksum(resp)
            assert UDP in resp
            udp = resp[UDP]
            assert udp.sport == dport
            assert udp.dport == sport
            resp_payload = udp.payload.load
            type_, length, magic = struct.unpack(">HHI", resp_payload[:8])
            tid = resp_payload[8:20]
            data = resp_payload[20:]
            assert type_ == 0x0101, "expected type 0X0101, got 0x{:04x}".format(type_)
            assert length == 24, "expected length 24, got {}".format(length)
            assert (
                magic == 0x2112A442
            ), "expected magic 0x2112a442, got 0x{:08x}".format(magic)
            assert (
                tid == b"\x00" * 12
            ), "expected tid 0x000000000000000000000000, got {:x}".format(tid)
            expected_data = (
                bytes.fromhex("000100140002")
                + struct.pack(">H", sport)
                + inet_pton(AF_INET6, "2001:41d0::1234:5678")
            )
            assert data == expected_data, "unexpected data: {}".format(data)


@test
def test_ipv4_udp_stun_change_port(iface):
    sports = [12345, 55555, 80, 43273]
    dports = [80, 800, 8000, 3478, 65535]
    payload = bytes.fromhex("0001000803a3b9464dd8eb75e19481474293845c0003000400000002")
    for sport in sports:
        for dport in dports:
            req = (
                Ether(dst=MAC_ADDR)
                / IP(dst=IPV4_ADDR)
                / UDP(sport=sport, dport=dport)
                / Raw(payload)
            )
            resp = iface.sr1(req, timeout=1)
            assert resp is not None, "expecting answer, got nothing"
            check_ip_checksum(resp)
            assert UDP in resp, "no UDP layer found"
            udp = resp[UDP]
            assert (
                udp.sport == (dport + 1) % 2 ** 16
            ), "expected answer from UDP/{}, got it from UDP/{}".format(
                (dport + 1) % 2 ** 16, udp.sport
            )
            assert (
                udp.dport == sport
            ), "expected answer to UDP/{}, got it to UDP/{}".format(sport, udp.dport)
            resp_payload = udp.payload.load
            type_, length = struct.unpack(">HH", resp_payload[:4])
            tid = resp_payload[4:20]
            data = resp_payload[20:]
            assert type_ == 0x0101, "expected type 0X0101, got 0x{:04x}".format(type_)
            assert length == 12, "expected length 12, got {}".format(length)
            assert tid == bytes.fromhex("03a3b9464dd8eb75e19481474293845c"), (
                "expected tid 0x03a3b9464dd8eb75e19481474293845c, got %r" % tid
            )
            expected_data = b"\x00\x01\x00\x08\x00\x01" + struct.pack(
                ">HBBBB", sport, 192, 0, 0, 0
            )
            assert (
                data == expected_data
            ), f"unexpected data {data!r} != {expected_data!r}"


@test
def test_ipv6_udp_stun_change_port(iface):
    sports = [12345, 55555, 80, 43273]
    dports = [80, 800, 8000, 3478, 65535]
    payload = bytes.fromhex("0001000803a3b9464dd8eb75e19481474293845c0003000400000002")
    for sport in sports:
        for dport in dports:
            req = (
                Ether(dst=MAC_ADDR)
                / IPv6(dst=IPV6_ADDR)
                / UDP(sport=sport, dport=dport)
                / Raw(payload)
            )
            resp = iface.sr1(req, timeout=1)
            assert resp is not None, "expecting answer, got nothing"
            check_ipv6_checksum(resp)
            assert UDP in resp, "expecting UDP layer in answer, got nothing"
            udp = resp[UDP]
            assert (
                udp.sport == (dport + 1) % 2 ** 16
            ), "expected answer from UDP/{}, got it from UDP/{}".format(
                (dport + 1) % 2 ** 16, udp.sport
            )
            assert (
                udp.dport == sport
            ), "expected answer to UDP/{}, got it to UDP/{}".format(sport, udp.dport)
            resp_payload = udp.payload.load
            type_, length = struct.unpack(">HH", resp_payload[:4])
            tid = resp_payload[4:20]
            data = resp_payload[20:]
            assert type_ == 0x0101, "expected type 0X0101, got 0x{:04x}".format(type_)
            assert length == 24, "expected length 12, got {}".format(length)
            assert tid == bytes.fromhex("03a3b9464dd8eb75e19481474293845c"), (
                "expected tid 0x03a3b9464dd8eb75e19481474293845c, got %r" % tid
            )
            expected_data = (
                bytes.fromhex("000100140002")
                + struct.pack(">H", sport)
                + inet_pton(AF_INET6, "2001:41d0::1234:5678")
            )
            assert (
                data == expected_data
            ), f"unexpected data {data!r} != {expected_data!r}"


@test
def test_ipv4_tcp_ssh(iface):
    sport = 37183
    dports = [22, 80, 2222, 2022, 23874, 50000]
    for i, dport in enumerate(dports):
        seq_init = int(RandInt())
        banner = [
            b"SSH-2.0-AsyncSSH_2.1.0",
            b"SSH-2.0-PuTTY",
            b"SSH-2.0-libssh2_1.4.3",
            b"SSH-2.0-Go",
            b"SSH-2.0-PUTTY",
        ][i % 5]
        syn = (
            Ether(dst=MAC_ADDR)
            / IP(dst=IPV4_ADDR)
            / TCP(flags="S", sport=sport, dport=dport, seq=seq_init)
        )
        syn_ack = iface.sr1(syn, timeout=1)
        assert syn_ack is not None, "expecting answer, got nothing"
        check_ip_checksum(syn_ack)
        assert TCP in syn_ack, "expecting TCP, got %r" % syn_ack.summary()
        syn_ack = syn_ack[TCP]
        assert syn_ack.flags == "SA"
        ack = (
            Ether(dst=MAC_ADDR)
            / IP(dst=IPV4_ADDR)
            / TCP(
                flags="A",
                sport=sport,
                dport=dport,
                seq=seq_init + 1,
                ack=syn_ack.seq + 1,
            )
        )
        _ = iface.sr1(ack, timeout=1)
        req = (
            Ether(dst=MAC_ADDR)
            / IP(dst=IPV4_ADDR)
            / TCP(
                flags="PA",
                sport=sport,
                dport=dport,
                seq=seq_init + 1,
                ack=syn_ack.seq + 1,
            )
            / Raw(banner + b"\r\n")
        )
        resp = iface.sr1(req, timeout=1)
        assert resp is not None, "expecting answer, got nothing"
        check_ip_checksum(resp)
        assert TCP in resp, "expecting TCP, got %r" % resp.summary()
        tcp = resp[TCP]
        assert "A" in tcp.flags, "expecting ACK flag, not set (%r)" % tcp.flags
        assert "P" in tcp.flags, "expecting PSH flag, not set (%r)" % tcp.flags
        assert len(tcp.payload) > 0, "expecting payload, got none"
        assert tcp.payload.load.startswith(b"SSH-2.0-"), (
            "unexpected banner: %r" % tcp.payload.load
        )
        assert tcp.payload.load.endswith(b"\r\n"), (
            "unexpected banner: %r" % tcp.payload.load
        )


@test
def test_ipv4_udp_ssh(iface):
    sport = 37183
    dports = [22, 80, 2222, 2022, 23874, 50000]
    for i, dport in enumerate(dports):
        banner = [
            b"SSH-2.0-AsyncSSH_2.1.0",
            b"SSH-2.0-PuTTY",
            b"SSH-2.0-libssh2_1.4.3",
            b"SSH-2.0-Go",
            b"SSH-2.0-PUTTY",
        ][i % 5]
        req = (
            Ether(dst=MAC_ADDR)
            / IP(dst=IPV4_ADDR)
            / UDP(sport=sport, dport=dport)
            / Raw(banner + b"\r\n")
        )
        resp = iface.sr1(req, timeout=1)
        assert resp is not None, "expecting answer, got nothing"
        check_ip_checksum(resp)
        assert UDP in resp
        udp = resp[UDP]
        assert len(udp.payload) > 0, "expecting payload, got none"
        assert udp.payload.load.startswith(b"SSH-2.0-"), (
            "unexpected banner: %r" % udp.payload.load
        )
        assert udp.payload.load.endswith(b"\r\n"), (
            "unexpected banner: %r" % udp.payload.load
        )


@test
def test_ipv6_tcp_ssh(iface):
    sport = 37183
    dports = [22, 80, 2222, 2022, 23874, 50000]
    for i, dport in enumerate(dports):
        seq_init = int(RandInt())
        banner = [
            b"SSH-2.0-AsyncSSH_2.1.0",
            b"SSH-2.0-PuTTY",
            b"SSH-2.0-libssh2_1.4.3",
            b"SSH-2.0-Go",
            b"SSH-2.0-PUTTY",
        ][i % 5]
        syn = (
            Ether(dst=MAC_ADDR)
            / IPv6(dst=IPV6_ADDR)
            / TCP(flags="S", sport=sport, dport=dport, seq=seq_init)
        )
        syn_ack = iface.sr1(syn, timeout=1)
        assert syn_ack is not None, "expecting answer, got nothing"
        check_ipv6_checksum(syn_ack)
        assert TCP in syn_ack, "expecting TCP, got %r" % syn_ack.summary()
        syn_ack = syn_ack[TCP]
        assert syn_ack.flags == "SA"
        ack = (
            Ether(dst=MAC_ADDR)
            / IPv6(dst=IPV6_ADDR)
            / TCP(
                flags="A",
                sport=sport,
                dport=dport,
                seq=seq_init + 1,
                ack=syn_ack.seq + 1,
            )
        )
        _ = iface.sr1(ack, timeout=1)
        req = (
            Ether(dst=MAC_ADDR)
            / IPv6(dst=IPV6_ADDR)
            / TCP(
                flags="PA",
                sport=sport,
                dport=dport,
                seq=seq_init + 1,
                ack=syn_ack.seq + 1,
            )
            / Raw(banner + b"\r\n")
        )
        resp = iface.sr1(req, timeout=1)
        assert resp is not None, "expecting answer, got nothing"
        check_ipv6_checksum(resp)
        assert TCP in resp, "expecting TCP, got %r" % resp.summary()
        tcp = resp[TCP]
        assert "A" in tcp.flags, "expecting ACK flag, not set (%r)" % tcp.flags
        assert "P" in tcp.flags, "expecting PSH flag, not set (%r)" % tcp.flags
        assert len(tcp.payload) > 0, "expecting payload, got none"
        assert tcp.payload.load.startswith(b"SSH-2.0-"), (
            "unexpected banner: %r" % tcp.payload.load
        )
        assert tcp.payload.load.endswith(b"\r\n"), (
            "unexpected banner: %r" % tcp.payload.load
        )


@test
def test_ipv6_udp_ssh(iface):
    sport = 37183
    dports = [22, 80, 2222, 2022, 23874, 50000]
    for i, dport in enumerate(dports):
        banner = [
            b"SSH-2.0-AsyncSSH_2.1.0",
            b"SSH-2.0-PuTTY",
            b"SSH-2.0-libssh2_1.4.3",
            b"SSH-2.0-Go",
            b"SSH-2.0-PUTTY",
        ][i % 5]
        req = (
            Ether(dst=MAC_ADDR)
            / IPv6(dst=IPV6_ADDR)
            / UDP(sport=sport, dport=dport)
            / Raw(banner + b"\r\n")
        )
        resp = iface.sr1(req, timeout=1)
        assert resp is not None, "expecting answer, got nothing"
        check_ipv6_checksum(resp)
        assert UDP in resp
        udp = resp[UDP]
        assert len(udp.payload) > 0, "expecting payload, got none"
        assert udp.payload.load.startswith(b"SSH-2.0-"), (
            "unexpected banner: %r" % udp.payload.load
        )
        assert udp.payload.load.endswith(b"\r\n"), (
            "unexpected banner: %r" % udp.payload.load
        )


@test
def test_ipv4_tcp_ghost(iface):
    sport = 37184
    dports = [22, 23874]
    for dport in dports:
        seq_init = int(RandInt())
        banner = b"Gh0st\xad\x00\x00\x00\xe0\x00\x00\x00x\x9cKS``\x98\xc3\xc0\xc0\xc0\x06\xc4\x8c@\xbcQ\x96\x81\x81\tH\x07\xa7\x16\x95e&\xa7*\x04$&g+\x182\x94\xf6\xb000\xac\xa8rc\x00\x01\x11\xa0\x82\x1f\\`&\x83\xc7K7\x86\x19\xe5n\x0c9\x95n\x0c;\x84\x0f3\xac\xe8sch\xa8^\xcf4'J\x97\xa9\x82\xe30\xc3\x91h]&\x90\xf8\xce\x97S\xcbA4L?2=\xe1\xc4\x92\x86\x0b@\xf5`\x0cT\x1f\xae\xaf]\nr\x0b\x03#\xa3\xdc\x02~\x06\x86\x03+\x18m\xc2=\xfdtC,C\xfdL<<==\\\x9d\x19\x88\x00\xe5 \x02\x00T\xf5+\\"
        syn = (
            Ether(dst=MAC_ADDR)
            / IP(dst=IPV4_ADDR)
            / TCP(flags="S", sport=sport, dport=dport, seq=seq_init)
        )
        syn_ack = iface.sr1(syn, timeout=1)
        assert syn_ack is not None, "expecting answer, got nothing"
        check_ip_checksum(syn_ack)
        assert TCP in syn_ack, "expecting TCP, got %r" % syn_ack.summary()
        syn_ack = syn_ack[TCP]
        assert syn_ack.flags == "SA"
        ack = (
            Ether(dst=MAC_ADDR)
            / IP(dst=IPV4_ADDR)
            / TCP(
                flags="A",
                sport=sport,
                dport=dport,
                seq=seq_init + 1,
                ack=syn_ack.seq + 1,
            )
        )
        _ = iface.sr1(ack, timeout=1)
        req = (
            Ether(dst=MAC_ADDR)
            / IP(dst=IPV4_ADDR)
            / TCP(
                flags="PA",
                sport=sport,
                dport=dport,
                seq=seq_init + 1,
                ack=syn_ack.seq + 1,
            )
            / Raw(banner)
        )
        resp = iface.sr1(req, timeout=1)
        assert resp is not None, "expecting answer, got nothing"
        check_ip_checksum(resp)
        assert TCP in resp, "expecting TCP, got %r" % resp.summary()
        tcp = resp[TCP]
        assert "A" in tcp.flags, "expecting ACK flag, not set (%r)" % tcp.flags
        assert "P" in tcp.flags, "expecting PSH flag, not set (%r)" % tcp.flags
        data = raw(tcp.payload)
        assert data, "expecting payload, got none"
        assert data.startswith(b"Gh0st"), "unexpected banner: %r" % tcp.payload.load
        data_len, uncompressed_len = struct.unpack("<II", data[5:13])
        assert len(data) == data_len, "invalid Ghost payload: %r" % data
        assert len(zlib.decompress(data[13:])) == uncompressed_len, (
            "invalid Ghost payload: %r" % data
        )


def test_all(iface):
    global TESTS
    # execute tests
    for t in TESTS:
        t(iface)
    return len(ERRORS)
