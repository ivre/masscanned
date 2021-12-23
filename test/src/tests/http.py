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

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.sendrecv import srp1
from scapy.volatile import RandInt

from ..conf import IPV4_ADDR, IPV6_ADDR, MAC_ADDR
from ..core import test, check_ip_checksum, check_ipv6_checksum


@test
def test_ipv4_tcp_http():
    sport = 24592
    dports = [80, 443, 5000, 53228]
    for dport in dports:
        seq_init = int(RandInt())
        syn = (
            Ether(dst=MAC_ADDR)
            / IP(dst=IPV4_ADDR)
            / TCP(flags="S", sport=sport, dport=dport, seq=seq_init)
        )
        syn_ack = srp1(syn, timeout=1)
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
        _ = srp1(ack, timeout=1)
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
        resp = srp1(req, timeout=1)
        assert resp is not None, "expecting answer, got nothing"
        check_ip_checksum(resp)
        assert TCP in resp, "expecting TCP, got %r" % resp.summary()
        tcp = resp[TCP]
        assert tcp.payload.load.startswith(b"HTTP/1.1 401 Unauthorized\n")


@test
def test_ipv4_tcp_http_segmented():
    sport = 24592
    dports = [80, 443, 5000, 53228]
    for dport in dports:
        seq_init = int(RandInt())
        syn = (
            Ether(dst=MAC_ADDR)
            / IP(dst=IPV4_ADDR)
            / TCP(flags="S", sport=sport, dport=dport, seq=seq_init)
        )
        syn_ack = srp1(syn, timeout=1)
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
        _ = srp1(ack, timeout=1)
        # request is not complete yet
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
            / Raw("GET / HTTP/1.1\r\n")
        )
        resp = srp1(req, timeout=1)
        assert resp is not None, "expecting answer, got nothing"
        check_ip_checksum(resp)
        assert TCP in resp, "expecting TCP, got %r" % resp.summary()
        assert resp[TCP].flags == "A"
        req = (
            Ether(dst=MAC_ADDR)
            / IP(dst=IPV4_ADDR)
            / TCP(
                flags="PA",
                sport=sport,
                dport=dport,
                seq=seq_init + len(req) + 1,
                ack=syn_ack.seq + 1,
            )
            / Raw("\r\n")
        )
        resp = srp1(req, timeout=1)
        assert resp is not None, "expecting answer, got nothing"
        check_ip_checksum(resp)
        assert TCP in resp, "expecting TCP, got %r" % resp.summary()
        tcp = resp[TCP]
        assert tcp.flags == "PA"
        assert tcp.payload.load.startswith(b"HTTP/1.1 401 Unauthorized\n")


@test
def test_ipv4_tcp_http_incomplete():
    sport = 24595
    dports = [80, 443, 5000, 53228]
    for dport in dports:
        seq_init = int(RandInt())
        syn = (
            Ether(dst=MAC_ADDR)
            / IP(dst=IPV4_ADDR)
            / TCP(flags="S", sport=sport, dport=dport, seq=seq_init)
        )
        syn_ack = srp1(syn, timeout=1)
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
        _ = srp1(ack, timeout=1)
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
            # purposedly incomplete request (missing additionnal ending \r\n)
            / Raw("GET / HTTP/1.1\r\n")
        )
        resp = srp1(req, timeout=1)
        assert resp is not None, "expecting an answer, got none"
        check_ip_checksum(resp)
        assert TCP in resp, "expecting TCP, got %r" % resp.summary()
        tcp = resp[TCP]
        assert tcp.flags == "A", "expecting TCP flag A, got {}".format(tcp.flags)


@test
def test_ipv6_tcp_http():
    sport = 24594
    dports = [80, 443, 5000, 53228]
    for dport in dports:
        seq_init = int(RandInt())
        syn = (
            Ether(dst=MAC_ADDR)
            / IPv6(dst=IPV6_ADDR)
            / TCP(flags="S", sport=sport, dport=dport, seq=seq_init)
        )
        syn_ack = srp1(syn, timeout=1)
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
        _ = srp1(ack, timeout=1)
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
        resp = srp1(req, timeout=1)
        assert resp is not None, "expecting answer, got nothing"
        check_ipv6_checksum(resp)
        assert TCP in resp, "expecting TCP, got %r" % resp.summary()
        tcp = resp[TCP]
        assert tcp.payload.load.startswith(b"HTTP/1.1 401 Unauthorized\n")


@test
def test_ipv4_udp_http():
    sport = 24592
    dports = [80, 443, 5000, 53228]
    for dport in dports:
        req = (
            Ether(dst=MAC_ADDR)
            / IP(dst=IPV4_ADDR)
            / UDP(sport=sport, dport=dport)
            / Raw("GET / HTTP/1.1\r\n\r\n")
        )
        resp = srp1(req, timeout=1)
        assert resp is not None, "expecting answer, got nothing"
        check_ip_checksum(resp)
        assert UDP in resp
        udp = resp[UDP]
        assert udp.payload.load.startswith(b"HTTP/1.1 401 Unauthorized\n")


@test
def test_ipv6_udp_http():
    sport = 24592
    dports = [80, 443, 5000, 53228]
    for dport in dports:
        req = (
            Ether(dst=MAC_ADDR)
            / IPv6(dst=IPV6_ADDR)
            / UDP(sport=sport, dport=dport)
            / Raw("GET / HTTP/1.1\r\n\r\n")
        )
        resp = srp1(req, timeout=1)
        assert resp is not None, "expecting answer, got nothing"
        check_ipv6_checksum(resp)
        assert UDP in resp
        udp = resp[UDP]
        assert udp.payload.load.startswith(b"HTTP/1.1 401 Unauthorized\n")


@test
def test_ipv4_tcp_http_ko():
    sport = 24596
    dports = [80, 443, 5000, 53228]
    for dport in dports:
        seq_init = int(RandInt())
        syn = (
            Ether(dst=MAC_ADDR)
            / IP(dst=IPV4_ADDR)
            / TCP(flags="S", sport=sport, dport=dport, seq=seq_init)
        )
        syn_ack = srp1(syn, timeout=1)
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
        _ = srp1(ack, timeout=1)
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
        resp = srp1(req, timeout=1)
        assert resp is not None, "expecting answer, got nothing"
        check_ip_checksum(resp)
        assert TCP in resp, "expecting TCP, got %r" % resp.summary()
        assert "P" not in resp[TCP].flags
        assert len(resp[TCP].payload) == 0


@test
def test_ipv4_udp_http_ko():
    sport = 24592
    dports = [80, 443, 5000, 53228]
    for dport in dports:
        req = (
            Ether(dst=MAC_ADDR)
            / IP(dst=IPV4_ADDR)
            / UDP(sport=sport, dport=dport)
            / Raw(bytes.fromhex("4f5054494f4e53"))
        )
        resp = srp1(req, timeout=1)
        assert resp is None, "expecting no answer, got one"


@test
def test_ipv6_tcp_http_ko():
    sport = 24597
    dports = [80, 443, 5000, 53228]
    for dport in dports:
        seq_init = int(RandInt())
        syn = (
            Ether(dst=MAC_ADDR)
            / IPv6(dst=IPV6_ADDR)
            / TCP(flags="S", sport=sport, dport=dport, seq=seq_init)
        )
        syn_ack = srp1(syn, timeout=1)
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
        _ = srp1(ack, timeout=1)
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
        resp = srp1(req, timeout=1)
        assert resp is not None, "expecting answer, got nothing"
        check_ipv6_checksum(resp)
        assert TCP in resp, "expecting TCP, got %r" % resp.summary()
        assert "P" not in resp[TCP].flags
        assert len(resp[TCP].payload) == 0


@test
def test_ipv6_udp_http_ko():
    sport = 24592
    dports = [80, 443, 5000, 53228]
    for dport in dports:
        req = (
            Ether(dst=MAC_ADDR)
            / IPv6(dst=IPV6_ADDR)
            / UDP(sport=sport, dport=dport)
            / Raw(bytes.fromhex("4f5054494f4e53"))
        )
        resp = srp1(req, timeout=1)
        assert resp is None, "expecting no answer, got one"
