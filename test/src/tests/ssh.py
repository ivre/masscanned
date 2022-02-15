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
def test_ipv4_tcp_ssh():
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
            / Raw(banner + b"\r\n")
        )
        resp = srp1(req, timeout=1)
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
def test_ipv4_udp_ssh():
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
        resp = srp1(req, timeout=1)
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
def test_ipv6_tcp_ssh():
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
            / Raw(banner + b"\r\n")
        )
        resp = srp1(req, timeout=1)
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
def test_ipv6_udp_ssh():
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
        resp = srp1(req, timeout=1)
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
