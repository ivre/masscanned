# This file is part of masscanned.
# Copyright 2022 - The IVRE project
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

from socket import AF_INET6
import struct

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.pton_ntop import inet_pton
from scapy.sendrecv import srp1

from ..conf import IPV4_ADDR, IPV6_ADDR, MAC_ADDR
from ..core import test, check_ip_checksum, check_ipv6_checksum


@test
def test_ipv4_udp_dns_a():
    sports = [13274] # [53, 13274, 12198, 888, 0]
    dports = [80] # [53, 5353, 80, 161, 24732]
    payload = DNS()
    for sport in sports:
        for dport in dports:
            for domain in ['example.com', 'www.example.com', 'masscan.ned']:
                qd = DNSQR(qname=domain, qtype="A", qclass="IN")
                req = (
                    Ether(dst=MAC_ADDR)
                    / IP(dst=IPV4_ADDR)
                    / UDP(sport=sport, dport=dport)
                    / DNS(id=1234, rd=False, opcode=0, qd=qd))
                resp = srp1(req, timeout=1)
                assert resp is not None, "expecting answer, got nothing"
                check_ip_checksum(resp)
                assert UDP in resp, "no UDP layer found"
                udp = resp[UDP]
                assert udp.sport == dport, "unexpected UDP sport: {}".format(udp.sport)
                assert udp.dport == sport, "unexpected UDP dport: {}".format(udp.dport)
                if not DNS in udp:
                    try:
                        rr = DNS(udp.load)
                    except Exception:
                        raise AssertionError("no DNS layer found")
                else:
                    rr = udp[DNS]
                assert(rr.id == 1234), f"unexpected id value: {rr.id}"
                assert(rr.qr == True), f"unexpected qr value"
                assert(rr.opcode == 0), f"unexpected opcode value"
                assert(rr.aa == True), f"unexpected aa value"
                assert(rr.tc == False), f"unexpected tc value"
                assert(rr.rd == False), f"unexpected rd value"
                assert(rr.ra == False), f"unexpected ra value"
                assert(rr.z == 0), f"unexpected z value"
                assert(rr.rcode == 0), f"unexpected rcode value"
                assert(rr.qdcount == 1), f"unexpected qdcount value"
                assert(rr.ancount == 1), f"unexpected ancount value"
                assert(rr.nscount == 0), f"unexpected nscount value"
                assert(rr.arcount == 0), f"unexpected arcount value"

"""

@test
def test_ipv6_udp_stun():
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
            resp = srp1(req, timeout=1)
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
def test_ipv4_udp_stun_change_port():
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
            resp = srp1(req, timeout=1)
            assert resp is not None, "expecting answer, got nothing"
            check_ip_checksum(resp)
            assert UDP in resp, "no UDP layer found"
            udp = resp[UDP]
            assert (
                udp.sport == (dport + 1) % 2**16
            ), "expected answer from UDP/{}, got it from UDP/{}".format(
                (dport + 1) % 2**16, udp.sport
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
def test_ipv6_udp_stun_change_port():
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
            resp = srp1(req, timeout=1)
            assert resp is not None, "expecting answer, got nothing"
            check_ipv6_checksum(resp)
            assert UDP in resp, "expecting UDP layer in answer, got nothing"
            udp = resp[UDP]
            assert (
                udp.sport == (dport + 1) % 2**16
            ), "expected answer from UDP/{}, got it from UDP/{}".format(
                (dport + 1) % 2**16, udp.sport
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
"""
