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

from scapy.compat import raw
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.sendrecv import srp1

from ..conf import IPV4_ADDR, MAC_ADDR
from ..core import test, check_ip_checksum


@test
def test_ipv4_udp_dns_in_a():
    sports = [53, 13274, 0]
    dports = [53, 5353, 80, 161, 24732]
    for sport in sports:
        for dport in dports:
            for domain in ["example.com", "www.example.com", "masscan.ned"]:
                qd = DNSQR(qname=domain, qtype="A", qclass="IN")
                dns_req = DNS(id=1234, rd=False, opcode=0, qd=qd)
                req = (
                    Ether(dst=MAC_ADDR)
                    / IP(dst=IPV4_ADDR)
                    / UDP(sport=sport, dport=dport)
                    / dns_req
                )
                resp = srp1(req, timeout=1)
                assert resp is not None, "expecting answer, got nothing"
                check_ip_checksum(resp)
                assert UDP in resp, "no UDP layer found"
                udp = resp[UDP]
                assert udp.sport == dport, "unexpected UDP sport: {}".format(udp.sport)
                assert udp.dport == sport, "unexpected UDP dport: {}".format(udp.dport)
                if DNS not in udp:
                    try:
                        dns_rep = DNS(udp.load)
                    except Exception:
                        raise AssertionError("no DNS layer found")
                else:
                    dns_rep = udp[DNS]
                assert dns_rep.id == 1234, f"unexpected id value: {dns_rep.id}"
                assert dns_rep.qr, "unexpected qr value"
                assert dns_rep.opcode == 0, "unexpected opcode value"
                assert dns_rep.aa, "unexpected aa value"
                assert not dns_rep.tc, "unexpected tc value"
                assert not dns_rep.rd, "unexpected rd value"
                assert not dns_rep.ra, "unexpected ra value"
                assert dns_rep.z == 0, "unexpected z value"
                assert dns_rep.rcode == 0, "unexpected rcode value"
                assert dns_rep.qdcount == 1, "unexpected qdcount value"
                assert dns_rep.ancount == 1, "unexpected ancount value"
                assert dns_rep.nscount == 0, "unexpected nscount value"
                assert dns_rep.arcount == 0, "unexpected arcount value"
                assert raw(dns_rep.qd[0]) == raw(
                    dns_req.qd[0]
                ), "query in request and response do not match"
                assert raw(dns_rep.qd[0].qname) == raw(
                    dns_req.qd[0].qname + b"."
                ), "if this test fails, it may mean that scapy fixed the bug in dns.py L134 - if that is so, remove \" + b'.'\" in the test"
                assert (
                    dns_rep.an[0].rrname == dns_req.qd[0].qname + b"."
                ), "if this test fails, it may mean that scapy fixed the bug in dns.py L134 - if that is so, remove \" + b'.'\" in the test"
                assert (
                    dns_rep.an[0].rclass == dns_req.qd[0].qclass
                ), "class in answer does not match query"
                assert (
                    dns_rep.an[0].type == dns_req.qd[0].qtype
                ), "type in answer does not match query"
                assert dns_rep.an[0].rdata == IPV4_ADDR


@test
def test_ipv4_udp_dns_in_a_multiple_queries():
    sports = [53, 13274, 12198, 888, 0]
    dports = [53, 5353, 80, 161, 24732]
    for sport in sports:
        for dport in dports:
            qd = (
                DNSQR(qname="www.example1.com", qtype="A", qclass="IN")
                / DNSQR(qname="www.example2.com", qtype="A", qclass="IN")
                / DNSQR(qname="www.example3.com", qtype="A", qclass="IN")
            )
            dns_req = DNS(id=1234, rd=False, opcode=0, qd=qd)
            req = (
                Ether(dst=MAC_ADDR)
                / IP(dst=IPV4_ADDR)
                / UDP(sport=sport, dport=dport)
                / dns_req
            )
            resp = srp1(req, timeout=1)
            assert resp is not None, "expecting answer, got nothing"
            check_ip_checksum(resp)
            assert UDP in resp, "no UDP layer found"
            udp = resp[UDP]
            assert udp.sport == dport, "unexpected UDP sport: {}".format(udp.sport)
            assert udp.dport == sport, "unexpected UDP dport: {}".format(udp.dport)
            if DNS not in udp:
                try:
                    dns_rep = DNS(udp.load)
                except Exception:
                    raise AssertionError("no DNS layer found")
            else:
                dns_rep = udp[DNS]
            assert dns_rep.id == 1234, f"unexpected id value: {dns_rep.id}"
            assert dns_rep.qr, "unexpected qr value"
            assert dns_rep.opcode == 0, "unexpected opcode value"
            assert dns_rep.aa, "unexpected aa value"
            assert not dns_rep.tc, "unexpected tc value"
            assert not dns_rep.rd, "unexpected rd value"
            assert not dns_rep.ra, "unexpected ra value"
            assert dns_rep.z == 0, "unexpected z value"
            assert dns_rep.rcode == 0, "unexpected rcode value"
            assert dns_rep.qdcount == 3, "unexpected qdcount value"
            assert dns_rep.ancount == 3, "unexpected ancount value"
            assert dns_rep.nscount == 0, "unexpected nscount value"
            assert dns_rep.arcount == 0, "unexpected arcount value"
            for i, q in enumerate(qd):
                assert raw(dns_rep.qd[i]) == raw(
                    dns_req.qd[i]
                ), "query in request and response do not match"
                assert raw(dns_rep.qd[i].qname) == raw(
                    dns_req.qd[i].qname + b"."
                ), "if this test fails, it may mean that scapy fixed the bug in dns.py L134 - if that is so, remove \" + b'.'\" in the test"
                assert (
                    dns_rep.an[i].rrname == dns_req.qd[i].qname + b"."
                ), "if this test fails, it may mean that scapy fixed the bug in dns.py L134 - if that is so, remove \" + b'.'\" in the test"
                assert (
                    dns_rep.an[i].rclass == dns_req.qd[i].qclass
                ), "class in answer does not match query"
                assert (
                    dns_rep.an[i].type == dns_req.qd[i].qtype
                ), "type in answer does not match query"
                assert dns_rep.an[i].rdata == IPV4_ADDR
