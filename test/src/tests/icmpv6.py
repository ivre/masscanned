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

from scapy.layers.inet6 import (
    ICMPv6EchoReply,
    ICMPv6EchoRequest,
    ICMPv6NDOptDstLLAddr,
    ICMPv6ND_NA,
    ICMPv6ND_NS,
    IPv6,
)
from scapy.layers.l2 import Ether
from scapy.sendrecv import srp1

from ..conf import IPV6_ADDR, MAC_ADDR
from ..core import test, multicast


@test
def test_icmpv6_neighbor_solicitation():
    ##### IPv6 Neighbor Solicitation #####
    for mac in [
        "ff:ff:ff:ff:ff:ff",
        "33:33:00:00:00:01",
        MAC_ADDR,
        multicast(IPV6_ADDR),
    ]:
        nd_ns = Ether(dst=mac) / IPv6() / ICMPv6ND_NS(tgt=IPV6_ADDR)
        nd_na = srp1(nd_ns, timeout=1)
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
        nd_na = srp1(nd_ns, timeout=1)
        assert nd_na is not None, "expecting no answer, got one"


@test
def test_icmpv6_neighbor_solicitation_other_ip():
    ##### IPv6 Neighbor Solicitation #####
    nd_ns = (
        Ether(dst="ff:ff:ff:ff:ff:ff")
        / IPv6()
        / ICMPv6ND_NS(tgt="2020:4141:3030:2020::bdbd")
    )
    nd_na = srp1(nd_ns, timeout=1)
    assert nd_na is None, "responding to ND_NS for other IP addresses"


@test
def test_icmpv6_echo_req():
    ##### IPv6 Ping #####
    echo_req = (
        Ether(dst=MAC_ADDR)
        / IPv6(dst=IPV6_ADDR)
        / ICMPv6EchoRequest(data="waytoomanynapkins")
    )
    echo_repl = srp1(echo_req, timeout=1)
    assert echo_repl is not None, "expecting answer, got nothing"
    assert ICMPv6EchoReply in echo_repl
    echo_repl = echo_repl[ICMPv6EchoReply]
    # check answer content
    assert echo_repl.code == 0
    assert echo_repl.data == echo_req.data
