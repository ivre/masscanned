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

from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.sendrecv import srp1
from scapy.volatile import RandInt

from ..conf import IPV4_ADDR, IPV6_ADDR, MAC_ADDR
from ..core import test, check_ip_checksum, check_ipv6_checksum


@test
def test_ipv4_udp_empty():
    for p in [0, 53, 1000]:
        req = (
            Ether(dst=MAC_ADDR)
            / IP(dst=IPV4_ADDR, proto=17)  # UDP
            / Raw()
        )
        repl = srp1(req, timeout=1)
        assert repl is None, "expecting no answer, got one"

@test
def test_ipv6_udp_empty():
    for p in [0, 53, 1000]:
        req = (
            Ether(dst=MAC_ADDR)
            / IPv6(dst=IPV6_ADDR, nh=17) # UDP
            / Raw()
        )
        repl = srp1(req, timeout=1)
        assert repl is None, "expecting no answer, got one"
