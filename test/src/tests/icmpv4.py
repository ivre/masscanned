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

from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.sendrecv import srp1

from ..conf import IPV4_ADDR, MAC_ADDR
from ..core import test, check_ip_checksum


@test
def test_icmpv4_echo_req():
    ##### ICMPv4 #####
    icmp_req = (
        Ether(dst=MAC_ADDR)
        / IP(dst=IPV4_ADDR)
        / ICMP(type=8, code=0)
        / Raw("idrinkwaytoomuchcoffee")
    )
    icmp_repl = srp1(icmp_req, timeout=1)
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
