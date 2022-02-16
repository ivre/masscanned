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
from scapy.sendrecv import srp1

from ..conf import IPV4_ADDR, MAC_ADDR
from ..core import test, check_ip_checksum


@test
def test_ipv4_req():
    ##### IP #####
    ip_req = Ether(dst=MAC_ADDR) / IP(dst=IPV4_ADDR, id=0x1337) / ICMP(type=8, code=0)
    ip_repl = srp1(ip_req, timeout=1)
    assert ip_repl is not None, "expecting answer, got nothing"
    check_ip_checksum(ip_repl)
    assert IP in ip_repl, "no IP layer in response"
    ip_repl = ip_repl[IP]
    assert ip_repl.id == 0, "IP identification unexpected"


@test
def test_eth_req_other_mac():
    #### ETH ####
    ip_req = Ether(dst="00:00:00:11:11:11") / IP(dst=IPV4_ADDR) / ICMP(type=8, code=0)
    ip_repl = srp1(ip_req, timeout=1)
    assert ip_repl is None, "responding to other MAC addresses"


@test
def test_ipv4_req_other_ip():
    ##### IP #####
    ip_req = Ether(dst=MAC_ADDR) / IP(dst="1.2.3.4") / ICMP(type=8, code=0)
    ip_repl = srp1(ip_req, timeout=1)
    assert ip_repl is None, "responding to other IP addresses"
