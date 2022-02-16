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

from scapy.layers.l2 import Ether, ARP, ETHER_BROADCAST
from scapy.sendrecv import srp1

from ..conf import IPV4_ADDR, MAC_ADDR
from ..core import test


@test
def test_arp_req():
    ##### ARP #####
    arp_req = Ether(dst=ETHER_BROADCAST) / ARP(pdst=IPV4_ADDR)
    arp_repl = srp1(arp_req, timeout=1)
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
def test_arp_req_other_ip():
    ##### ARP #####
    arp_req = Ether(dst=ETHER_BROADCAST) / ARP(pdst="1.2.3.4")
    arp_repl = srp1(arp_req, timeout=1)
    assert arp_repl is None, "responding to ARP requests for other IP addresses"
