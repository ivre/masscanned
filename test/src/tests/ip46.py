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

from scapy.layers.inet import IP, ICMP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.sendrecv import srp1
from scapy.volatile import RandInt

from ..conf import IPV4_ADDR, IPV6_ADDR, MAC_ADDR
from ..core import test, check_ip_checksum, check_ipv6_checksum


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


@test
def test_tcp_syn():
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
        syn_ack = srp1(syn, timeout=1)
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
def test_ipv4_tcp_psh_ack():
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
    syn_ack = srp1(psh_ack, timeout=1)
    assert syn_ack is None, "no answer expected, got one"
    # test the anti-injection mechanism
    seq_init = int(RandInt())
    syn = (
        Ether(dst=MAC_ADDR)
        / IP(dst=IPV4_ADDR)
        / TCP(flags="S", sport=sport, dport=port, seq=seq_init)
    )
    syn_ack = srp1(syn, timeout=1)
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
    ack = srp1(psh_ack, timeout=1)
    assert ack is None, "no answer expected, got one"
    # should get an answer this time
    psh_ack = (
        Ether(dst=MAC_ADDR)
        / IP(dst=IPV4_ADDR)
        / TCP(
            flags="PA", sport=sport, dport=port, ack=syn_ack.seq + 1, seq=seq_init + 1
        )
    )
    ack = srp1(psh_ack, timeout=1)
    assert ack is not None, "expecting answer, got nothing"
    check_ip_checksum(ack)
    assert TCP in ack, "expecting TCP, got %r" % ack.summary()
    ack = ack[TCP]
    assert ack.flags == "A", "expecting TCP A, got %r" % syn_ack.flags


@test
def test_ipv6_tcp_psh_ack():
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
    syn_ack = srp1(psh_ack, timeout=1)
    assert syn_ack is None, "no answer expected, got one"
    # test the anti-injection mechanism
    syn = (
        Ether(dst=MAC_ADDR)
        / IPv6(dst=IPV6_ADDR)
        / TCP(flags="S", sport=sport, dport=port, seq=seq_init)
    )
    syn_ack = srp1(syn, timeout=1)
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
    ack = srp1(psh_ack, timeout=1)
    assert ack is None, "no answer expected, got one"
    # should get an answer this time
    psh_ack = (
        Ether(dst=MAC_ADDR)
        / IPv6(dst=IPV6_ADDR)
        / TCP(
            flags="PA", sport=sport, dport=port, ack=syn_ack.seq + 1, seq=seq_init + 1
        )
    )
    ack = srp1(psh_ack, timeout=1)
    assert ack is not None, "expecting answer, got nothing"
    check_ipv6_checksum(ack)
    assert TCP in ack, "expecting TCP, got %r" % ack.summary()
    ack = ack[TCP]
    assert ack.flags == "A", "expecting TCP A, got %r" % syn_ack.flags
