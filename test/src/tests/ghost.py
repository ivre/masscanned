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

import struct
import zlib

from scapy.compat import raw
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.sendrecv import srp1
from scapy.volatile import RandInt

from ..conf import IPV4_ADDR, MAC_ADDR
from ..core import test, check_ip_checksum


@test
def test_ipv4_tcp_ghost():
    sport = 37184
    dports = [22, 23874]
    for dport in dports:
        seq_init = int(RandInt())
        banner = b"Gh0st\xad\x00\x00\x00\xe0\x00\x00\x00x\x9cKS``\x98\xc3\xc0\xc0\xc0\x06\xc4\x8c@\xbcQ\x96\x81\x81\tH\x07\xa7\x16\x95e&\xa7*\x04$&g+\x182\x94\xf6\xb000\xac\xa8rc\x00\x01\x11\xa0\x82\x1f\\`&\x83\xc7K7\x86\x19\xe5n\x0c9\x95n\x0c;\x84\x0f3\xac\xe8sch\xa8^\xcf4'J\x97\xa9\x82\xe30\xc3\x91h]&\x90\xf8\xce\x97S\xcbA4L?2=\xe1\xc4\x92\x86\x0b@\xf5`\x0cT\x1f\xae\xaf]\nr\x0b\x03#\xa3\xdc\x02~\x06\x86\x03+\x18m\xc2=\xfdtC,C\xfdL<<==\\\x9d\x19\x88\x00\xe5 \x02\x00T\xf5+\\"
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
            / Raw(banner)
        )
        resp = srp1(req, timeout=1)
        assert resp is not None, "expecting answer, got nothing"
        check_ip_checksum(resp)
        assert TCP in resp, "expecting TCP, got %r" % resp.summary()
        tcp = resp[TCP]
        assert "A" in tcp.flags, "expecting ACK flag, not set (%r)" % tcp.flags
        assert "P" in tcp.flags, "expecting PSH flag, not set (%r)" % tcp.flags
        data = raw(tcp.payload)
        assert data, "expecting payload, got none"
        assert data.startswith(b"Gh0st"), "unexpected banner: %r" % tcp.payload.load
        data_len, uncompressed_len = struct.unpack("<II", data[5:13])
        assert len(data) == data_len, "invalid Ghost payload: %r" % data
        assert len(zlib.decompress(data[13:])) == uncompressed_len, (
            "invalid Ghost payload: %r" % data
        )
