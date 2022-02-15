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

import logging

from scapy.compat import raw
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6


def setup_logs():
    log = logging.getLogger()
    log.setLevel(logging.DEBUG)
    if not log.handlers:
        ch = logging.StreamHandler()
        ch.setFormatter(logging.Formatter("%(levelname)s\t%(message)s"))
        ch.setLevel(logging.DEBUG)
        log.addHandler(ch)
    return log


LOG = setup_logs()
TESTS = []
ERRORS = []

# decorator to automatically add a function to tests
def test(f):
    global ERRORS, TESTS
    OK = "\033[1mOK\033[0m"
    KO = "\033[1m\033[1;%dmKO\033[0m" % 31
    fname = f.__name__.ljust(50, ".")

    def w():
        try:
            f()
            LOG.info("{}{}".format(fname, OK))
        except AssertionError as e:
            LOG.error("{}{}: {}".format(fname, KO, e))
            ERRORS.append(fname)

    TESTS.append(w)
    return w


def test_all():
    global ERRORS, TESTS
    # execute tests
    for t in TESTS:
        t()
    LOG.info(f"\033[1mRan {len(TESTS)} tests with {len(ERRORS)} errors\033[0m")
    return len(ERRORS)


def multicast(ip6):
    a, b = ip6.split(":")[-2:]
    mac = ["33", "33", "ff"]
    if len(a) == 4:
        mac.append(a[2:])
    else:
        mac.append("00")
    if len(b) >= 2:
        mac.append(b[:2])
    else:
        mac.append("00")
    if len(b) >= 4:
        mac.append(b[2:])
    else:
        mac.append("00")
    return ":".join(mac)


def check_ip_checksum(pkt):
    assert IP in pkt, "no IP layer found"
    ip_pkt = pkt[IP]
    chksum = ip_pkt.chksum
    del ip_pkt.chksum
    assert IP(raw(ip_pkt)).chksum == chksum, "bad IPv4 checksum"


def check_ipv6_checksum(pkt):
    assert IPv6 in pkt, "no IP layer found"
    ip_pkt = pkt[IPv6]
    chksum = ip_pkt.chksum
    del ip_pkt.chksum
    assert IPv6(raw(ip_pkt)).chksum == chksum, "bad IPv6 checksum"
