#!/usr/bin/env python3

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
import os
import subprocess
import sys
from time import sleep
from tempfile import NamedTemporaryFile

try:
    from ivre.config import guess_prefix
except ImportError:
    HAS_IVRE = False
else:
    HAS_IVRE = True
from scapy.config import conf
from scapy.interfaces import resolve_iface
from scapy.layers.tuntap import TunTapInterface

from src.all import test_all
from src.conf import IPV4_ADDR, IPV6_ADDR, MAC_ADDR, OUTDIR


def setup_logs():
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(levelname)s\t%(message)s"))
    ch.setLevel(logging.INFO)
    log = logging.getLogger(__name__)
    log.setLevel(logging.INFO)
    log.addHandler(ch)
    return log


LOG = setup_logs()
IFACE = "tap0"
TCPDUMP = bool(os.environ.get("USE_TCPDUMP"))
if HAS_IVRE:
    ZEEK_PASSIVERECON = bool(os.environ.get("USE_ZEEK"))
else:
    ZEEK_PASSIVERECON = False
P0F = bool(os.environ.get("USE_P0F"))
conf.verb = 0

# prepare configuration file for masscanned
with NamedTemporaryFile(delete=False, mode="w") as ipfile:
    ipfile.write(f"{IPV4_ADDR}\n")
    ipfile.write(f"{IPV6_ADDR}\n")

# create test interface
tap = TunTapInterface(IFACE)
conf.iface = resolve_iface(IFACE)

# set interface
subprocess.check_call(["ip", "addr", "add", "dev", IFACE, "192.0.0.0/31"])
subprocess.check_call(["ip", "addr", "add", "dev", IFACE, "2001:41d0::1234:5678/96"])
subprocess.check_call(["ip", "link", "set", IFACE, "up"])
subprocess.check_call(["ip", "route", "add", "1.2.3.4/32", "via", IPV4_ADDR])
conf.route.resync()
conf.route6.resync()

# start capture
if TCPDUMP:
    tcpdump = subprocess.Popen(
        ["tcpdump", "-enli", IFACE, "-w", os.path.join(OUTDIR, "test_capture.pcap")]
    )
if ZEEK_PASSIVERECON:
    zeek = subprocess.Popen(
        [
            "zeek",
            "-C",
            "-b",
            "-i",
            IFACE,
            os.path.join(
                guess_prefix("zeek"),
                "ivre",
                "passiverecon",
                "bare.zeek",
            ),
            "-e",
            "redef tcp_content_deliver_all_resp = T; "
            "redef tcp_content_deliver_all_orig = T; "
            f"redef PassiveRecon::HONEYPOTS += {{ {IPV4_ADDR}, [{IPV6_ADDR}] }}",
        ],
        stdout=open(os.path.join(OUTDIR, "zeek_passiverecon.stdout"), "w"),
        stderr=open(os.path.join(OUTDIR, "zeek_passiverecon.stderr"), "w"),
    )
if P0F:
    p0f = subprocess.Popen(
        ["p0f", "-i", IFACE, "-o", os.path.join(OUTDIR, "p0f_log.txt")],
        stdout=open(os.path.join(OUTDIR, "p0f.stdout"), "w"),
        stderr=open(os.path.join(OUTDIR, "p0f.stderr"), "w"),
    )
# run masscanned
masscanned = subprocess.Popen(
    [
        "./target/debug/masscanned",
        "-vvvvv",
        "-i",
        IFACE,
        "-f",
        ipfile.name,
        "-a",
        MAC_ADDR,
    ]
    # if args in CLI, they are passed to masscanned
    + sys.argv[1:],
    env=dict(os.environ, RUST_BACKTRACE="1"),
    stdout=open(os.path.join(OUTDIR, "masscanned.stdout"), "w"),
    stderr=open(os.path.join(OUTDIR, "masscanned.stderr"), "w"),
)
sleep(1)

try:
    result = test_all(tap)
except AssertionError:
    result = -1

# terminate masscanned
masscanned.kill()
masscanned.wait()
# terminate capture
if TCPDUMP:
    tcpdump.kill()
    tcpdump.wait()
if ZEEK_PASSIVERECON:
    zeek.kill()
    zeek.wait()
if P0F:
    p0f.kill()
    p0f.wait()
sys.exit(result)
