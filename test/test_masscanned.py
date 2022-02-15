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

import atexit
import functools
import os
from signal import SIGINT
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

from src.all import test_all
from src.conf import IPV4_ADDR, IPV6_ADDR, MAC_ADDR, OUTDIR


def cleanup_net(iface):
    global ipfile
    subprocess.check_call(["ip", "link", "delete", iface])
    subprocess.check_call(
        [
            "iptables",
            "-D",
            "INPUT",
            "-i",
            iface,
            "-m",
            "state",
            "--state",
            "ESTABLISHED",
            "-j",
            "ACCEPT",
        ]
    )
    subprocess.check_call(["iptables", "-D", "INPUT", "-i", iface, "-j", "DROP"])
    try:
        os.unlink(ipfile.name)
    except NameError:
        pass


def setup_net(iface):
    global IPV4_ADDR
    # create the interfaces pair
    atexit.register(functools.partial(cleanup_net, f"{iface}a"))
    subprocess.check_call(
        ["ip", "link", "add", f"{iface}a", "type", "veth", "peer", f"{iface}b"]
    )
    for sub in "a", "b":
        subprocess.check_call(["ip", "link", "set", f"{iface}{sub}", "up"])
    subprocess.check_call(["ip", "addr", "add", "dev", f"{iface}a", "192.0.0.0/31"])
    subprocess.check_call(
        ["ip", "addr", "add", "dev", f"{iface}a", "2001:41d0::1234:5678/96"]
    )
    subprocess.check_call(["ip", "route", "add", "1.2.3.4/32", "via", IPV4_ADDR])
    # prevent problems between raw scanners (Scapy, Nmap, Masscan) and
    # the host IP stack
    subprocess.check_call(
        [
            "iptables",
            "-A",
            "INPUT",
            "-i",
            f"{iface}a",
            "-m",
            "state",
            "--state",
            "ESTABLISHED",
            "-j",
            "ACCEPT",
        ]
    )
    subprocess.check_call(["iptables", "-A", "INPUT", "-i", f"{iface}a", "-j", "DROP"])
    conf.route.resync()
    conf.route6.resync()


IFACE = "masscanned"
setup_net(IFACE)
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
conf.iface = resolve_iface(f"{IFACE}a")

# start capture
if TCPDUMP:
    tcpdump = subprocess.Popen(
        [
            "tcpdump",
            "-enli",
            f"{IFACE}a",
            "-w",
            os.path.join(OUTDIR, "test_capture.pcap"),
        ]
    )
if ZEEK_PASSIVERECON:
    zeek = subprocess.Popen(
        [
            "zeek",
            "-C",
            "-b",
            "-i",
            f"{IFACE}a",
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
        ["p0f", "-i", f"{IFACE}a", "-o", os.path.join(OUTDIR, "p0f_log.txt")],
        stdout=open(os.path.join(OUTDIR, "p0f.stdout"), "w"),
        stderr=open(os.path.join(OUTDIR, "p0f.stderr"), "w"),
    )
# run masscanned
masscanned = subprocess.Popen(
    [
        "./target/debug/masscanned",
        "-vvvvv",
        "-i",
        f"{IFACE}b",
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
    result = test_all()
except AssertionError:
    result = -1

# terminate masscanned
masscanned.send_signal(SIGINT)
masscanned.wait()
# terminate capture
if TCPDUMP:
    tcpdump.send_signal(SIGINT)
    tcpdump.wait()
if ZEEK_PASSIVERECON:
    zeek.send_signal(SIGINT)
    zeek.wait()
if P0F:
    p0f.send_signal(SIGINT)
    p0f.wait()
sys.exit(result)
