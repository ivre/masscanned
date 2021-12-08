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

from scapy.all import *
from time import sleep
from tempfile import _get_candidate_names as gen_tmp_filename
from tempfile import gettempdir
import subprocess
import logging
import sys
import os

from src.all import test_all
from src.conf import *

# if args in CLI, they are passed to masscanned
if len(sys.argv) > 1:
    args = " ".join(sys.argv[1:])
else:
    args = ""

fmt = logging.Formatter("%(levelname)s\t%(message)s")
ch = logging.StreamHandler()
ch.setFormatter(fmt)
ch.setLevel(logging.INFO)
LOG = logging.getLogger(__name__)
LOG.setLevel(logging.INFO)
LOG.addHandler(ch)

conf.iface = 'tap0'
conf.verb = 0

# prepare configuration file for masscanned
ipfile = os.path.join(gettempdir(), next(gen_tmp_filename()))
with open(ipfile, "w") as f:
    f.write("{}\n".format(IPV4_ADDR))
    f.write("{}\n".format(IPV6_ADDR))

# create test interface
tap = TunTapInterface(resolve_iface(conf.iface))

# set interface
subprocess.run("ip a a dev {} 192.0.0.2".format(conf.iface), shell=True)
subprocess.run("ip link set {} up".format(conf.iface), shell=True)

# start capture
tcpdump = subprocess.Popen("tcpdump -enli {} -w {}".format(conf.iface, os.path.join(OUTDIR, "test_capture.pcap")), shell=True,
             stdin=None, stdout=None, stderr=None, close_fds=True)
# run masscanned
masscanned = subprocess.Popen("RUST_BACKTRACE=1 ./target/debug/masscanned -vvvvv -i {} -f {} -a {} {}".format(conf.iface, ipfile, MAC_ADDR, args), shell=True,
             stdin=None, stdout=open("test/res/masscanned.stdout", "w"), stderr=open("test/res/masscanned.stderr", "w"), close_fds=True)
sleep(1)

try:
    test_all(tap)
except AssertionError:
    pass

# terminate masscanned
masscanned.kill()
# terminate capture
sleep(2)
tcpdump.kill()
