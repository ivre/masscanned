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

import importlib
import os

# Export / other tests
from .core import test_all  # noqa: F401

DEFAULT_TESTS = [
    "arp",
    "ghost",
    "http",
    "icmpv4",
    "icmpv6",
    "ip",
    "rpc",
    "smb",
    "ssh",
    "stun",
    "tcp",
]

ENABLED_TESTS = DEFAULT_TESTS
if tests := os.environ.get("TESTS"):
    ENABLED_TESTS = [x.strip() for x in tests.split(",")]

for test in ENABLED_TESTS:
    importlib.import_module(".tests." + test, package="src")
