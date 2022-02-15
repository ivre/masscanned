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

from subprocess import check_call
from tempfile import NamedTemporaryFile
import json
import os
import re

from ivre.db import DBNmap

from ..conf import IPV4_ADDR
from ..core import test


@test
def test_rpc_nmap():
    for scan in "SU":
        with NamedTemporaryFile(delete=False) as xml_result:
            check_call(
                [
                    "nmap",
                    "-n",
                    "-vv",
                    "-oX",
                    "-",
                    IPV4_ADDR,
                    f"-s{scan}V",
                    "-p",
                    "111",
                    "--script",
                    "rpcinfo,rpc-grind",
                ],
                stdout=xml_result,
            )
        with NamedTemporaryFile(delete=False, mode="w") as json_result:
            DBNmap(output=json_result).store_scan(xml_result.name)
        os.unlink(xml_result.name)
        with open(json_result.name) as fdesc:
            results = [json.loads(line) for line in fdesc]
        os.unlink(json_result.name)
        assert len(results) == 1, f"Expected 1 result, got {len(results)}"
        result = results[0]
        assert len(result["ports"]) == 1, f"Expected 1 port, got {len(result['ports'])}"
        port = result["ports"][0]
        assert port["port"] == 111 and port["protocol"] == (
            "tcp" if scan == "S" else "udp"
        )
        assert port["service_name"] in {"rpcbind", "nfs"}
        assert port["service_extrainfo"] in {"RPC #100000", "RPC #100003"}
        assert (
            len(port["scripts"]) == 1
        ), f"Expected 1 script, got {len(port['scripts'])}"
        script = port["scripts"][0]
        assert script["id"] == "rpcinfo", "Expected rpcinfo script, not found"
        assert len(script["rpcinfo"]) == 1


@test
def test_rpcinfo():
    with NamedTemporaryFile(delete=False) as rpcout:
        check_call(["rpcinfo", "-p", IPV4_ADDR], stdout=rpcout)
    with open(rpcout.name) as fdesc:
        found = []
        for line in fdesc:
            line = line.split()
            if line[0] == "program":
                # header
                continue
            assert line[0] == "100000", f"Expected program 100000, got {line[0]}"
            found.append(int(line[1]))
        assert len(found) == 3, f"Expected three versions, got {found}"
        for i in range(2, 5):
            assert i in found, f"Missing version {i} in {found}"
    os.unlink(rpcout.name)
    with NamedTemporaryFile(delete=False) as rpcout:
        check_call(["rpcinfo", "-u", IPV4_ADDR, "100000"], stdout=rpcout)
    with open(rpcout.name) as fdesc:
        found = []
        expr = re.compile("^program 100000 version ([0-9]) ready and waiting$")
        for line in fdesc:
            found.append(int(expr.search(line.strip()).group(1)))
        assert len(found) == 3, f"Expected three versions, got {found}"
        for i in range(2, 5):
            assert i in found, f"Missing version {i} in {found}"
    os.unlink(rpcout.name)
