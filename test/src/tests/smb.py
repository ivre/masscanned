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

import subprocess

from ..core import test
from ..conf import IPV4_ADDR


@test
def test_smb1_network_req():
    proc = subprocess.Popen(
        [
            "smbclient",
            "-U ''",
            "-N",
            "-d 6",
            "-t 1",
            "-L",
            IPV4_ADDR,
            "--option=client min protocol=NT1",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    out, _ = proc.communicate()
    assert f"Connecting to {IPV4_ADDR} at port 445" in out, "\n" + out
    assert "session request ok" in out, "\n" + out
    assert f"negotiated dialect[NT1] against server[{IPV4_ADDR}]" in out, "\n" + out


@test
def test_smb2_network_req():
    proc = subprocess.Popen(
        [
            "smbclient",
            "-U ''",
            "-N",
            "-d 5",
            "-t 1",
            "-L",
            IPV4_ADDR,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    out, _ = proc.communicate()
    assert f"Connecting to {IPV4_ADDR} at port 445" in out, "\n" + out
    assert "session request ok" in out, "\n" + out
    assert f"negotiated dialect[SMB2_02] against server[{IPV4_ADDR}]" in out, "\n" + out
