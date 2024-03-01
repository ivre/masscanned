# This file is part of masscanned.
# Copyright 2021 - 2024 The IVRE project
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

FROM debian:12 AS fetcher

RUN apt-get -q update && \
    apt-get -qy --no-install-recommends install ca-certificates curl && \
    curl -L https://github.com/ivre/masscanned/archive/refs/heads/master.tar.gz | tar zxf -


FROM rust AS builder

COPY --from=fetcher /masscanned-master /masscanned-master

RUN cd masscanned-master && \
    cargo build --release


FROM debian:12
LABEL maintainer="Pierre LALET <pierre@droids-corp.org>"

COPY --from=builder /masscanned-master/target/release/masscanned /usr/local/bin/masscanned

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get -q update && \
    apt-get -qy --no-install-recommends install iproute2 iptables && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY runmasscanned /usr/local/bin/runmasscanned

CMD /usr/local/bin/runmasscanned
