[![Build masscanned](https://github.com/ivre/masscanned/actions/workflows/test.yml/badge.svg?branch=master)](https://github.com/ivre/masscanned/actions/workflows/test.yml?branch=master)

# Masscanned

**Masscanned** (name inspired, of course, by [masscan](https://github.com/robertdavidgraham/masscan))
is a network responder. Its purpose is to provide generic answers to as many protocols as possible,
and with as few assumptions as possible on the client's intentions.

> *Let them talk first.*

Just like [masscan](https://github.com/robertdavidgraham/masscan), **masscanned** implements its own,
userland network stack, similarly to [honeyd](http://honeyd.org/). It is designed to interact
with scanners and opportunistic bots as far as possible, and to support as many protocols as possible.

For example, when it receives network packets:

* **masscanned** answers to `ARP who is-at` with `ARP is-at` (for its IP addresses),
* **masscanned** answers to `ICMP Echo Request` with `ICMP Echo Reply`,
* **masscanned** answers to `TCP SYN` (any port) with `TCP SYN/ACK` on any port,
* **masscanned** answers to `HTTP` requests (any verb) over `TCP/UDP` (any port) with a `HTTP 401` web page.

![demo](doc/img/demo.gif)

## Overview

**Masscanned** currently supports most common protocols at layers 2-3-4, and a few application
protocols.

### Network protocols

* ARP (answers to ARP requests)
* ICMP (answers to ping) 
* ICMPv6 (answers to ND NS) 
* TCP (answers to SYN and PUSH)

### Application protocols

* HTTP (answers to all verbs)
* SSH (answers to the client banner)
* STUN (answers to binding requests)
* SMB
* DNS (answers to IN/A queries)

## Try it locally

1. Build **masscanned**
```
$ cargo build
```
2. Create a new net namespace
```
# ip netns add masscanned
```
3. Create veth between the two namespaces
```
# ip link add vethmasscanned type veth peer veth netns masscanned
# ip link set vethmasscanned up
# ip -n masscanned link set veth up
```
4. Set IP on local veth to have a route for outgoing packets
```
# ip addr add dev vethmasscanned 192.168.0.0/31
```
5. Run **masscanned** in the namespace
```
# ip netns exec masscanned ./target/debug/masscanned --iface veth -v[vv]
```
6. With another terminal, send packets to **masscanned**
```
# arping 192.168.0.1
# ping 192.168.0.1
# nc -n -v 192.168.0.1 80
# nc -n -v -u 192.168.0.1 80
...
```

## Use it

A good use of **masscanned** is to deploy it on a VPS with one or more public IP addresses.

To use the results, the best way is to capture all network traffic on the interface **masscanned** is listening to/responding on.
The pcaps can then be analyzed using [zeek](https://zeek.org/) and the output files can typically be pushed in an instance of **IVRE**.

A documentation on how to deploy an instance of **masscanned** on a VPS is coming (see [Issue #2](https://github.com/ivre/masscanned/issues/2)).

## Supported protocols - details

### Layer 2

#### ARP

`masscanned` anwsers to `ARP` requests, for requests that target an `IPv4` address
that is handled by `masscanned` (*i.e.*, an address that is in the 
IP address file given with option `-f`).

The answer contains the first of the following possible `MAC` addresses:

* the `MAC` address specified with `-a` in command line if any,
* the `MAC` address of the interface specified with `-i` in command line if any,
* or the `masscanned` default `MAC` address, *i.e.*, `c0:ff:ee:c0:ff:ee`.

#### Ethernet

`masscanned` answers to `Ethernet` frames, if and only if the following requirements are met:

* the destination address of the frame should be handled by `masscanned`, which means:
    
    * `masscanned` own `MAC` address,
    * the broadcast `MAC` address `ff:ff:ff:ff:ff:ff`,
    * a multicast `MAC` address corresponding to one of the `IPv4` addresses handled by `masscanned` ([RFC 1112](https://datatracker.ietf.org/doc/html/rfc1112)),
    * a multicast `MAC` address corresponding to one of the `IPv6` addresses handled by `masscanned` ;

* `EtherType` field is one of `ARP`, `IPv4` or `IPv6`.

**Note:** even for a non-multicast IP address, `masscanned` will respond to L2 frames addressed to the corresponding multicast `MAC` address.
For instance, if `masscanned` handles `10.11.12.13`, it will answer to frames addressed to `01:00:5e:0b:0c:0d`.

### Layer 3

#### IPv4/IPv6

`masscanned` answers to `IPv4` and `IPv6` packets, only if:

* no `IP` address is specified in a file (*i.e.*, no `-f` option is specified or the file is empty),

**or**

* the destination IP address of the incoming packet is one of the IP addresses handled by `masscanned`.

An additionnal requirement is that the next layer protocol is supported - see below.

#### IPv4

The following L3+/4 protocols are supported for an `IPv4` packet:

* `ICMPv4`
* `UDP`
* `TCP`

If the next layer protocol is not one of them, the packet is dropped.

#### IPv6

The following L3+/4 protocols are supported for an `IPv6` packet:

* `ICMPv6`
* `UDP`
* `TCP`

If the next layer protocol is not one of them, the packet is dropped.

### Layer 3+/4

#### ICMPv4

`masscanned` answers to `ICMPv4` packets if and only if:

* the `ICMP` type of the incoming packet is `EchoRequest` (`8`),
* the `ICMP` code of the incoming packet is `0`.

If these conditions are met, `masscanned` answers with an `ICMP` packet of type `EchoReply` (`0`), 
code `0` and the same payload as the incoming packet, as specified by [RFC 792](https://datatracker.ietf.org/doc/html/rfc792).

#### ICMPv6

`masscanned` answers to `ICMPv6` packets if and only if:

* the `ICMP` type is `NeighborSol` (`135`) **and**:
    * no IP (v4 or v6) was speficied for `masscanned`
    * **or** the target address of the Neighbor Solicitation is one of `masscanned`

*In that case, the answer is a `Neighbor Advertisement` (`136`) packet with `masscanned` `MAC` address*

**or**

*  the `ICMP` type is `EchoRequest` (`128`)

*In that case, the answer is a `EchoReply` (`129`) packet.*

#### TCP

`masscanned` answers to the following `TCP` packets:

* if the received packet has flags `PSH` and `ACK`, `masscanned` checks the **SYNACK-cookie**, and if valid answers at least a `ACK`, or a `PSH-ACK` if
a supported protocol (Layer 5/6/7) has been detected,
* if the received packet has flag `ACK`, it is ignored,
* if the received packet has flag `RST` or `FIN-ACK`, it is ignored,
* if the received packet has flag `SYN`, then `masscanned` answers with a `SYN-ACK` packet, setting a **SYNACK-cookie** in the sequence number.  

#### UDP

`masscanned` answers to an `UDP` packet if and only if the upper-layer protocol
is handled and provides an answer.

### Application protocols

#### HTTP

`masscanned` answers to any `HTTP` request (any **valid** verb) with a `401 Authorization Required`.
Note that `HTTP` requests with an invalid verb will not be answered.

Example:

```
$ curl -X GET 10.11.10.129
<html>
<head><title>401 Authorization Required</title></head>
<body bgcolor="white">
<center><h1>401 Authorization Required</h1></center>
<hr><center>nginx/1.14.2</center>
</body>
</html>
$ curl -X OPTIONS 10.11.10.129
<html>
<head><title>401 Authorization Required</title></head>
<body bgcolor="white">
<center><h1>401 Authorization Required</h1></center>
<hr><center>nginx/1.14.2</center>
</body>
</html>
$ curl -X HEAD 10.11.10.129
Warning: Setting custom HTTP method to HEAD with -X/--request may not work the 
Warning: way you want. Consider using -I/--head instead.
<html>
<head><title>401 Authorization Required</title></head>
<body bgcolor="white">
<center><h1>401 Authorization Required</h1></center>
<hr><center>nginx/1.14.2</center>
</body>
</html>
$ curl -X XXX 10.11.10.129
[timeout]
```

#### STUN

Example:

```
$ stun 10.11.10.129
STUN client version 0.97
Primary: Open
Return value is 0x000001
```

#### SSH

`masscanned` answers to `SSH` `Client: Protocol` messages with the following `Server: Protocol` message:

```
SSH-2.0-1\r\n
```

#### SMB

`masscanned` answers to `Negotiate Protocol Request` packets in order for the
client to send a `NTLMSSP_NEGOTIATE`, to which `masscanned` answers with a challenge.

Example:

```
##$ smbclient -U user \\\\10.11.10.129\\shared
Enter WORKGROUP\user's password: 
```

#### DNS

`masscanned` answers to `DNS` queries of class `IN` and type `A` (for now).
The answer it provides always contains the IP address the query was sent to.

Example:

```
$ host -t A masscan.ned 10.11.10.129
Using domain server:
Name: 10.11.10.129
Address: 10.11.10.129#53
Aliases: 

masscan.ned has address 10.11.10.129
$ host -t A masscan.ned 10.11.10.130
Using domain server:
Name: 10.11.10.130
Address: 10.11.10.130#53
Aliases: 

masscan.ned has address 10.11.10.130
$ host -t A masscan.ned 10.11.10.131
Using domain server:
Name: 10.11.10.131
Address: 10.11.10.131#53
Aliases: 

masscan.ned has address 10.11.10.131
$ host -t A masscan.ned 10.11.10.132
Using domain server:
Name: 10.11.10.132
Address: 10.11.10.132#53
Aliases: 

masscan.ned has address 10.11.10.132

```

## Internals

### Tests

#### Unit tests

```
$ cargo test
   Compiling masscanned v0.2.0 (/zdata/workdir/masscanned)
    Finished test [unoptimized + debuginfo] target(s) in 3.83s
     Running unittests (target/debug/deps/masscanned-f9292f8600038978)

running 92 tests
test client::client_info::tests::test_client_info_eq ... ok
test layer_2::arp::tests::test_arp_reply ... ok
test layer_2::tests::test_eth_empty ... ok
test layer_2::tests::test_eth_reply ... ok
test layer_3::ipv4::tests::test_ipv4_reply ... ok
test layer_3::ipv4::tests::test_ipv4_empty ... ok
test layer_3::ipv6::tests::test_ipv6_empty ... ok
test layer_3::ipv6::tests::test_ipv6_reply ... ok
test layer_4::icmpv4::tests::test_icmpv4_reply ... ok
test layer_4::icmpv6::tests::test_icmpv6_reply ... ok
test layer_4::icmpv6::tests::test_nd_na_reply ... ok
test layer_4::tcp::tests::test_synack_cookie_ipv6 ... ok
test layer_4::tcp::tests::test_tcp_fin_ack_wrap ... ok
test proto::dns::cst::tests::class_parse ... ok
test layer_4::tcp::tests::test_tcp_fin_ack ... ok
test layer_4::tcp::tests::test_synack_cookie_ipv4 ... ok
test proto::dns::cst::tests::type_parse ... ok
test proto::dns::header::tests::parse_byte_by_byte ... ok
test proto::dns::header::tests::repl_id ... ok
test proto::dns::header::tests::repl_opcode ... ok
test proto::dns::header::tests::repl_ancount ... ok
test proto::dns::header::tests::repl_rd ... ok
test proto::dns::query::tests::parse_in_a_all ... ok
test proto::dns::header::tests::parse_all ... ok
test proto::dns::query::tests::repl ... ok
test proto::dns::query::tests::reply_in_a ... ok
test proto::dns::rr::tests::parse_all ... ok
test proto::dns::rr::tests::parse_byte_by_byte ... ok
test proto::dns::query::tests::parse_in_a_byte_by_byte ... ok
test proto::dns::tests::parse_qd_all ... ok
test proto::dns::tests::parse_qd_byte_by_byte ... ok
test proto::dns::rr::tests::build ... ok
test proto::dns::tests::parse_qd_rr_all ... ok
test proto::dns::tests::parse_qr_rr_byte_by_byte ... ok
test proto::dns::tests::parse_rr_byte_by_byte ... ok
test proto::dns::tests::parse_rr_all ... ok
test proto::dns::tests::reply_in_a ... ok
test proto::http::tests::test_http_request_line ... ok
test proto::http::tests::test_http_request_no_field ... ok
test proto::http::tests::test_http_request_field ... ok
test proto::http::tests::test_http_verb ... ok
test proto::rpc::tests::test_probe_nmap ... ok
test proto::rpc::tests::test_probe_nmap_split1 ... ok
test proto::rpc::tests::test_probe_portmap_v4_dump ... ok
test proto::rpc::tests::test_probe_nmap_split2 ... ok
test proto::rpc::tests::test_probe_nmap_udp ... ok
test proto::smb::tests::test_smb1_session_setup_request_parse ... ok
test proto::smb::tests::test_smb1_protocol_nego_parsing ... ok
test proto::smb::tests::test_smb1_protocol_nego_reply ... ok
test proto::smb::tests::test_smb1_session_setup_request_reply ... ok
test proto::smb::tests::test_smb2_protocol_nego_parsing ... ok
test proto::smb::tests::test_smb2_protocol_nego_reply ... ok
test proto::smb::tests::test_smb2_session_setup_request_reply ... ok
test proto::smb::tests::test_smb2_session_setup_request_parse ... ok
test proto::ssh::tests::ssh_1_banner_cr ... ok
test proto::ssh::tests::ssh_1_banner_crlf ... ok
test proto::ssh::tests::ssh_1_banner_lf ... ok
test proto::ssh::tests::ssh_1_banner_space ... ok
test proto::ssh::tests::ssh_2_banner_cr ... ok
test proto::ssh::tests::ssh_1_banner_parse ... ok
test proto::ssh::tests::ssh_2_banner_parse ... ok
test proto::ssh::tests::ssh_2_banner_lf ... ok
test proto::ssh::tests::ssh_2_banner_crlf ... ok
test proto::stun::tests::test_change_request_port_overflow ... ok
test proto::stun::tests::test_proto_stun_ipv4 ... ok
test proto::stun::tests::test_change_request_port ... ok
test proto::ssh::tests::ssh_2_banner_space ... ok
test proto::stun::tests::test_proto_stun_ipv6 ... ok
test proto::tcb::tests::test_proto_tcb_proto_state_http ... ok
test proto::tests::dispatch_dns ... ok
test proto::tcb::tests::test_proto_tcb_proto_state_rpc ... ok
test proto::tcb::tests::test_proto_tcb_proto_id ... ok
test proto::tests::test_proto_dispatch_http ... ok
test proto::tests::test_proto_dispatch_ssh ... ok
test proto::tests::test_proto_dispatch_ghost ... ok
test proto::tests::test_proto_dispatch_stun ... ok
test smack::smack::tests::test_anchor_end ... ok
test smack::smack::tests::test_multiple_matches_wildcard ... ok
test smack::smack::tests::test_multiple_matches ... ok
test smack::smack::tests::test_anchor_begin ... ok
test smack::smack::tests::test_http_banner ... ok
test synackcookie::tests::test_clientinfo ... ok
test synackcookie::tests::test_ip4 ... ok
test synackcookie::tests::test_ip4_dst ... ok
test synackcookie::tests::test_ip4_src ... ok
test synackcookie::tests::test_ip6 ... ok
test synackcookie::tests::test_key ... ok
test synackcookie::tests::test_tcp_dst ... ok
test synackcookie::tests::test_tcp_src ... ok
test smack::smack::tests::test_wildcard ... ok
test smack::smack::tests::test_proto ... ok
test smack::smack::tests::test_pattern ... ok

test result: ok. 92 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.41s
```

#### Functional tests

```
# ./test/test_masscanned.py
INFO    test_arp_req......................................OK
INFO    test_arp_req_other_ip.............................OK
INFO    test_ipv4_udp_dns_in_a............................OK
INFO    test_ipv4_udp_dns_in_a_multiple_queries...........OK
INFO    test_ipv4_tcp_ghost...............................OK
INFO    test_ipv4_tcp_http................................OK
INFO    test_ipv4_tcp_http_segmented......................OK
INFO    test_ipv4_tcp_http_incomplete.....................OK
INFO    test_ipv6_tcp_http................................OK
INFO    test_ipv4_udp_http................................OK
INFO    test_ipv6_udp_http................................OK
INFO    test_ipv4_tcp_http_ko.............................OK
INFO    test_ipv4_udp_http_ko.............................OK
INFO    test_ipv6_tcp_http_ko.............................OK
INFO    test_ipv6_udp_http_ko.............................OK
INFO    test_icmpv4_echo_req..............................OK
INFO    test_icmpv6_neighbor_solicitation.................OK
INFO    test_icmpv6_neighbor_solicitation_other_ip........OK
INFO    test_icmpv6_echo_req..............................OK
INFO    test_ipv4_req.....................................OK
INFO    test_eth_req_other_mac............................OK
INFO    test_ipv4_req_other_ip............................OK
INFO    test_rpc_nmap.....................................OK
INFO    test_rpcinfo......................................OK
INFO    test_smb1_network_req.............................OK
INFO    test_smb2_network_req.............................OK
INFO    test_ipv4_tcp_ssh.................................OK
INFO    test_ipv4_udp_ssh.................................OK
INFO    test_ipv6_tcp_ssh.................................OK
INFO    test_ipv6_udp_ssh.................................OK
INFO    test_ipv4_udp_stun................................OK
INFO    test_ipv6_udp_stun................................OK
INFO    test_ipv4_udp_stun_change_port....................OK
INFO    test_ipv6_udp_stun_change_port....................OK
INFO    test_ipv4_tcp_empty...............................OK
INFO    test_ipv6_tcp_empty...............................OK
INFO    test_tcp_syn......................................OK
INFO    test_ipv4_tcp_psh_ack.............................OK
INFO    test_ipv6_tcp_psh_ack.............................OK
INFO    test_ipv4_udp_empty...............................OK
INFO    test_ipv6_udp_empty...............................OK
INFO    Ran 41 tests with 0 errors
```

You can also chose what tests to run using the `TESTS` environment variable
```
TESTS=smb ./test/test_masscanned.py
INFO    test_smb1_network_req.............................OK
INFO    test_smb2_network_req.............................OK
INFO    Ran 2 tests with 0 errors
```

## Logging

### Console Logger

**Verbs**: 
* `init`
* `recv`
* `send`
* `drop`

#### ARP

```
$ts arp $verb   $operation $client_mac $client_ip  $masscanned_mac $masscanned_ip
```

#### Ethernet

```
$ts eth $verb   $ethertype  $client_mac $masscanned_mac
```

## To Do

* Drop incoming packets if checksum is incorrect
* Fix source address when answering to multicast packets.
