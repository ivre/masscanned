use crate::client::ClientInfo;
use siphasher::sip::SipHasher24;
use std::convert::TryInto;
use std::hash::Hasher;
use std::io;
use std::net::IpAddr;

pub fn generate(client_info: &ClientInfo, key: &[u64; 2]) -> Result<u32, io::Error> {
    /* check parameters */
    /* ip fields must not be None */
    if client_info.ip.src == None || client_info.ip.dst == None {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "IP addresses must not be None",
        ));
    }
    /* port fields must not be None */
    if client_info.port.src == None || client_info.port.dst == None {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Ports must not be None",
        ));
    }
    let mut sip = SipHasher24::new_with_keys(key[0], key[1]);
    /* check IPAddr type */
    if let Some(IpAddr::V6(s)) = client_info.ip.src {
        if let Some(IpAddr::V6(d)) = client_info.ip.dst {
            sip.write_u128(s.into());
            sip.write_u128(d.into());
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "The two IP addresses (src and dst) must be of same type",
            ));
        }
    } else if let Some(IpAddr::V4(s)) = client_info.ip.src {
        if let Some(IpAddr::V4(d)) = client_info.ip.dst {
            sip.write_u32(s.into());
            sip.write_u32(d.into());
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "The two IP addresses (src and dst) must be of same type",
            ));
        }
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Unknown data type",
        ));
    }
    sip.write_u16(client_info.port.src.unwrap());
    sip.write_u16(client_info.port.dst.unwrap());
    Ok((sip.finish() & 0xFFFFFFFF).try_into().unwrap())
}

pub fn _check(client_info: &ClientInfo, val: u32, key: &[u64; 2]) -> bool {
    if let Ok(cookie) = generate(client_info, &key) {
        cookie == val
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::ClientInfoSrcDst;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_ip4() {
        let key = [0xfb3818fcf501729d, 0xeb3b3e8720618e69];
        let ip_src = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
        let ip_dst = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let tcp_sport = 65000;
        let tcp_dport = 80;
        let client_info = ClientInfo {
            mac: ClientInfoSrcDst {
                src: None,
                dst: None,
            },
            ip: ClientInfoSrcDst {
                src: Some(ip_src),
                dst: Some(ip_dst),
            },
            transport: None,
            port: ClientInfoSrcDst {
                src: Some(tcp_sport),
                dst: Some(tcp_dport),
            },
            cookie: None,
        };
        let res = generate(&client_info, &key);
        if let Ok(_) = res {
            assert!(true);
        } else {
            assert!(false);
        }
    }

    #[test]
    fn test_ip6() {
        let key = [0x6b794087697b9180, 0x0c149aa303534b02];
        let ip_src = IpAddr::V6(Ipv6Addr::new(
            0xe50f, 0xe521, 0x70a2, 0xa3b3, 0x2135, 0x52d9, 0x6a0d, 0xe215,
        ));
        let ip_dst = IpAddr::V6(Ipv6Addr::new(
            0xc2eb, 0x33cf, 0x2c15, 0x4f7a, 0x7085, 0x492c, 0x2dbc, 0xf35b,
        ));
        let tcp_sport = 65000;
        let tcp_dport = 80;
        let client_info = ClientInfo {
            mac: ClientInfoSrcDst {
                src: None,
                dst: None,
            },
            ip: ClientInfoSrcDst {
                src: Some(ip_src),
                dst: Some(ip_dst),
            },
            transport: None,
            port: ClientInfoSrcDst {
                src: Some(tcp_sport),
                dst: Some(tcp_dport),
            },
            cookie: None,
        };
        let res = generate(&client_info, &key);
        if let Ok(_) = res {
            assert!(true);
        } else {
            assert!(false);
        }
    }

    #[test]
    fn test_clientinfo() {
        let key = [0x0b1a8621b0caf88d, 0x677cc071dab41639];
        let err = Err(io::ErrorKind::InvalidInput);
        /* all ok */
        let ip_src = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
        let ip_dst = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let tcp_sport = 65000;
        let tcp_dport = 80;
        let mut client_info = ClientInfo {
            mac: ClientInfoSrcDst {
                src: None,
                dst: None,
            },
            ip: ClientInfoSrcDst {
                src: Some(ip_src),
                dst: Some(ip_dst),
            },
            transport: None,
            port: ClientInfoSrcDst {
                src: Some(tcp_sport),
                dst: Some(tcp_dport),
            },
            cookie: None,
        };
        let res = generate(&client_info, &key);
        if let Ok(_) = res {
            assert!(true);
        } else {
            assert!(false);
        }
        /* ip src is None */
        client_info.ip.src = None;
        let res = generate(&client_info, &key);
        assert_eq!(res.map_err(|e| e.kind()), err);
        client_info.ip.src = Some(ip_src);
        /* ip dst is None */
        client_info.ip.dst = None;
        let res = generate(&client_info, &key);
        assert_eq!(res.map_err(|e| e.kind()), err);
        client_info.ip.dst = Some(ip_dst);
        /* port src is None */
        client_info.port.src = None;
        let res = generate(&client_info, &key);
        assert_eq!(res.map_err(|e| e.kind()), err);
        client_info.port.src = Some(tcp_sport);
        /* port dst is None */
        client_info.port.dst = None;
        let res = generate(&client_info, &key);
        assert_eq!(res.map_err(|e| e.kind()), err);
        client_info.port.dst = Some(tcp_dport);
    }

    #[test]
    fn test_key() {
        /* reference */
        let ref_key = [0x1e9219e0b0e0b44c, 0x9e460bcddf4eaac9];
        let ip_src = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
        let ip_dst = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let tcp_sport = 65000;
        let tcp_dport = 80;
        let client_info = ClientInfo {
            mac: ClientInfoSrcDst {
                src: None,
                dst: None,
            },
            ip: ClientInfoSrcDst {
                src: Some(ip_src),
                dst: Some(ip_dst),
            },
            transport: None,
            port: ClientInfoSrcDst {
                src: Some(tcp_sport),
                dst: Some(tcp_dport),
            },
            cookie: None,
        };
        let ref_cookie = generate(&client_info, &ref_key).unwrap();
        assert!(_check(&client_info, ref_cookie, &ref_key));
        /* change key */
        let key = [0xc98a8cb8579004d4, 0x8b53a2735381ded4];
        let cookie = generate(&client_info, &key).unwrap();
        assert_ne!(ref_key, key);
        assert_ne!(cookie, ref_cookie);
        assert!(_check(&client_info, cookie, &key));
        assert!(!_check(&client_info, ref_cookie, &key));
        assert!(!_check(&client_info, cookie, &ref_key));
    }

    #[test]
    fn test_ip4_src() {
        let key = [0x77b781aaeca4f0d1, 0x7481d7251789d247];
        /* reference */
        let ip_src = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
        let ip_dst = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let tcp_sport = 65000;
        let tcp_dport = 80;
        let mut client_info = ClientInfo {
            mac: ClientInfoSrcDst {
                src: None,
                dst: None,
            },
            ip: ClientInfoSrcDst {
                src: Some(ip_src),
                dst: Some(ip_dst),
            },
            transport: None,
            port: ClientInfoSrcDst {
                src: Some(tcp_sport),
                dst: Some(tcp_dport),
            },
            cookie: None,
        };
        let ref_cookie = generate(&client_info, &key).unwrap();
        assert!(_check(&client_info, ref_cookie, &key));
        client_info.ip.src = Some(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 1)));
        let cookie = generate(&client_info, &key).unwrap();
        assert!(_check(&client_info, cookie, &key));
        assert!(!_check(&client_info, ref_cookie, &key));
        assert_ne!(cookie, ref_cookie);
    }

    #[test]
    fn test_ip4_dst() {
        let key = [0xe2ada0ff90978791, 0xb18586de261db429];
        /* reference */
        let ip_src = IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2));
        let ip_dst = IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3));
        let tcp_sport = 65000;
        let tcp_dport = 80;
        let mut client_info = ClientInfo {
            mac: ClientInfoSrcDst {
                src: None,
                dst: None,
            },
            ip: ClientInfoSrcDst {
                src: Some(ip_src),
                dst: Some(ip_dst),
            },
            transport: None,
            port: ClientInfoSrcDst {
                src: Some(tcp_sport),
                dst: Some(tcp_dport),
            },
            cookie: None,
        };
        let ref_cookie = generate(&client_info, &key).unwrap();
        assert!(_check(&client_info, ref_cookie, &key));
        client_info.ip.dst = Some(IpAddr::V4(Ipv4Addr::new(4, 4, 3, 3)));
        let cookie = generate(&client_info, &key).unwrap();
        assert!(_check(&client_info, cookie, &key));
        assert!(!_check(&client_info, ref_cookie, &key));
        assert_ne!(cookie, ref_cookie);
    }

    #[test]
    fn test_tcp_src() {
        let key = [0xda0e06f5916b0a24, 0x754a8c2f23106b5f];
        /* reference */
        let ip_src = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let ip_dst = IpAddr::V4(Ipv4Addr::new(3, 4, 3, 4));
        let tcp_sport = 65000;
        let tcp_dport = 443;
        let mut client_info = ClientInfo {
            mac: ClientInfoSrcDst {
                src: None,
                dst: None,
            },
            ip: ClientInfoSrcDst {
                src: Some(ip_src),
                dst: Some(ip_dst),
            },
            transport: None,
            port: ClientInfoSrcDst {
                src: Some(tcp_sport),
                dst: Some(tcp_dport),
            },
            cookie: None,
        };
        let ref_cookie = generate(&client_info, &key).unwrap();
        assert!(_check(&client_info, ref_cookie, &key));
        client_info.port.src = Some(12345);
        let cookie = generate(&client_info, &key).unwrap();
        assert!(_check(&client_info, cookie, &key));
        assert!(!_check(&client_info, ref_cookie, &key));
        assert_ne!(cookie, ref_cookie);
    }

    #[test]
    fn test_tcp_dst() {
        let key = [0x85fa7e3f1cd254b7, 0xcfce5e92a7bb7595];
        /* reference */
        let ip_src = IpAddr::V4(Ipv4Addr::new(200, 210, 220, 230));
        let ip_dst = IpAddr::V4(Ipv4Addr::new(172, 48, 14, 103));
        let tcp_sport = 65000;
        let tcp_dport = 443;
        let mut client_info = ClientInfo {
            mac: ClientInfoSrcDst {
                src: None,
                dst: None,
            },
            ip: ClientInfoSrcDst {
                src: Some(ip_src),
                dst: Some(ip_dst),
            },
            transport: None,
            port: ClientInfoSrcDst {
                src: Some(tcp_sport),
                dst: Some(tcp_dport),
            },
            cookie: None,
        };
        let ref_cookie = generate(&client_info, &key).unwrap();
        assert!(_check(&client_info, ref_cookie, &key));
        client_info.port.dst = Some(80);
        let cookie = generate(&client_info, &key).unwrap();
        assert!(_check(&client_info, cookie, &key));
        assert!(!_check(&client_info, ref_cookie, &key));
        assert_ne!(cookie, ref_cookie);
    }
}
