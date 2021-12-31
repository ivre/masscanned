// This file is part of masscanned.
// Copyright 2021 - The IVRE project
//
// Masscanned is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Masscanned is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
// License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Masscanned. If not, see <http://www.gnu.org/licenses/>.

use log::*;

use chrono::Utc;
use lazy_static::lazy_static;
use std::str;

use crate::client::ClientInfo;
use crate::proto::TCPControlBlock;
use crate::smack::{
    Smack, SmackFlags, BASE_STATE, NO_MATCH, SMACK_CASE_INSENSITIVE, UNANCHORED_STATE,
};
use crate::Masscanned;

pub const HTTP_VERBS: [&str; 9] = [
    "GET", "PUT", "POST", "HEAD", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH",
];

#[derive(Copy, Clone)]
enum HttpField {
    Verb,
    // Incomplete,
    // Server,
    ContentLength,
    ContentType,
    // Via,
    // Location,
    Unknown,
    NewLine,
}

const HTTP_STATE_START: usize = 0;
const HTTP_STATE_VERB: usize = 1;
const HTTP_STATE_SPACE: usize = 2;
const HTTP_STATE_URI: usize = 3;
const HTTP_STATE_H: usize = 4;
const HTTP_STATE_T1: usize = 5;
const HTTP_STATE_T2: usize = 6;
const HTTP_STATE_P: usize = 7;
const HTTP_STATE_SLASH: usize = 8;
const HTTP_STATE_VERSION_MAJ: usize = 9;
const HTTP_STATE_VERSION_MIN: usize = 10;

const HTTP_STATE_FIELD_START: usize = 32;
const HTTP_STATE_FIELD_NAME: usize = 33;
const HTTP_STATE_FIELD_VALUE: usize = 34;
const HTTP_STATE_CONTENT: usize = 64;

const HTTP_STATE_FAIL: usize = 0xFFFF;

pub struct ProtocolState {
    state: usize,
    state_bis: usize,
    smack_state: usize,
    smack_id: usize,
    http_verb: Vec<u8>,
    http_uri: Vec<u8>,
}

impl ProtocolState {
    fn new() -> Self {
        ProtocolState {
            state: HTTP_STATE_START,
            state_bis: 0,
            smack_state: BASE_STATE,
            smack_id: NO_MATCH,
            http_verb: Vec::<u8>::new(),
            http_uri: Vec::<u8>::new(),
        }
    }
}

const HTTP_PATTERN: [(&str, HttpField, SmackFlags); 4] = [
    (
        "Content-Length",
        HttpField::ContentLength,
        SmackFlags::ANCHOR_BEGIN,
    ),
    (
        "Content-Type",
        HttpField::ContentType,
        SmackFlags::ANCHOR_BEGIN,
    ),
    (":", HttpField::Unknown, SmackFlags::EMPTY),
    ("\n", HttpField::NewLine, SmackFlags::EMPTY),
];

lazy_static! {
    static ref HTTP_SMACK: Smack = http_init();
}

fn http_init() -> Smack {
    let mut smack = Smack::new("http".to_string(), SMACK_CASE_INSENSITIVE);
    for verb in HTTP_VERBS.iter() {
        smack.add_pattern(
            verb.as_bytes(),
            HttpField::Verb as usize,
            SmackFlags::ANCHOR_BEGIN,
        );
    }
    for p in HTTP_PATTERN.iter() {
        smack.add_pattern(p.0.as_bytes(), p.1 as usize, p.2);
    }
    smack.compile();
    smack
}

fn http_parse(pstate: &mut ProtocolState, data: &[u8]) {
    /* RFC 2616:
     * The Request-Line begins with a method token, followed by the
     * Request-URI and the protocol version, and ending with CRLF. The
     * elements are separated by SP characters. No CR or LF is allowed
     * except in the final CRLF sequence.
     */
    let mut i = 0;
    while i < data.len() {
        match pstate.state {
            HTTP_STATE_START => {
                pstate.state += 1;
                continue;
            }
            HTTP_STATE_VERB => {
                let i_save = i;
                pstate.smack_id = HTTP_SMACK.search_next(&mut pstate.smack_state, data, &mut i);
                pstate.http_verb.extend_from_slice(&data[i_save..i]);
                i -= 1;
                if pstate.smack_id == HttpField::Verb as usize {
                    pstate.state += 1;
                } else if pstate.smack_id == NO_MATCH {
                    /* if in UNANCHORED_STATE, it means we'll never get a match from now on */
                    if pstate.smack_state == UNANCHORED_STATE {
                        pstate.state = HTTP_STATE_FAIL;
                    } else {
                        /* continue getting input */
                    }
                }
            }
            HTTP_STATE_SPACE => {
                if data[i] == b' ' {
                    pstate.state += 1;
                } else {
                    pstate.state = HTTP_STATE_FAIL;
                }
            }
            HTTP_STATE_URI => {
                if data[i] != b' ' {
                    pstate.http_uri.push(data[i]);
                } else {
                    pstate.state += 1;
                }
            }
            HTTP_STATE_H | HTTP_STATE_T1 | HTTP_STATE_T2 | HTTP_STATE_P | HTTP_STATE_SLASH => {
                if data[i] != b"HTTP/"[pstate.state - HTTP_STATE_H] {
                    pstate.state = HTTP_STATE_FAIL;
                } else {
                    pstate.state += 1;
                }
            }
            HTTP_STATE_VERSION_MAJ => {
                if data[i] == b'.' {
                    pstate.state += 1;
                } else if !data[i].is_ascii_digit() {
                    pstate.state = HTTP_STATE_FAIL;
                }
            }
            HTTP_STATE_VERSION_MIN => {
                /* ignore \r to be compliant with relaxed implementations of the protocole */
                if data[i] == b'\r' {
                } else if data[i] == b'\n' {
                    pstate.state = HTTP_STATE_FIELD_START;
                } else if !data[i].is_ascii_digit() {
                    pstate.state = HTTP_STATE_FAIL;
                }
            }
            HTTP_STATE_FIELD_START => {
                if data[i] == b'\r' {
                } else if data[i] == b'\n' {
                    pstate.state_bis = 0;
                    pstate.state = HTTP_STATE_CONTENT;
                } else {
                    pstate.state_bis = 0;
                    pstate.state = HTTP_STATE_FIELD_NAME;
                }
            }
            HTTP_STATE_FIELD_NAME => {
                if data[i] == b'\r' || data[i] == b'\n' {
                    pstate.state = HTTP_STATE_FAIL;
                } else if data[i] == b':' {
                    pstate.state = HTTP_STATE_FIELD_VALUE;
                }
            }
            HTTP_STATE_FIELD_VALUE => {
                if data[i] == b'\r' {
                } else if data[i] == b'\n' {
                    pstate.state = HTTP_STATE_FIELD_START;
                }
            }
            HTTP_STATE_FAIL => {
                return;
            }
            HTTP_STATE_CONTENT => { /* so far, do not parse content */ }
            _ => {}
        };
        i += 1;
    }
}

pub fn repl<'a>(
    data: &'a [u8],
    _masscanned: &Masscanned,
    _client_info: &ClientInfo,
    _tcb: Option<&mut TCPControlBlock>,
) -> Option<Vec<u8>> {
    debug!("receiving HTTP data");
    let mut pstate = ProtocolState::new();
    http_parse(&mut pstate, data);
    if pstate.state == HTTP_STATE_FAIL {
        debug!("data in not correctly formatted - not responding");
        debug!("pstate: {}", pstate.state);
        return None;
    }
    /* if not in CONTENT state, not responding yet (it means the client
     * has not finished sending headers yet) */
    if pstate.state != HTTP_STATE_CONTENT {
        return None;
    }
    let content = "\
<html>
<head><title>401 Authorization Required</title></head>
<body bgcolor=\"white\">
<center><h1>401 Authorization Required</h1></center>
<hr><center>nginx/1.14.2</center>
</body>
</html>
";
    let repl_data = format!(
        "\
HTTP/1.1 401 Unauthorized
Server: nginx/1.14.2
Date: {}
Content-Type: text/html
Content-Length: {}
Connection: keep-alive
WWW-Authenticate: Basic realm=\"Access to admin page\"

{}
",
        Utc::now().to_rfc2822(),
        content.len(),
        content
    )
    .into_bytes();
    debug!("sending HTTP data");
    warn!(
        "HTTP/1.1 401 to {} {}",
        str::from_utf8(&pstate.http_verb).unwrap(),
        str::from_utf8(&pstate.http_uri).unwrap()
    );
    Some(repl_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_verb() {
        /* all at once */
        for verb in HTTP_VERBS.iter() {
            let mut pstate = ProtocolState::new();
            assert!(pstate.state == HTTP_STATE_START);
            assert!(pstate.smack_state == BASE_STATE);
            assert!(pstate.smack_id == NO_MATCH);
            http_parse(&mut pstate, &verb.as_bytes());
            assert!(pstate.state == HTTP_STATE_SPACE);
            assert!(pstate.smack_id == (HttpField::Verb as usize));
            assert!(pstate.http_verb == verb.as_bytes());
        }
        /* byte by byte */
        for verb in HTTP_VERBS.iter() {
            let mut pstate = ProtocolState::new();
            assert!(pstate.state == HTTP_STATE_START);
            assert!(pstate.smack_state == BASE_STATE);
            assert!(pstate.smack_id == NO_MATCH);
            for i in 0..verb.len() {
                if i > 0 {
                    assert!(pstate.state == HTTP_STATE_VERB);
                    assert!(pstate.smack_id == NO_MATCH);
                }
                http_parse(&mut pstate, &verb.as_bytes()[i..i + 1]);
            }
            assert!(pstate.state == HTTP_STATE_SPACE);
            assert!(pstate.smack_id == (HttpField::Verb as usize));
            assert!(pstate.http_verb == verb.as_bytes());
        }
        /* KO test: XXX */
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == HTTP_STATE_START);
        assert!(pstate.smack_state == BASE_STATE);
        assert!(pstate.smack_id == NO_MATCH);
        http_parse(&mut pstate, "XXX".as_bytes());
        assert!(pstate.state == HTTP_STATE_FAIL);
        assert!(pstate.smack_state == UNANCHORED_STATE);
        assert!(pstate.smack_id == NO_MATCH);
        /* KO test: XGET */
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == HTTP_STATE_START);
        assert!(pstate.smack_state == BASE_STATE);
        assert!(pstate.smack_id == NO_MATCH);
        http_parse(&mut pstate, "XGET".as_bytes());
        assert!(pstate.state == HTTP_STATE_FAIL);
        assert!(pstate.smack_state == UNANCHORED_STATE);
        assert!(pstate.smack_id == NO_MATCH);
        /* KO test: GEX */
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == HTTP_STATE_START);
        assert!(pstate.smack_state == BASE_STATE);
        assert!(pstate.smack_id == NO_MATCH);
        http_parse(&mut pstate, "GEX".as_bytes());
        assert!(pstate.state == HTTP_STATE_FAIL);
        assert!(pstate.smack_state == UNANCHORED_STATE);
        assert!(pstate.smack_id == NO_MATCH);
        /* KO test: GE T */
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == HTTP_STATE_START);
        assert!(pstate.smack_state == BASE_STATE);
        assert!(pstate.smack_id == NO_MATCH);
        http_parse(&mut pstate, "GE T".as_bytes());
        assert!(pstate.state == HTTP_STATE_FAIL);
        assert!(pstate.smack_state == UNANCHORED_STATE);
        assert!(pstate.smack_id == NO_MATCH);
    }

    #[test]
    fn test_http_request_line() {
        let mut pstate = ProtocolState::new();
        let data = "GET /index.php HTTP/1.1\r\n".as_bytes();
        for i in 0..data.len() {
            http_parse(&mut pstate, &data[i..i + 1]);
            if i < 2 {
                assert!(pstate.state == HTTP_STATE_VERB);
            } else if i == 2 {
                assert!(pstate.state == HTTP_STATE_SPACE);
            } else if 3 <= i && i <= 13 {
                assert!(pstate.state == HTTP_STATE_URI);
            } else if 14 <= i && i <= 19 {
                assert!(pstate.state == HTTP_STATE_H + (i - 14));
            } else if i == 20 {
                assert!(pstate.state == HTTP_STATE_VERSION_MAJ);
            } else if 21 <= i && i <= 23 {
                assert!(pstate.state == HTTP_STATE_VERSION_MIN);
            } else if i == 24 {
                assert!(pstate.state == HTTP_STATE_FIELD_START);
            }
        }
    }

    #[test]
    fn test_http_request_field() {
        let mut pstate = ProtocolState::new();
        let req = "POST /index.php HTTP/2.0\r\n".as_bytes();
        http_parse(&mut pstate, req);
        assert!(pstate.state == HTTP_STATE_FIELD_START);
        let field = b"Content-Length";
        http_parse(&mut pstate, field);
        assert!(pstate.state == HTTP_STATE_FIELD_NAME);
        let dot = b": ";
        http_parse(&mut pstate, dot);
        assert!(pstate.state == HTTP_STATE_FIELD_VALUE);
        let value = b": 0\r\n";
        http_parse(&mut pstate, value);
        assert!(pstate.state == HTTP_STATE_FIELD_START);
    }

    #[test]
    fn test_http_request_no_field() {
        let mut pstate = ProtocolState::new();
        let req = "POST /index.php HTTP/2.0\r\n".as_bytes();
        http_parse(&mut pstate, req);
        assert!(pstate.state == HTTP_STATE_FIELD_START);
        let crlf = "\r\n".as_bytes();
        http_parse(&mut pstate, crlf);
        assert!(pstate.state == HTTP_STATE_CONTENT);
    }
}
