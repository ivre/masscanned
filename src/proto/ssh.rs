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

use crate::client::ClientInfo;
use crate::proto::TCPControlBlock;
use crate::utils::byte2str;
use crate::Masscanned;

pub const SSH_PATTERN_CLIENT_PROTOCOL_2: &[u8; 7] = b"SSH-2.0";
pub const SSH_PATTERN_CLIENT_PROTOCOL_1: &[u8; 8] = b"SSH-1.99";

const SSH_STATE_START: usize = 0;
const SSH_STATE_S1: usize = 1;
const SSH_STATE_S2: usize = 2;
const SSH_STATE_H: usize = 3;
const SSH_STATE_DASH: usize = 4;
const SSH_STATE_VERSION: usize = 5;
const SSH_STATE_SOFTWARE: usize = 6;
const SSH_STATE_COMMENT: usize = 7;
const SSH_STATE_EOB: usize = 8;
const SSH_STATE_LF: usize = 9;

const SSH_STATE_FAIL: usize = 0xFFFF;

struct ProtocolState {
    state: usize,
    prev_state: usize,
    ssh_version: Vec<u8>,
    ssh_software: Vec<u8>,
    ssh_comment: Vec<u8>,
}

impl ProtocolState {
    fn new() -> Self {
        ProtocolState {
            state: SSH_STATE_START,
            prev_state: SSH_STATE_START,
            ssh_version: Vec::<u8>::new(),
            ssh_software: Vec::<u8>::new(),
            ssh_comment: Vec::<u8>::new(),
        }
    }
}

fn ssh_parse(pstate: &mut ProtocolState, data: &[u8]) {
    /* RFC 4253:
     *
     * 4.2.  Protocol Version Exchange
     *
     *    When the connection has been established, both sides MUST send an
     *    identification string.  This identification string MUST be
     *
     *       SSH-protoversion-softwareversion SP comments CR LF
     *
     *    Since the protocol being defined in this set of documents is version
     *    2.0, the 'protoversion' MUST be "2.0".  The 'comments' string is
     *    OPTIONAL.  If the 'comments' string is included, a 'space' character
     *    (denoted above as SP, ASCII 32) MUST separate the 'softwareversion'
     *    and 'comments' strings.  The identification MUST be terminated by a
     *    single Carriage Return (CR) and a single Line Feed (LF) character
     *    (ASCII 13 and 10, respectively).  Implementers who wish to maintain
     *    compatibility with older, undocumented versions of this protocol may
     *    want to process the identification string without expecting the
     *    presence of the carriage return character for reasons described in
     *    Section 5 of this document.  The null character MUST NOT be sent.
     *    The maximum length of the string is 255 characters, including the
     *    Carriage Return and Line Feed.
     */
    let mut i = 0;
    while i < data.len() {
        match pstate.state {
            SSH_STATE_START => {
                pstate.state = SSH_STATE_S1;
                continue;
            }
            /* first bytes should be "SSH-" */
            SSH_STATE_S1 | SSH_STATE_S2 | SSH_STATE_H | SSH_STATE_DASH => {
                if data[i] != b"SSH-"[pstate.state - SSH_STATE_S1] {
                    pstate.state = SSH_STATE_FAIL;
                } else {
                    pstate.state += 1;
                }
            }
            /* expect LF after a CR was read */
            SSH_STATE_LF => {
                if data[i] == b'\n' {
                    pstate.state = SSH_STATE_EOB;
                } else {
                    if pstate.prev_state == SSH_STATE_SOFTWARE {
                        /* when reading software, \r can be followed by something else than \n */
                        pstate.state = pstate.prev_state;
                        /* cancel the read of this char */
                        i -= 1;
                        /* add the previously read \r to the software string */
                        pstate.ssh_software.push(b'\r');
                    } else if pstate.prev_state == SSH_STATE_COMMENT {
                        /* when reading comment, \r can be followed by something else than \n */
                        pstate.state = pstate.prev_state;
                        /* cancel the read of this char */
                        i -= 1;
                        /* add the previously read \r to the software string */
                        pstate.ssh_comment.push(b'\r');
                    } else {
                        /* in some other cases, it fails */
                        pstate.state = SSH_STATE_FAIL;
                    }
                }
            }
            SSH_STATE_VERSION => {
                if data[i] == b'-' {
                    pstate.state = SSH_STATE_SOFTWARE;
                } else if !data[i].is_ascii_digit() && data[i] != b'.' {
                    pstate.state = SSH_STATE_FAIL;
                } else {
                    pstate.ssh_version.push(data[i]);
                }
            }
            SSH_STATE_SOFTWARE => {
                if data[i] == b'\r' {
                    /* look for LF in the next char */
                    pstate.prev_state = pstate.state;
                    pstate.state = SSH_STATE_LF;
                } else if data[i] == b' ' {
                    pstate.state = SSH_STATE_COMMENT;
                } else {
                    pstate.ssh_software.push(data[i]);
                }
            }
            SSH_STATE_COMMENT => {
                if data[i] == b'\r' {
                    /* look for LF in the next char */
                    pstate.prev_state = pstate.state;
                    pstate.state = SSH_STATE_LF;
                } else {
                    pstate.ssh_comment.push(data[i]);
                }
            }
            SSH_STATE_FAIL => {
                return;
            }
            SSH_STATE_EOB => { /* so far, do not parse after banner */ }
            _ => {}
        };
        i += 1;
    }
}

pub fn repl<'a>(
    data: &'a [u8],
    _masscanned: &Masscanned,
    mut _client_info: &ClientInfo,
    _tcb: Option<&mut TCPControlBlock>,
) -> Option<Vec<u8>> {
    debug!("receiving SSH data");
    let mut pstate = ProtocolState::new();
    ssh_parse(&mut pstate, data);
    if pstate.state != SSH_STATE_EOB {
        debug!("data in not correctly formatted - not responding");
        debug!("pstate: {}", pstate.state);
        return None;
    }
    let repl_data = b"SSH-2.0-1\r\n".to_vec();
    debug!("sending SSH answer");
    warn!(
        "SSH server banner to {}",
        std::str::from_utf8(&pstate.ssh_software).unwrap().trim_end()
    );
    Some(repl_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_2_banner_parse() {
        /* all at once */
        let test_banner = b"SSH-2.0-SOFTWARE COMMENT\r\n";
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == SSH_STATE_START);
        ssh_parse(&mut pstate, test_banner);
        assert!(pstate.state == SSH_STATE_EOB);
        assert!(pstate.ssh_version == b"2.0");
        assert!(pstate.ssh_software == b"SOFTWARE");
        assert!(pstate.ssh_comment == b"COMMENT");
        /* byte by byte */
        let test_banner = b"SSH-2.0-SOFTWARE COMMENT\r\n";
        let mut pstate = ProtocolState::new();
        for i in 0..test_banner.len() {
            if i == 0 {
                assert!(pstate.state == SSH_STATE_START);
            } else if i > 0 && i < 4 {
                assert!(pstate.state == SSH_STATE_S1 + i);
            } else if i >= 4 && i < 8 {
                assert!(pstate.state == SSH_STATE_VERSION);
            } else if i >= 8 && i < 17 {
                assert!(pstate.state == SSH_STATE_SOFTWARE);
            } else if i >= 17 && i < test_banner.len() - 1 {
                assert!(pstate.state == SSH_STATE_COMMENT);
            } else {
                assert!(pstate.state == SSH_STATE_LF);
            }
            ssh_parse(&mut pstate, &test_banner[i..i + 1]);
        }
        assert!(pstate.state == SSH_STATE_EOB);
        assert!(pstate.ssh_version == b"2.0");
        assert!(pstate.ssh_software == b"SOFTWARE");
        assert!(pstate.ssh_comment == b"COMMENT");
    }

    #[test]
    fn ssh_1_banner_parse() {
        /* all at once */
        let test_banner = b"SSH-1.99-SOFTWARE COMMENT\r\n";
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == SSH_STATE_START);
        ssh_parse(&mut pstate, test_banner);
        assert!(pstate.state == SSH_STATE_EOB);
        assert!(pstate.ssh_version == b"1.99");
        assert!(pstate.ssh_software == b"SOFTWARE");
        assert!(pstate.ssh_comment == b"COMMENT");
        /* byte by byte */
        let test_banner = b"SSH-1.99-SOFTWARE COMMENT\r\n";
        let mut pstate = ProtocolState::new();
        for i in 0..test_banner.len() {
            if i == 0 {
                assert!(pstate.state == SSH_STATE_START);
            } else if i > 0 && i < 4 {
                assert!(pstate.state == SSH_STATE_S1 + i);
            } else if i >= 4 && i < 9 {
                assert!(pstate.state == SSH_STATE_VERSION);
            } else if i >= 9 && i < 18 {
                assert!(pstate.state == SSH_STATE_SOFTWARE);
            } else if i >= 18 && i < test_banner.len() - 1 {
                assert!(pstate.state == SSH_STATE_COMMENT);
            } else {
                assert!(pstate.state == SSH_STATE_LF);
            }
            ssh_parse(&mut pstate, &test_banner[i..i + 1]);
        }
        assert!(pstate.state == SSH_STATE_EOB);
        assert!(pstate.ssh_version == b"1.99");
        assert!(pstate.ssh_software == b"SOFTWARE");
        assert!(pstate.ssh_comment == b"COMMENT");
    }

    #[test]
    fn ssh_2_banner_space() {
        /* space in SSH */
        let test_banner = b"S SH-2.0-SOFTWARE COMMENT\r\n";
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == SSH_STATE_START);
        ssh_parse(&mut pstate, test_banner);
        assert!(pstate.state == SSH_STATE_FAIL);
        /* space in VERSION */
        let test_banner = b"SSH-2. 0-SOFTWARE COMMENT\r\n";
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == SSH_STATE_START);
        ssh_parse(&mut pstate, test_banner);
        assert!(pstate.state == SSH_STATE_FAIL);
        /* space in software */
        let test_banner = b"SSH-2.0-SOFT WARE COMMENT\r\n";
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == SSH_STATE_START);
        ssh_parse(&mut pstate, test_banner);
        assert!(pstate.state == SSH_STATE_EOB);
        assert!(pstate.ssh_version == b"2.0");
        assert!(pstate.ssh_software == b"SOFT");
        assert!(pstate.ssh_comment == b"WARE COMMENT");
        /* space in comment */
        let test_banner = b"SSH-2.0-SOFTWARE COM MENT\r\n";
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == SSH_STATE_START);
        ssh_parse(&mut pstate, test_banner);
        assert!(pstate.state == SSH_STATE_EOB);
        assert!(pstate.ssh_version == b"2.0");
        assert!(pstate.ssh_software == b"SOFTWARE");
        assert!(pstate.ssh_comment == b"COM MENT");
        /* double space */
        let test_banner = b"SSH-2.0-SOFTWARE  COMMENT\r\n";
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == SSH_STATE_START);
        ssh_parse(&mut pstate, test_banner);
        assert!(pstate.state == SSH_STATE_EOB);
        assert!(pstate.ssh_version == b"2.0");
        assert!(pstate.ssh_software == b"SOFTWARE");
        assert!(pstate.ssh_comment == b" COMMENT");
    }

    #[test]
    fn ssh_1_banner_space() {
        /* space in SSH */
        let test_banner = b"S SH-1.99-SOFTWARE COMMENT\r\n";
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == SSH_STATE_START);
        ssh_parse(&mut pstate, test_banner);
        assert!(pstate.state == SSH_STATE_FAIL);
        /* space in VERSION */
        let test_banner = b"SSH-1. 99-SOFTWARE COMMENT\r\n";
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == SSH_STATE_START);
        ssh_parse(&mut pstate, test_banner);
        assert!(pstate.state == SSH_STATE_FAIL);
        /* space in software */
        let test_banner = b"SSH-1.99-SOFT WARE COMMENT\r\n";
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == SSH_STATE_START);
        ssh_parse(&mut pstate, test_banner);
        assert!(pstate.state == SSH_STATE_EOB);
        assert!(pstate.ssh_version == b"1.99");
        assert!(pstate.ssh_software == b"SOFT");
        assert!(pstate.ssh_comment == b"WARE COMMENT");
        /* space in comment */
        let test_banner = b"SSH-1.99-SOFTWARE COM MENT\r\n";
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == SSH_STATE_START);
        ssh_parse(&mut pstate, test_banner);
        assert!(pstate.state == SSH_STATE_EOB);
        assert!(pstate.ssh_version == b"1.99");
        assert!(pstate.ssh_software == b"SOFTWARE");
        assert!(pstate.ssh_comment == b"COM MENT");
        /* double space */
        let test_banner = b"SSH-1.99-SOFTWARE  COMMENT\r\n";
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == SSH_STATE_START);
        ssh_parse(&mut pstate, test_banner);
        assert!(pstate.state == SSH_STATE_EOB);
        assert!(pstate.ssh_version == b"1.99");
        assert!(pstate.ssh_software == b"SOFTWARE");
        assert!(pstate.ssh_comment == b" COMMENT");
    }

    #[test]
    fn ssh_2_banner_cr() {
        /* CR in SSH */
        let test_banner = b"S\rSH-2.0-SOFTWARE COMMENT\r\n";
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == SSH_STATE_START);
        ssh_parse(&mut pstate, test_banner);
        assert!(pstate.state == SSH_STATE_FAIL);
        /* CR in VERSION */
        let test_banner = b"SSH-2.\r0-SOFTWARE COMMENT\r\n";
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == SSH_STATE_START);
        ssh_parse(&mut pstate, test_banner);
        assert!(pstate.state == SSH_STATE_FAIL);
        /* CR in SOFTWARE */
        let test_banner = b"SSH-2.0-SOFT\rWARE COMMENT\r\n";
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == SSH_STATE_START);
        ssh_parse(&mut pstate, test_banner);
        assert!(pstate.state == SSH_STATE_EOB);
        assert!(pstate.ssh_version == b"2.0");
        assert!(pstate.ssh_software == b"SOFT\rWARE");
        assert!(pstate.ssh_comment == b"COMMENT");
        /* CR in COMMENT */
        let test_banner = b"SSH-2.0-SOFTWARE COM\rMENT\r\n";
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == SSH_STATE_START);
        ssh_parse(&mut pstate, test_banner);
        assert!(pstate.state == SSH_STATE_EOB);
        assert!(pstate.ssh_version == b"2.0");
        assert!(pstate.ssh_software == b"SOFTWARE");
        assert!(pstate.ssh_comment == b"COM\rMENT");
        /* CR at the end */
        let test_banner = b"SSH-2.0-SOFTWARE COMMENT\r\r\n";
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == SSH_STATE_START);
        ssh_parse(&mut pstate, test_banner);
        assert!(pstate.state == SSH_STATE_EOB);
        assert!(pstate.ssh_version == b"2.0");
        assert!(pstate.ssh_software == b"SOFTWARE");
        assert!(pstate.ssh_comment == b"COMMENT\r");
    }

    #[test]
    fn ssh_1_banner_cr() {
        /* CR in SSH */
        let test_banner = b"S\rSH-1.99-SOFTWARE COMMENT\r\n";
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == SSH_STATE_START);
        ssh_parse(&mut pstate, test_banner);
        assert!(pstate.state == SSH_STATE_FAIL);
        /* CR in VERSION */
        let test_banner = b"SSH-1.\r99-SOFTWARE COMMENT\r\n";
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == SSH_STATE_START);
        ssh_parse(&mut pstate, test_banner);
        assert!(pstate.state == SSH_STATE_FAIL);
        /* CR in SOFTWARE */
        let test_banner = b"SSH-1.99-SOFT\rWARE COMMENT\r\n";
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == SSH_STATE_START);
        ssh_parse(&mut pstate, test_banner);
        assert!(pstate.state == SSH_STATE_EOB);
        assert!(pstate.ssh_version == b"1.99");
        assert!(pstate.ssh_software == b"SOFT\rWARE");
        assert!(pstate.ssh_comment == b"COMMENT");
        /* CR in COMMENT */
        let test_banner = b"SSH-1.99-SOFTWARE COM\rMENT\r\n";
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == SSH_STATE_START);
        ssh_parse(&mut pstate, test_banner);
        assert!(pstate.state == SSH_STATE_EOB);
        assert!(pstate.ssh_version == b"1.99");
        assert!(pstate.ssh_software == b"SOFTWARE");
        assert!(pstate.ssh_comment == b"COM\rMENT");
        /* CR at the end */
        let test_banner = b"SSH-1.99-SOFTWARE COMMENT\r\r\n";
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == SSH_STATE_START);
        ssh_parse(&mut pstate, test_banner);
        assert!(pstate.state == SSH_STATE_EOB);
        assert!(pstate.ssh_version == b"1.99");
        assert!(pstate.ssh_software == b"SOFTWARE");
        assert!(pstate.ssh_comment == b"COMMENT\r");
    }

    #[test]
    fn ssh_2_banner_lf() {
        /* LF in SSH */
        let test_banner = b"S\nSH-2.0-SOFTWARE COMMENT\r\n";
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == SSH_STATE_START);
        ssh_parse(&mut pstate, test_banner);
        assert!(pstate.state == SSH_STATE_FAIL);
        /* LF in VERSION */
        let test_banner = b"SSH-2.\n0-SOFTWARE COMMENT\r\n";
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == SSH_STATE_START);
        ssh_parse(&mut pstate, test_banner);
        assert!(pstate.state == SSH_STATE_FAIL);
        /* LF in SOFTWARE */
        let test_banner = b"SSH-2.0-SOFT\nWARE COMMENT\r\n";
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == SSH_STATE_START);
        ssh_parse(&mut pstate, test_banner);
        assert!(pstate.state == SSH_STATE_EOB);
        assert!(pstate.ssh_version == b"2.0");
        assert!(pstate.ssh_software == b"SOFT\nWARE");
        assert!(pstate.ssh_comment == b"COMMENT");
        /* LF in COMMENT */
        let test_banner = b"SSH-2.0-SOFTWARE COM\nMENT\r\n";
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == SSH_STATE_START);
        ssh_parse(&mut pstate, test_banner);
        assert!(pstate.state == SSH_STATE_EOB);
        assert!(pstate.ssh_version == b"2.0");
        assert!(pstate.ssh_software == b"SOFTWARE");
        assert!(pstate.ssh_comment == b"COM\nMENT");
        /* LF at the end */
        let test_banner = b"SSH-2.0-SOFTWARE COMMENT\n\r\n";
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == SSH_STATE_START);
        ssh_parse(&mut pstate, test_banner);
        assert!(pstate.state == SSH_STATE_EOB);
        assert!(pstate.ssh_version == b"2.0");
        assert!(pstate.ssh_software == b"SOFTWARE");
        assert!(pstate.ssh_comment == b"COMMENT\n");
    }

    #[test]
    fn ssh_1_banner_lf() {
        /* LF in SSH */
        let test_banner = b"S\nSH-1.99-SOFTWARE COMMENT\r\n";
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == SSH_STATE_START);
        ssh_parse(&mut pstate, test_banner);
        assert!(pstate.state == SSH_STATE_FAIL);
        /* LF in VERSION */
        let test_banner = b"SSH-1.\n99-SOFTWARE COMMENT\r\n";
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == SSH_STATE_START);
        ssh_parse(&mut pstate, test_banner);
        assert!(pstate.state == SSH_STATE_FAIL);
        /* LF in SOFTWARE */
        let test_banner = b"SSH-1.99-SOFT\nWARE COMMENT\r\n";
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == SSH_STATE_START);
        ssh_parse(&mut pstate, test_banner);
        assert!(pstate.state == SSH_STATE_EOB);
        assert!(pstate.ssh_version == b"1.99");
        assert!(pstate.ssh_software == b"SOFT\nWARE");
        assert!(pstate.ssh_comment == b"COMMENT");
        /* LF in COMMENT */
        let test_banner = b"SSH-1.99-SOFTWARE COM\nMENT\r\n";
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == SSH_STATE_START);
        ssh_parse(&mut pstate, test_banner);
        assert!(pstate.state == SSH_STATE_EOB);
        assert!(pstate.ssh_version == b"1.99");
        assert!(pstate.ssh_software == b"SOFTWARE");
        assert!(pstate.ssh_comment == b"COM\nMENT");
        /* LF at the end */
        let test_banner = b"SSH-1.99-SOFTWARE COMMENT\n\r\n";
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == SSH_STATE_START);
        ssh_parse(&mut pstate, test_banner);
        assert!(pstate.state == SSH_STATE_EOB);
        assert!(pstate.ssh_version == b"1.99");
        assert!(pstate.ssh_software == b"SOFTWARE");
        assert!(pstate.ssh_comment == b"COMMENT\n");
    }

    #[test]
    fn ssh_2_banner_crlf() {
        /* CRLF in SSH */
        let test_banner = b"S\r\nSH-2.0-SOFTWARE COMMENT\r\n";
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == SSH_STATE_START);
        ssh_parse(&mut pstate, test_banner);
        assert!(pstate.state == SSH_STATE_FAIL);
        /* CRLF in VERSION */
        let test_banner = b"SSH-2.\r\n0-SOFTWARE COMMENT\r\n";
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == SSH_STATE_START);
        ssh_parse(&mut pstate, test_banner);
        assert!(pstate.state == SSH_STATE_FAIL);
        /* CRLF in SOFTWARE */
        let test_banner = b"SSH-2.0-SOFT\r\nWARE COMMENT\r\n";
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == SSH_STATE_START);
        ssh_parse(&mut pstate, test_banner);
        assert!(pstate.state == SSH_STATE_EOB);
        assert!(pstate.ssh_version == b"2.0");
        assert!(pstate.ssh_software == b"SOFT");
        assert!(pstate.ssh_comment == b"");
        /* CRLF in COMMENT */
        let test_banner = b"SSH-2.0-SOFTWARE COM\r\nMENT\r\n";
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == SSH_STATE_START);
        ssh_parse(&mut pstate, test_banner);
        assert!(pstate.state == SSH_STATE_EOB);
        assert!(pstate.ssh_version == b"2.0");
        assert!(pstate.ssh_software == b"SOFTWARE");
        assert!(pstate.ssh_comment == b"COM");
        /* CRLF at the end */
        let test_banner = b"SSH-2.0-SOFTWARE COMMENT\r\n\r\n";
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == SSH_STATE_START);
        ssh_parse(&mut pstate, test_banner);
        assert!(pstate.state == SSH_STATE_EOB);
        assert!(pstate.ssh_version == b"2.0");
        assert!(pstate.ssh_software == b"SOFTWARE");
        assert!(pstate.ssh_comment == b"COMMENT");
    }

    #[test]
    fn ssh_1_banner_crlf() {
        /* CRLF in SSH */
        let test_banner = b"S\r\nSH-1.99-SOFTWARE COMMENT\r\n";
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == SSH_STATE_START);
        ssh_parse(&mut pstate, test_banner);
        assert!(pstate.state == SSH_STATE_FAIL);
        /* CRLF in VERSION */
        let test_banner = b"SSH-1.\r\n99-SOFTWARE COMMENT\r\n";
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == SSH_STATE_START);
        ssh_parse(&mut pstate, test_banner);
        assert!(pstate.state == SSH_STATE_FAIL);
        /* CRLF in SOFTWARE */
        let test_banner = b"SSH-1.99-SOFT\r\nWARE COMMENT\r\n";
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == SSH_STATE_START);
        ssh_parse(&mut pstate, test_banner);
        assert!(pstate.state == SSH_STATE_EOB);
        assert!(pstate.ssh_version == b"1.99");
        assert!(pstate.ssh_software == b"SOFT");
        assert!(pstate.ssh_comment == b"");
        /* CRLF in COMMENT */
        let test_banner = b"SSH-1.99-SOFTWARE COM\r\nMENT\r\n";
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == SSH_STATE_START);
        ssh_parse(&mut pstate, test_banner);
        assert!(pstate.state == SSH_STATE_EOB);
        assert!(pstate.ssh_version == b"1.99");
        assert!(pstate.ssh_software == b"SOFTWARE");
        assert!(pstate.ssh_comment == b"COM");
        /* CRLF at the end */
        let test_banner = b"SSH-1.99-SOFTWARE COMMENT\r\n\r\n";
        let mut pstate = ProtocolState::new();
        assert!(pstate.state == SSH_STATE_START);
        ssh_parse(&mut pstate, test_banner);
        assert!(pstate.state == SSH_STATE_EOB);
        assert!(pstate.ssh_version == b"1.99");
        assert!(pstate.ssh_software == b"SOFTWARE");
        assert!(pstate.ssh_comment == b"COMMENT");
    }
}
