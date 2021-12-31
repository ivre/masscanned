use std::mem;

use crate::smack::smack_constants::*;
use crate::smack::smack_pattern::SmackPattern;
use crate::smack::smack_queue::SmackQueue;
use crate::smack::smack_utils::{row_shift_from_symbol_count, SmackFlags};

struct SmackRow {
    next_state: Vec<usize>,
    fail: usize,
}

impl SmackRow {
    fn new() -> Self {
        SmackRow {
            next_state: vec![BASE_STATE; ALPHABET_SIZE],
            fail: 0,
        }
    }
}

struct SmackMatches {
    m_ids: Vec<usize>,
    m_count: usize,
}

impl SmackMatches {
    fn new() -> Self {
        SmackMatches {
            m_ids: Vec::new(),
            m_count: 0,
        }
    }
    fn copy_matches(&mut self, new_ids: Vec<usize>) {
        for id in &new_ids {
            if !self.m_ids.contains(id) {
                self.m_count += 1;
                self.m_ids.push(*id)
            }
        }
    }
}

pub struct Smack {
    _name: String,
    is_nocase: bool,
    is_anchor_begin: bool,
    is_anchor_end: bool,
    m_pattern_list: Vec<SmackPattern>,
    m_pattern_count: usize,
    m_state_table: Vec<SmackRow>,
    m_state_count: usize,
    m_state_max: usize,
    m_match: Vec<SmackMatches>,
    m_match_limit: usize,
    symbol_to_char: Vec<usize>,
    char_to_symbol: Vec<u8>,
    symbol_count: usize,
    row_shift: usize,
    transitions: Vec<usize>,
}

fn make_copy_of_pattern(pattern: &[u8], is_nocase: bool) -> Vec<u8> {
    let mut p = pattern.clone().to_vec();
    for i in 0..p.len() {
        if is_nocase {
            p[i] = p[i].to_ascii_lowercase();
        }
    }
    p
}

impl Smack {
    pub fn new(name: String, nocase: bool) -> Self {
        Smack {
            _name: name,
            is_nocase: nocase,
            is_anchor_begin: false,
            is_anchor_end: false,
            m_pattern_list: Vec::new(),
            m_pattern_count: 0,
            m_state_table: Vec::new(),
            m_state_count: 0,
            m_state_max: 0,
            m_match: Vec::new(),
            m_match_limit: 0,
            symbol_to_char: vec![0; ALPHABET_SIZE],
            char_to_symbol: vec![0; ALPHABET_SIZE],
            symbol_count: 0,
            row_shift: 0,
            transitions: Vec::new(),
        }
    }
    fn create_intermediate_table(&mut self, size: usize) {
        for _ in 0..size {
            self.m_state_table.push(SmackRow::new());
        }
    }
    fn create_matches_table(&mut self, size: usize) {
        for _ in 0..size {
            self.m_match.push(SmackMatches::new());
        }
    }
    fn add_symbol(&mut self, c: usize) -> usize {
        for i in 1..self.symbol_count + 1 {
            if self.symbol_to_char[i] == c {
                return i;
            }
        }
        self.symbol_count += 1;
        let symbol = self.symbol_count;
        self.symbol_to_char[symbol] = c;
        self.char_to_symbol[c] = symbol.to_le_bytes()[0];
        symbol
    }
    fn add_symbols(&mut self, pattern: &[u8]) {
        for c in pattern {
            if self.is_nocase {
                self.add_symbol(c.to_ascii_lowercase().into());
            } else {
                self.add_symbol((*c).into());
            }
        }
    }
    pub fn add_pattern(&mut self, pattern: &[u8], id: usize, flags: SmackFlags) {
        let p = SmackPattern::new(make_copy_of_pattern(pattern, self.is_nocase), id, flags);
        if p.is_anchor_begin {
            self.is_anchor_begin = true;
        }
        if p.is_anchor_end {
            self.is_anchor_end = true;
        }
        self.add_symbols(&p.pattern);
        self.m_pattern_list.push(p);
        self.m_pattern_count += 1;
    }
    fn set_goto(&mut self, r: usize, a: usize, h: usize) {
        self.m_state_table[r].next_state[a] = h;
    }
    fn goto(&self, r: usize, a: usize) -> usize {
        self.m_state_table[r].next_state[a]
    }
    fn set_goto_fail(&mut self, r: usize, h: usize) {
        self.m_state_table[r].fail = h;
    }
    fn goto_fail(&self, r: usize) -> usize {
        self.m_state_table[r].fail
    }
    fn new_state(&mut self) -> usize {
        self.m_state_count += 1;
        self.m_state_count - 1
    }
    fn add_prefixes(&mut self, p: &SmackPattern) {
        let mut state = BASE_STATE;
        let pattern = &p.pattern;
        if p.is_anchor_begin {
            state = self.goto(state, CHAR_ANCHOR_START);
        }
        let mut i = 0;
        while i < pattern.len() && self.goto(state, pattern[i].into()) != FAIL_STATE {
            state = self.goto(state, pattern[i].into());
            i += 1;
        }
        while i < pattern.len() {
            let new_state = self.new_state();
            self.set_goto(state, pattern[i].into(), new_state);
            state = new_state;
            i += 1;
        }
        if p.is_anchor_end {
            let new_state = self.new_state();
            self.set_goto(state, CHAR_ANCHOR_END, new_state);
            state = new_state;
        }
        self.m_match[state].copy_matches(vec![p.id]);
    }
    fn stage0_compile_prefixes(&mut self) {
        self.m_state_count = 1;
        for s in 0..self.m_state_max {
            for a in 0..ALPHABET_SIZE {
                self.set_goto(s, a, FAIL_STATE);
            }
        }
        if self.is_anchor_begin {
            let anchor_begin = self.new_state();
            self.set_goto(BASE_STATE, CHAR_ANCHOR_START, anchor_begin);
        }
        let plist = mem::replace(&mut self.m_pattern_list, Vec::new());
        for p in plist.iter() {
            self.add_prefixes(&p);
        }
        self.m_pattern_list = plist;
        for a in 0..ALPHABET_SIZE {
            if self.goto(BASE_STATE, a) == FAIL_STATE {
                self.set_goto(BASE_STATE, a, BASE_STATE);
            }
        }
    }
    fn stage1_generate_fails(&mut self) {
        let mut queue: SmackQueue<usize> = SmackQueue::new();
        for a in 0..ALPHABET_SIZE {
            let s = self.goto(BASE_STATE, a);
            if s != BASE_STATE {
                queue.enqueue(s);
                self.set_goto_fail(s, BASE_STATE);
            }
        }
        while queue.has_more_items() {
            let r = queue.dequeue();
            for a in 0..ALPHABET_SIZE {
                let s = self.goto(r, a);
                if s == FAIL_STATE {
                    continue;
                }
                if s == r {
                    continue;
                }
                queue.enqueue(s);
                let mut f = self.goto_fail(r);
                while self.goto(f, a) == FAIL_STATE {
                    f = self.goto_fail(f);
                }
                self.set_goto_fail(s, self.goto(f, a));
                if self.m_match[self.goto(f, a)].m_count > 0 {
                    let gt = self.goto(f, a);
                    let m = mem::take(&mut self.m_match[gt].m_ids);
                    self.m_match[s].copy_matches(m.clone());
                    self.m_match[gt].m_ids = m;
                }
            }
        }
    }
    fn stage2_link_fails(&mut self) {
        let mut queue = SmackQueue::new();
        for a in 0..ALPHABET_SIZE {
            if self.goto(BASE_STATE, a) != BASE_STATE {
                queue.enqueue(self.goto(BASE_STATE, a));
            }
        }
        loop {
            if !queue.has_more_items() {
                break;
            }
            let r = queue.dequeue();
            for a in 0..ALPHABET_SIZE {
                if self.goto(r, a) == FAIL_STATE {
                    self.set_goto(r, a, self.goto(self.goto_fail(r), a));
                } else if self.goto(r, a) == r {
                } else {
                    queue.enqueue(self.goto(r, a));
                }
            }
        }
    }
    fn swap_rows(&mut self, row1: usize, row2: usize) {
        let tmp = mem::replace(&mut self.m_state_table[row1], SmackRow::new());
        self.m_state_table[row1] = mem::replace(&mut self.m_state_table[row2], tmp);
        let tmp = mem::replace(&mut self.m_match[row1], SmackMatches::new());
        self.m_match[row1] = mem::replace(&mut self.m_match[row2], tmp);
        for s in 0..self.m_state_count {
            for a in 0..ALPHABET_SIZE {
                if self.goto(s, a) == row1 {
                    self.set_goto(s, a, row2);
                } else if self.goto(s, a) == row2 {
                    self.set_goto(s, a, row1);
                }
            }
        }
    }
    fn stage3_sort(&mut self) {
        let mut start = 0;
        let mut end = self.m_state_count;
        loop {
            while start < end && self.m_match[start].m_count == 0 {
                start += 1;
            }
            while start < end && self.m_match[end - 1].m_count != 0 {
                end -= 1;
            }
            if start >= end {
                break;
            }
            self.swap_rows(start, end - 1);
        }
        self.m_match_limit = start;
    }
    fn stage4_make_final_table(&mut self) {
        let row_count = self.m_state_count;
        self.row_shift = row_shift_from_symbol_count(self.symbol_count);
        let column_count = 1 << self.row_shift;
        self.transitions = vec![0; row_count * column_count];
        for row in 0..row_count {
            for c in 0..ALPHABET_SIZE {
                let symbol = usize::from(self.char_to_symbol[c]);
                let transition = self.goto(row, c);
                self.transitions[row * column_count + symbol] = transition;
            }
        }
    }
    fn fixup_wildcards(&mut self) {
        for i in 0..self.m_pattern_count {
            let p = &self.m_pattern_list[i];
            if !p.is_wildcards {
                continue;
            }
            for j in 0..p.pattern.len() {
                let mut row = 0;
                let mut offset = 0;
                let row_size = 1 << self.row_shift;
                let base_state = if self.is_anchor_begin {
                    UNANCHORED_STATE
                } else {
                    BASE_STATE
                };
                if p.pattern[j] != b'*' {
                    continue;
                }
                while offset < j {
                    self.search_next(&mut row, &p.pattern[..j], &mut offset);
                }
                row &= 0xFFFFFF;
                let next_pattern = self.transitions
                    [(row << self.row_shift) + usize::from(self.char_to_symbol[usize::from(b'*')])];
                for k in 0..row_size {
                    if self.transitions[(row << self.row_shift) + k] == base_state {
                        self.transitions[(row << self.row_shift) + k] = next_pattern;
                    }
                }
            }
        }
    }
    fn inner_match(&self, px: Vec<u8>, length: usize, state: usize) -> (usize, usize) {
        let px_start = 0;
        let px_end = length;
        let mut row = state;
        let mut idx = px_start;
        while idx < px_end {
            let column: usize = self.char_to_symbol[usize::from(px[idx])].into();
            row = self.transitions[(row << self.row_shift) + column];
            if row >= self.m_match_limit {
                break;
            }
            idx += 1;
        }
        (idx - px_start, row)
    }
    fn inner_match_shift7(&self, px: Vec<u8>, length: usize, state: usize) -> (usize, usize) {
        let px_start = 0;
        let px_end = length;
        let mut row = state;
        let mut idx = px_start;
        while idx < px_end {
            let column: usize = self.char_to_symbol[usize::from(px[idx])].into();
            row = self.transitions[(row << 7) + column];
            if row >= self.m_match_limit {
                break;
            }
            idx += 1;
        }
        (idx - px_start, row)
    }
    pub fn search_next(&self, current_state: &mut usize, v_px: &[u8], offset: &mut usize) -> usize {
        let px = v_px;
        let length = px.len();
        let mut i = *offset;
        let mut id = NO_MATCH;
        let mut row = *current_state & 0xFFFFFF;
        let mut current_matches = *current_state >> 24;
        if current_matches == 0 {
            if self.row_shift == 7 {
                let (ii, new_row) = self.inner_match_shift7(px[i..].to_vec(), length - i, row);
                i += ii;
                row = new_row;
            } else {
                let (ii, new_row) = self.inner_match(px[i..].to_vec(), length - i, row);
                i += ii;
                row = new_row;
            }
            if self.m_match[row].m_count != 0 {
                i += 1;
                current_matches = self.m_match[row].m_count;
            }
        }
        if current_matches != 0 {
            id = self.m_match[row].m_ids[current_matches - 1];
            current_matches -= 1;
        }
        let new_state = row | (current_matches << 24);
        *current_state = new_state;
        *offset = i;
        id
    }
    pub fn search_next_end(&self, current_state: &mut usize) -> usize {
        let id;
        let mut row = *current_state & 0xFFFFFF;
        let mut current_matches = *current_state >> 24;
        let column = self.char_to_symbol[CHAR_ANCHOR_END];
        /*
         * We can enumerate more than one matching end patterns. When we
         * reach the end of that list, return NOT FOUND.
         */
        if current_matches == 0xFF {
            return NO_MATCH;
        }
        /*
         * If we've already returned the first result in our list,
         * then return the next result.
         */
        if current_matches != 0 {
            id = self.m_match[row].m_ids[current_matches - 1];
            current_matches -= 1;
        } else {
            /*
             * This is the same logic as for "smack_search()", except there is
             * only one byte of input -- the virtual character ($) that represents
             * the anchor at the end of some patterns.
             */
            row = self.transitions[(row << self.row_shift) + column as usize];
            /* There was no match, so therefore return NOT FOUND */
            if self.m_match[row].m_count == 0 {
                return NO_MATCH;
            }
            /*
             * If we reach this point, we have found matches, but
             * haven't started returning them. So start returning
             * them. This returns the first one in the list.
             */
            current_matches = self.m_match[row].m_count;
            id = self.m_match[row].m_ids[current_matches - 1];
            if current_matches > 0 {
                current_matches -= 1;
            } else {
                current_matches = 0xFF;
            }
        }
        let new_state = row | (current_matches << 24);
        *current_state = new_state;
        id
    }
    pub fn _next_match(&self, current_state: &mut usize) -> usize {
        let mut id = NO_MATCH;
        let row = *current_state & 0xFFFFFF;
        let mut current_matches = *current_state >> 24;
        if current_matches != 0 {
            id = self.m_match[row].m_ids[current_matches - 1];
            current_matches -= 1;
        }
        *current_state = row | (current_matches << 24);
        return id;
    }
    pub fn compile(&mut self) {
        if self.is_anchor_begin {
            self.add_symbol(CHAR_ANCHOR_START);
        }
        if self.is_anchor_end {
            self.add_symbol(CHAR_ANCHOR_END);
        }
        if self.is_nocase {
            for i in b'A'..b'Z' + 1 {
                self.char_to_symbol[usize::from(i)] =
                    self.char_to_symbol[usize::from(i.to_ascii_lowercase())];
            }
        }
        self.m_state_max = 1;
        for p in self.m_pattern_list.iter() {
            if p.is_anchor_begin {
                self.m_state_max += 1;
            }
            if p.is_anchor_end {
                self.m_state_max += 1;
            }
            self.m_state_max += p.pattern.len();
        }
        self.create_intermediate_table(self.m_state_max);
        self.create_matches_table(self.m_state_max);
        self.stage0_compile_prefixes();
        self.stage1_generate_fails();
        self.stage2_link_fails();
        if self.is_anchor_begin {
            self.swap_rows(BASE_STATE, UNANCHORED_STATE);
        }
        self.stage3_sort();
        self.stage4_make_final_table();
        // self.dump();
        // self.dump_transitions();
        self.fixup_wildcards();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern() {
        let mut smack = Smack::new("test".to_string(), SMACK_CASE_INSENSITIVE);
        let patterns = vec![
            "GET",
            "PUT",
            "POST",
            "OPTIONS",
            "HEAD",
            "DELETE",
            "TRACE",
            "CONNECT",
            "PROPFIND",
            "PROPPATCH",
            "MKCOL",
            "MKWORKSPACE",
            "MOVE",
            "LOCK",
            "UNLOCK",
            "VERSION-CONTROL",
            "REPORT",
            "CHECKOUT",
            "CHECKIN",
            "UNCHECKOUT",
            "COPY",
            "UPDATE",
            "LABEL",
            "BASELINE-CONTROL",
            "MERGE",
            "SEARCH",
            "ACL",
            "ORDERPATCH",
            "PATCH",
            "MKACTIVITY",
        ];
        let text = "ahpropfinddf;orderpatchposearchmoversion-controlockasldhf";
        let mut state = 0;
        for (i, p) in patterns.iter().enumerate() {
            smack.add_pattern(p.as_bytes(), i, SmackFlags::EMPTY);
        }
        smack.compile();
        let mut i = 0;
        let test = |pat: usize, offset: usize, id: usize, i: usize| (pat == id) && (offset == i);
        let id = smack.search_next(&mut state, &text.as_bytes().to_vec(), &mut i);
        assert!(test(8, 10, id, i));
        let id = smack.search_next(&mut state, &text.as_bytes().to_vec(), &mut i);
        assert!(test(28, 23, id, i));
        let id = smack.search_next(&mut state, &text.as_bytes().to_vec(), &mut i);
        assert!(test(27, 23, id, i));
        let id = smack.search_next(&mut state, &text.as_bytes().to_vec(), &mut i);
        assert!(test(25, 31, id, i));
        let id = smack.search_next(&mut state, &text.as_bytes().to_vec(), &mut i);
        assert!(test(12, 35, id, i));
        let id = smack.search_next(&mut state, &text.as_bytes().to_vec(), &mut i);
        assert!(test(15, 48, id, i));
        let id = smack.search_next(&mut state, &text.as_bytes().to_vec(), &mut i);
        assert!(test(13, 51, id, i));
    }

    #[test]
    fn test_anchor_begin() {
        /* test without anchor */
        let mut smack = Smack::new("test anchor begin".to_string(), SMACK_CASE_INSENSITIVE);
        smack.add_pattern(b"abc", 0, SmackFlags::EMPTY);
        smack.add_pattern(b"def", 1, SmackFlags::EMPTY);
        smack.compile();
        let mut i = 0;
        let mut state = BASE_STATE;
        let text = "abc_def";
        /* should find abc and then def */
        let id = smack.search_next(&mut state, &text.as_bytes().to_vec(), &mut i);
        assert!(id == 0);
        let id = smack.search_next(&mut state, &text.as_bytes().to_vec(), &mut i);
        assert!(id == 1);
        /* test with anchor - OK */
        let mut smack = Smack::new("test anchor begin".to_string(), SMACK_CASE_INSENSITIVE);
        smack.add_pattern(b"abc", 0, SmackFlags::ANCHOR_BEGIN);
        smack.add_pattern(b"def", 1, SmackFlags::EMPTY);
        smack.compile();
        let mut i = 0;
        let mut state = BASE_STATE;
        let text = "abc_def";
        /* should find abc and then def */
        let id = smack.search_next(&mut state, &text.as_bytes().to_vec(), &mut i);
        assert!(id == 0);
        let id = smack.search_next(&mut state, &text.as_bytes().to_vec(), &mut i);
        assert!(id == 1);
        /* test with anchor - KO */
        let mut smack = Smack::new("test anchor begin".to_string(), SMACK_CASE_INSENSITIVE);
        smack.add_pattern(b"abc", 0, SmackFlags::ANCHOR_BEGIN);
        smack.add_pattern(b"def", 1, SmackFlags::ANCHOR_BEGIN);
        smack.compile();
        let mut i = 0;
        let mut state = BASE_STATE;
        let text = "abc_def";
        /* should find abc and then nothing */
        let id = smack.search_next(&mut state, &text.as_bytes().to_vec(), &mut i);
        assert!(id == 0);
        let id = smack.search_next(&mut state, &text.as_bytes().to_vec(), &mut i);
        assert!(id == NO_MATCH);
    }

    #[test]
    fn test_wildcard() {
        /* test wildcard without wildcard */
        let mut smack = Smack::new("test".to_string(), SMACK_CASE_INSENSITIVE);
        smack.add_pattern(b"abc", 0, SmackFlags::EMPTY);
        smack.add_pattern(b"egjkfhd", 1, SmackFlags::EMPTY);
        /* here we do not specify the WILDCARD flag */
        smack.add_pattern(b"c*ap", 2, SmackFlags::EMPTY);
        smack.compile();
        let mut i = 0;
        let mut state = BASE_STATE;
        let text = "abc_clap";
        let id = smack.search_next(&mut state, &text.as_bytes().to_vec(), &mut i);
        assert!(id == 0);
        assert!(i == 3);
        let id = smack.search_next(&mut state, &text.as_bytes().to_vec(), &mut i);
        assert!(id != 2);

        /* test wildcard */
        let mut smack = Smack::new("test".to_string(), SMACK_CASE_INSENSITIVE);
        smack.add_pattern(b"abc", 0, SmackFlags::EMPTY);
        smack.add_pattern(b"egjkfhd", 1, SmackFlags::EMPTY);
        smack.add_pattern(b"c*ap", 2, SmackFlags::WILDCARDS);
        smack.compile();
        let mut i = 0;
        let mut state = BASE_STATE;
        let text = "abc_clap";
        let id = smack.search_next(&mut state, &text.as_bytes().to_vec(), &mut i);
        assert!(id == 0);
        assert!(i == 3);
        let id = smack.search_next(&mut state, &text.as_bytes().to_vec(), &mut i);
        assert!(id == 2);

        /* test wildcard + anchor beg */
        let mut smack = Smack::new("test".to_string(), SMACK_CASE_INSENSITIVE);
        smack.add_pattern(
            b"abc*ef",
            0,
            SmackFlags::ANCHOR_BEGIN | SmackFlags::WILDCARDS,
        );
        smack.compile();
        let mut i = 0;
        let mut state = BASE_STATE;
        let text = "abc_ef";
        let id = smack.search_next(&mut state, &text.as_bytes().to_vec(), &mut i);
        assert!(id == 0);
    }

    #[test]
    fn test_http_banner() {
        let mut smack = Smack::new("test".to_string(), SMACK_CASE_INSENSITIVE);
        smack.add_pattern(b"Server:", 0, SmackFlags::ANCHOR_BEGIN);
        smack.add_pattern(b"Via:", 1, SmackFlags::ANCHOR_BEGIN);
        smack.add_pattern(b"Location:", 2, SmackFlags::ANCHOR_BEGIN);
        smack.add_pattern(b":", 3, SmackFlags::EMPTY);
        smack.compile();
        let mut state = BASE_STATE;
        let mut offset = 0;
        let id = smack.search_next(&mut state, &b"server: lol\n".to_vec(), &mut offset);
        assert!(id == 3);
        let id = smack._next_match(&mut state);
        assert!(id == 0);
        let id = smack._next_match(&mut state);
        assert!(id == NO_MATCH);
    }

    #[test]
    fn test_anchor_end() {
        let mut smack = Smack::new("test".to_string(), SMACK_CASE_INSENSITIVE);
        smack.add_pattern(b"def", 0, SmackFlags::ANCHOR_END);
        smack.compile();
        let mut state = BASE_STATE;
        let mut offset = 0;
        let mut id = smack.search_next(&mut state, &b"defabcabb".to_vec(), &mut offset);
        assert!(id == NO_MATCH);
        id = smack.search_next_end(&mut state);
        assert!(id == NO_MATCH);
        let mut state = BASE_STATE;
        let mut offset = 0;
        let mut id = smack.search_next(&mut state, &b"def".to_vec(), &mut offset);
        assert!(id == NO_MATCH);
        id = smack.search_next_end(&mut state);
        assert!(id == 0);
        let mut state = BASE_STATE;
        let mut offset = 0;
        let mut id = smack.search_next(&mut state, &b"abcdef".to_vec(), &mut offset);
        assert!(id == NO_MATCH);
        id = smack.search_next_end(&mut state);
        assert!(id == 0);
    }

    #[test]
    fn test_wildcard_collision() {
        let mut smack = Smack::new("test".to_string(), SMACK_CASE_INSENSITIVE);
        smack.add_pattern(
            b"****abcd",
            0,
            SmackFlags::ANCHOR_BEGIN | SmackFlags::WILDCARDS,
        );
        smack.add_pattern(
            b"******abcd",
            1,
            SmackFlags::ANCHOR_BEGIN | SmackFlags::WILDCARDS,
        );
        smack.compile();
        let mut state = BASE_STATE;
        let mut offset = 0;
        let id = smack.search_next(&mut state, &b"xxxxabcd".to_vec(), &mut offset);
        assert!(id == 0);
        let mut state = BASE_STATE;
        let mut offset = 0;
        let mut id = smack.search_next(&mut state, &b"xxxxxxabcd".to_vec(), &mut offset);
        assert!(id == 1);
        let mut state = BASE_STATE;
        let mut offset = 0;
        let mut id = smack.search_next(&mut state, &b"xxxxbxabcd".to_vec(), &mut offset);
        assert!(id == 1);
        let mut state = BASE_STATE;
        let mut offset = 0;
        let mut id = smack.search_next(&mut state, &b"xxxxaxabcd".to_vec(), &mut offset);
        assert!(id == 1);
    }

    #[test]
    fn test_multiple_matches() {
        let mut smack = Smack::new("test".to_string(), SMACK_CASE_INSENSITIVE);
        smack.add_pattern(b"aabb", 0, SmackFlags::ANCHOR_BEGIN);
        smack.add_pattern(b"abb", 1, SmackFlags::EMPTY);
        smack.add_pattern(b"bb", 2, SmackFlags::EMPTY);
        smack.compile();
        let mut state = BASE_STATE;
        let mut offset = 0;
        let id = smack.search_next(&mut state, &b"aabb".to_vec(), &mut offset);
        assert!(id <= 2);
        let id = smack._next_match(&mut state);
        assert!(id <= 2);
        let id = smack._next_match(&mut state);
        assert!(id <= 2);
        let id = smack._next_match(&mut state);
        assert!(id == NO_MATCH);
    }

    #[test]
    fn test_multiple_matches_wildcard() {
        let mut smack = Smack::new("test".to_string(), SMACK_CASE_INSENSITIVE);
        smack.add_pattern(b"aab", 0, SmackFlags::ANCHOR_BEGIN);
        smack.add_pattern(b"*ac", 1, SmackFlags::ANCHOR_BEGIN | SmackFlags::WILDCARDS);
        smack.compile();
        let mut state = BASE_STATE;
        let mut offset = 0;
        let id = smack.search_next(&mut state, &b"aab".to_vec(), &mut offset);
        assert!(id == 0);
        let mut state = BASE_STATE;
        let mut offset = 0;
        let id = smack.search_next(&mut state, &b"bac".to_vec(), &mut offset);
        assert!(id == 1);
    }

    #[test]
    fn test_proto() {
        const PROTO_HTTP: usize = 0;
        const PROTO_SMB: usize = 1;
        let mut smack = Smack::new("proto".to_string(), SMACK_CASE_SENSITIVE);
        /* HTTP markers */
        let http_verbs = [
            "GET /",
            "PUT /",
            "POST /",
            "HEAD /",
            "DELETE /",
            "CONNECT /",
            "OPTIONS /",
            "TRACE /",
            "PATCH /",
        ];
        for (_, v) in http_verbs.iter().enumerate() {
            smack.add_pattern(v.as_bytes(), PROTO_HTTP, SmackFlags::ANCHOR_BEGIN);
        }
        /* SMB markers */
        smack.add_pattern(
            b"\x00\x00**\xffSMB",
            PROTO_SMB,
            SmackFlags::ANCHOR_BEGIN | SmackFlags::WILDCARDS,
        );
        smack.compile();
        let mut state = BASE_STATE;
        let mut offset = 0;
        let id = smack.search_next(&mut state, &b"HEAD /".to_vec(), &mut offset);
        assert!(id == PROTO_HTTP);
        let mut state = BASE_STATE;
        let mut offset = 0;
        let id = smack.search_next(&mut state, &b"\x00\x00aa\xffSMB".to_vec(), &mut offset);
        assert!(id == PROTO_SMB);
    }
}
