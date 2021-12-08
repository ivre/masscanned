pub const ALPHABET_SIZE: usize = 256 + 2;
pub const BASE_STATE: usize = 0;
pub const UNANCHORED_STATE: usize = 1;
pub const FAIL_STATE: usize = 0xFFFFFFFF;

pub const CHAR_ANCHOR_START: usize = 256;
pub const CHAR_ANCHOR_END: usize = 257;

pub const NO_MATCH: usize = 0xFFFFFFFFFFFFFFFF;

pub const SMACK_CASE_INSENSITIVE: bool = true;
pub const SMACK_CASE_SENSITIVE: bool = false;
