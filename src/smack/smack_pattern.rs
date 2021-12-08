use crate::smack::smack_utils::SmackFlags;

pub struct SmackPattern {
    pub id: usize,
    pub pattern: Vec<u8>,
    pub is_anchor_begin: bool,
    pub is_anchor_end: bool,
    pub is_wildcards: bool,
}

impl SmackPattern {
    pub fn new(pattern: Vec<u8>, id: usize, flags: SmackFlags) -> Self {
        SmackPattern {
            id,
            is_anchor_begin: flags.contains(SmackFlags::ANCHOR_BEGIN),
            is_anchor_end: flags.contains(SmackFlags::ANCHOR_END),
            is_wildcards: flags.contains(SmackFlags::WILDCARDS),
            pattern,
        }
    }
}
