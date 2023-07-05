bitflags! {
    #[derive(Clone, Copy)]
    pub struct SmackFlags: usize {
        const EMPTY         = 0x00;
        const ANCHOR_BEGIN  = 0x01;
        const ANCHOR_END    = 0x02;
        const WILDCARDS     = 0x04;
    }
}

pub fn row_shift_from_symbol_count(symbol_count: usize) -> usize {
    let mut row_shift = 1;
    let symbol_count = symbol_count + 1;
    while (1 << row_shift) < symbol_count {
        row_shift += 1;
    }
    row_shift
}
