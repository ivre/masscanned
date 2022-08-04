// This file is part of masscanned.
// Copyright 2022 - The IVRE project
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

use strum_macros::EnumIter;

#[derive(PartialEq, Debug, Clone, Copy, EnumIter)]
pub enum DNSType {
    NONE,
    A,
    TXT, // value: 16 - text strings
}

impl From<u16> for DNSType {
    fn from(item: u16) -> Self {
        match item {
            1 => DNSType::A,
            16 => DNSType::TXT,
            _ => DNSType::NONE,
        }
    }
}

impl From<DNSType> for u16 {
    fn from(item: DNSType) -> Self {
        match item {
            DNSType::A => 1,
            DNSType::TXT => 16,
            _ => 0,
        }
    }
}

#[derive(PartialEq, Debug, Clone, Copy, EnumIter)]
pub enum DNSClass {
    NONE,
    IN, // value: 1 - the Internet
    CH, // value: 3 - the CHAOS class
}

impl From<u16> for DNSClass {
    fn from(item: u16) -> Self {
        match item {
            1 => DNSClass::IN,
            3 => DNSClass::CH,
            _ => DNSClass::NONE,
        }
    }
}

impl From<DNSClass> for u16 {
    fn from(item: DNSClass) -> Self {
        match item {
            DNSClass::IN => 1,
            DNSClass::CH => 3,
            _ => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_parse() {
        /* type TXT */
        assert!(DNSType::from(1) == DNSType::A);
        assert!(1 as u16 == DNSType::A.into());
        assert!(DNSType::from(16) == DNSType::TXT);
        assert!(16 as u16 == DNSType::TXT.into());
    }

    #[test]
    fn class_parse() {
        assert!(DNSClass::from(1) == DNSClass::IN);
        assert!(1 as u16 == DNSClass::IN.into());
        assert!(DNSClass::from(3) == DNSClass::CH);
        assert!(3 as u16 == DNSClass::CH.into());
    }
}
