use crate::BitkitError;
use std::collections::HashSet;

pub enum FieldSpec {
    Preamble {
        len: usize,
        start_bit: u8,
    },
    SyncWord {
        bits: Vec<u8>,
    },
    Fixed {
        bits: Vec<u8>,
    },
    Payload {
        len: usize,
    },
    Crc {
        width: usize,
        poly: u128,
        init: u128,
        refin: bool,
        refout: bool,
        xorval: u128,
        covers: String,
    },
    Checksum {
        len: usize,
        covers: String,
        label: String,
    },
}

impl FieldSpec {
    pub fn gen_header_lines(&self, field_name: &str, start_loc: usize) -> Vec<String> {
        let mut output: Vec<String> = vec![];
        let (start, end): (usize, usize) = match self {
            Self::Preamble { len, start_bit: _ } => (start_loc, start_loc + len),
            Self::SyncWord { bits } | Self::Fixed { bits } => (start_loc, start_loc + bits.len()),

            Self::Payload { len } => (start_loc, start_loc + len),
            Self::Crc { width, .. } => (start_loc, start_loc + width),
            Self::Checksum { len, .. } => (start_loc, start_loc + len),
        };
        let field_type = self.type_str();
        let optional_str: String = match self {
            Self::SyncWord { bits } | Self::Fixed { bits } => {
                let packed = bits.iter().enumerate().fold(0u128, |acc, (ii, &bit)| {
                    acc | (bit as u128) << (bits.len() - 1 - ii)
                });
                format!(" val=0x{:x}", packed)
            }
            _ => String::new(),
        };
        output.push(format!(
            "# field: name={field_name} type={field_type} range={start}..{end}{optional_str}\n"
        ));
        let add_str = match self {
            Self::Preamble { .. }
            | Self::SyncWord { .. }
            | Self::Fixed { .. }
            | Self::Payload { .. } => String::new(),
            Self::Crc {
                width: _,
                poly,
                init,
                xorval,
                refin,
                refout,
                covers,
            } => {
                format!("# crc: field={field_name} poly=0x{:x} init=0x{:x} xorout=0x{:x} refin={refin} refout={refout} covers={covers}\n", poly, init, xorval)
            }
            Self::Checksum {
                len: _,
                covers,
                label,
            } => {
                format!("# checksum: field={field_name} label={label} covers={covers}\n")
            }
        };
        if !add_str.is_empty() {
            output.push(add_str)
        };
        output
    }
    pub fn type_str(&self) -> String {
        match self {
            Self::Preamble { .. } => String::from("preamble"),
            Self::SyncWord { .. } => String::from("sync_word"),
            Self::Fixed { .. } => String::from("fixed"),
            Self::Payload { .. } => String::from("payload"),
            Self::Crc { .. } => String::from("crc"),
            Self::Checksum { .. } => String::from("checksum"),
        }
    }
}
pub struct PacketSpec(Vec<(String, FieldSpec)>);

impl PacketSpec {
    pub fn new(fields: Vec<(String, FieldSpec)>) -> Result<Self, BitkitError> {
        // Validated constructor - field names must be unique, and `covers` references must be valid
        // and ordered.
        if fields.is_empty() {
            return Err(BitkitError::InvalidSpec(String::from("Empty spec")));
        }
        let mut names = HashSet::new();
        for (fname, fspec) in fields.iter() {
            if names.contains(fname) {
                return Err(BitkitError::InvalidSpec(format!(
                    "Field name {fname} already in spec. Names must be unique."
                )));
            }
            match fspec {
                FieldSpec::Crc { covers, .. } | FieldSpec::Checksum { covers, .. } => {
                    if !names.contains(covers) {
                        return Err(BitkitError::InvalidSpec(format!(
                            "{covers} field reference must be declared before being used in {}",
                            fspec.type_str()
                        )));
                    }
                }
                _ => (),
            };
            names.insert(fname);
        }
        Ok(PacketSpec(fields))
    }
    pub fn fields(&self) -> &[(String, FieldSpec)] {
        &self.0
    }
    fn gen_header(&self) -> Vec<String> {
        let mut header: Vec<String> = vec![];
        let mut start_loc: usize = 0;
        for (fname, fspec) in self.0.iter() {
            let lines = fspec.gen_header_lines(fname, start_loc);
            header.extend(lines);
            start_loc += match fspec {
                FieldSpec::Preamble { len, .. }
                | FieldSpec::Payload { len }
                | FieldSpec::Checksum { len, .. } => *len,
                FieldSpec::SyncWord { bits, .. } | FieldSpec::Fixed { bits, .. } => bits.len(),
                FieldSpec::Crc { width, .. } => *width,
            };
        }
        header
    }
    // Parse # comment lines into PacketSpec
    // fn parse_header(lines: &Vec<String>) -> Self {
    //     let mut header: Vec<(String, FieldSpec)> = vec![];
    // }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitvec_to_hex() {
        let field = FieldSpec::Fixed {
            bits: vec![1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0],
        };
        assert_eq!(
            field.gen_header_lines("test", 0)[0],
            format!("# field: name=test type=fixed range=0..12 val=0xabc\n")
        );
    }
    #[test]
    fn test_new_packetspec() {
        assert!(PacketSpec::new(vec![]).is_err());
        assert!(PacketSpec::new(vec![
            (format!("test1"), FieldSpec::Fixed { bits: vec![] }),
            (format!("test1"), FieldSpec::SyncWord { bits: vec![] })
        ])
        .is_err());
        let crc = FieldSpec::Crc {
            width: 20,
            poly: 7u128,
            init: 0u128,
            refin: false,
            refout: false,
            xorval: 0u128,
            covers: format!("payload"),
        };
        assert!(PacketSpec::new(vec![
            (format!("data"), FieldSpec::Payload { len: 25 }),
            (format!("crc1"), crc),
        ])
        .is_err());
    }
    //     #[test]
    //     fn test_write() {
    //         let crc = FieldSpec::Crc {
    //             width: 20,
    //             poly: 7u128,
    //             init: 0u128,
    //             refin: false,
    //             refout: false,
    //             xorval: 0u128,
    //             covers: format!("data"),
    //         };
    //         let pack = PacketSpec::new(vec![
    //             (String::from("data"), FieldSpec::Payload { len: 200 }),
    //             (String::from("crc1"), crc),
    //         ])
    //         .unwrap();
    //         let lines = pack.gen_header();
    //         for line in lines.iter() {
    //             println!("{line}");
    //         }
    //     }
}
