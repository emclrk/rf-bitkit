use crate::BitkitError;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;

pub enum FieldType {
    Preamble,
    SyncWord,
    Fixed,
    Payload,
    Crc,
    Checksum,
}
impl FromStr for FieldType {
    type Err = BitkitError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "preamble" => Ok(Self::Preamble),
            "sync_word" => Ok(Self::SyncWord),
            "fixed" => Ok(Self::Fixed),
            "payload" => Ok(Self::Payload),
            "crc" => Ok(Self::Crc),
            "checksum" => Ok(Self::Checksum),
            _ => Err(Self::Err::InvalidSpec(String::from("Unknown field type"))),
        }
    }
}
#[derive(Debug)]
pub enum FieldSpec {
    Preamble {
        len: usize,
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
            Self::SyncWord { bits } | Self::Fixed { bits } => (start_loc, start_loc + bits.len()),

            Self::Preamble { len, .. } | Self::Payload { len } | Self::Checksum { len, .. } => {
                (start_loc, start_loc + len)
            }
            Self::Crc { width, .. } => (start_loc, start_loc + width),
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
} // impl FieldSpec

#[derive(Debug)]
pub struct PacketSpec(Vec<(String, FieldSpec)>);

struct FieldParse<'a> {
    name: &'a str,
    field_type: FieldType,
    range: (usize, usize),
    val: Option<u128>,
}

struct CrcParse<'a> {
    poly: u128,
    init: u128,
    refin: bool,
    refout: bool,
    xorval: u128,
    covers: &'a str,
}

struct CheckParse<'a> {
    covers: &'a str,
    label: &'a str,
}

impl PacketSpec {
    /// Construct and validate PacketSpec from a vector of (String, FieldSpec)
    /// Field names must be unique and `covers` references must be valid and ordered
    pub fn new(fields: Vec<(String, FieldSpec)>) -> Result<Self, BitkitError> {
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
                FieldSpec::Crc { covers, .. } | FieldSpec::Checksum { covers, .. }
                    if !names.contains(covers) =>
                {
                    return Err(BitkitError::InvalidSpec(format!(
                        "{covers} field reference must be declared before being used in {}",
                        fspec.type_str()
                    )));
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
    /// Parse # comment lines from testfile headers into PacketSpec
    pub fn parse_header(header: &[String]) -> Result<Self, BitkitError> {
        let mut packet: Vec<(String, FieldSpec)> = vec![];
        let mut fieldlines: Vec<FieldParse> = vec![];
        let mut crcs: Vec<(String, CrcParse)> = vec![];
        let mut checks: Vec<(String, CheckParse)> = vec![];
        for each in header.iter() {
            if let Some(line) = each.strip_prefix("# field: ") {
                fieldlines.push(Self::parse_fieldline(line)?);
            } else if let Some(crc_line) = each.strip_prefix("# crc: ") {
                crcs.push(Self::parse_crc(&crc_line)?);
            } else if let Some(cs_line) = each.strip_prefix("# checksum: ") {
                checks.push(Self::parse_checksum(&cs_line)?);
            }
        }
        for parsed in fieldlines.iter() {
            match parsed.field_type {
                FieldType::Preamble => packet.push((
                    parsed.name.to_string(),
                    FieldSpec::Preamble {
                        len: parsed.range.1 - parsed.range.0,
                    },
                )),
                FieldType::SyncWord => packet.push((
                    parsed.name.to_string(),
                    FieldSpec::SyncWord {
                        bits: u128_to_bitvec(parsed.val.unwrap(), parsed.range.1 - parsed.range.0),
                    },
                )),
                FieldType::Fixed => packet.push((
                    parsed.name.to_string(),
                    FieldSpec::Fixed {
                        bits: u128_to_bitvec(parsed.val.unwrap(), parsed.range.1 - parsed.range.0),
                    },
                )),
                FieldType::Payload => packet.push((
                    parsed.name.to_string(),
                    FieldSpec::Payload {
                        len: parsed.range.1 - parsed.range.0,
                    },
                )),
                FieldType::Crc => {
                    let crc = &crcs.iter().find(|(name, _)| name == parsed.name).unwrap().1;
                    packet.push((
                        parsed.name.to_string(),
                        FieldSpec::Crc {
                            width: parsed.range.1 - parsed.range.0,
                            poly: crc.poly,
                            init: crc.init,
                            refin: crc.refin,
                            refout: crc.refout,
                            xorval: crc.xorval,
                            covers: crc.covers.to_string(),
                        },
                    ))
                }
                FieldType::Checksum => {
                    let cx = &checks
                        .iter()
                        .find(|(name, _)| name == parsed.name)
                        .ok_or(BitkitError::InvalidSpec(format!(
                            "Could not find {} in header",
                            parsed.name,
                        )))?
                        .1;
                    packet.push((
                        parsed.name.to_string(),
                        FieldSpec::Checksum {
                            len: parsed.range.1 - parsed.range.0,
                            covers: cx.covers.to_string(),
                            label: cx.label.to_string(),
                        },
                    ))
                }
            }
        }
        Self::new(packet)
    }
    fn parse_fieldline(line: &str) -> Result<FieldParse, BitkitError> {
        let keyvals = line
            .split_whitespace()
            .filter_map(|kv| kv.split_once('='))
            .collect::<HashMap<&str, &str>>();
        let field_type = keyvals
            .get("type")
            .ok_or(BitkitError::InvalidSpec(String::from(
                "Spec parsing: no field type provided",
            )))?
            .parse::<FieldType>()?;
        let mut val: Option<u128> = None;
        if let Some(value) = keyvals.get("val") {
            val = Some(u128::from_str_radix(
                value.strip_prefix("0x").unwrap_or(value),
                16,
            )?);
        }
        let (start_str, end_str) = keyvals
            .get("range")
            .ok_or(BitkitError::InvalidSpec(String::from(
                "Spec parsing: no range provided",
            )))?
            .split_once("..")
            .ok_or(BitkitError::InvalidSpec(String::from(
                "Spec parsing: malformed range",
            )))?;
        let range = (
            start_str.parse::<usize>().map_err(|_| {
                BitkitError::InvalidSpec(String::from("Spec parsing: invalid range start"))
            })?,
            end_str.parse::<usize>().map_err(|_| {
                BitkitError::InvalidSpec(String::from("Spec parsing: invalid range end"))
            })?,
        );
        let name = keyvals
            .get("name")
            .ok_or(BitkitError::InvalidSpec(String::from(
                "Spec parsing: no field name provided",
            )))?;
        Ok(FieldParse {
            name,
            field_type,
            range,
            val,
        })
    }
    fn parse_crc(crc_line: &str) -> Result<(String, CrcParse), BitkitError> {
        let keyvals = crc_line
            .split_whitespace()
            .filter_map(|kv| kv.split_once('='))
            .collect::<HashMap<&str, &str>>();
        let fieldname = keyvals
            .get("field")
            .ok_or(BitkitError::InvalidSpec(String::from(
                "{crc_line} missing \"field:\"",
            )))?;
        let poly = if let Some(value) = keyvals.get("poly") {
            u128::from_str_radix(value.strip_prefix("0x").unwrap_or(value), 16)?
        } else {
            0
        };
        let init = if let Some(value) = keyvals.get("init") {
            u128::from_str_radix(value.strip_prefix("0x").unwrap_or(value), 16)?
        } else {
            0
        };
        let xorval = if let Some(value) = keyvals.get("xorout") {
            u128::from_str_radix(value.strip_prefix("0x").unwrap_or(value), 16)?
        } else {
            0
        };
        let refin = if let Some(value) = keyvals.get("refin") {
            value.parse::<bool>().unwrap()
        } else {
            false
        };
        let refout = if let Some(value) = keyvals.get("refout") {
            value.parse::<bool>().unwrap()
        } else {
            false
        };
        let covers = keyvals
            .get("covers")
            .ok_or(BitkitError::InvalidSpec(String::from(
                "{crc_line} missing \"covers:\"",
            )))?;
        Ok((
            fieldname.to_string(),
            CrcParse {
                poly,
                init,
                refin,
                refout,
                xorval,
                covers,
            },
        ))
    }
    fn parse_checksum(cs_line: &str) -> Result<(String, CheckParse), BitkitError> {
        let keyvals = cs_line
            .split_whitespace()
            .filter_map(|kv| kv.split_once('='))
            .collect::<HashMap<&str, &str>>();
        let fieldname = keyvals
            .get("field")
            .ok_or(BitkitError::InvalidSpec(String::from(
                "{cs_line} missing \"field:\"",
            )))?;
        let label = keyvals
            .get("label")
            .ok_or(BitkitError::InvalidSpec(String::from(
                "{cs_line} missing \"label:\", needed for checksum type",
            )))?;
        let covers = keyvals
            .get("covers")
            .ok_or(BitkitError::InvalidSpec(String::from(
                "{cs_line} missing \"covers:\"",
            )))?;
        Ok((fieldname.to_string(), CheckParse { covers, label }))
    }
    pub fn gen_header(&self) -> Vec<String> {
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
    pub fn gen_packets(&self, num_packets: usize) -> Vec<String> {
        let mut contents = self.gen_header();
        for _ in 0..num_packets {
            let mut line = String::new();
            for (name, field) in self.fields().iter() {
                let res = match field {
                    FieldSpec::Preamble { len } => &(0..*len)
                        .map(|ii| {
                            let bit = 1 - (ii % 2);
                            if bit == 0 {
                                '0'
                            } else {
                                '1'
                            }
                        })
                        .collect::<String>(),
                    FieldSpec::SyncWord { bits } | FieldSpec::Fixed { bits } => &bits
                        .iter()
                        .map(|b| if *b == 0 { '0' } else { '1' })
                        .collect::<String>(),
                    //len
                    FieldSpec::Payload { .. } => &String::new(),
                    // width, poly, init, refin, refout, xorval, covers,
                    FieldSpec::Crc { .. } => &String::new(),
                    // len, covers, label
                    FieldSpec::Checksum { .. } => &String::new(),
                };
                line.push_str(res);

                break;
            }
            contents.push(line);
            break;
        }
        contents
    }
} // impl PacketSpec

fn u128_to_bitvec(val: u128, len: usize) -> Vec<u8> {
    (0..len)
        .map(|ii| ((val >> (len - 1 - ii)) & 1) as u8)
        .collect()
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
    #[test]
    fn test_write_spec() {
        let crc = FieldSpec::Crc {
            width: 20,
            poly: 7u128,
            init: 0u128,
            refin: false,
            refout: false,
            xorval: 0u128,
            covers: format!("data"),
        };
        let fixed_bits = vec![1, 1, 0, 1, 1];
        let pack = PacketSpec::new(vec![
            (String::from("pre"), FieldSpec::Preamble { len: 7 }),
            (
                String::from("spacer"),
                FieldSpec::Fixed {
                    bits: fixed_bits.clone(),
                },
            ),
            (String::from("data"), FieldSpec::Payload { len: 200 }),
            (String::from("crc1"), crc),
        ])
        .unwrap();
        let lines = pack.gen_header();
        let packet = PacketSpec::parse_header(&lines).unwrap();
        if let FieldSpec::Fixed { bits } = &packet
            .fields()
            .iter()
            .find(|(name, _)| name == "spacer")
            .unwrap()
            .1
        {
            assert_eq!(bits, &fixed_bits);
        } else {
            // failed to pull the bits out for some reason
            unreachable!();
        }
        let contents = packet.gen_packets(10);
        println!("{:?}", contents);
    }
}
