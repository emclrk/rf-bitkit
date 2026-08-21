use crate::BitkitError;
use crate::crc;
use rand::prelude::*;
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
        covers: (String, String),
    },
    Checksum {
        len: usize,
        covers: (String, String),
        label: String,
    },
}
impl FieldSpec {
    fn gen_header_lines(&self, field_name: &str, start_loc: usize) -> Vec<String> {
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
                let packed = bitvec_to_u128(bits);
                format!(" val=0x{:x}", packed)
            }
            _ => String::new(),
        };
        output.push(format!(
            "# field: name={field_name} type={field_type} range={start}..{end}{optional_str}"
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
                format!(
                    "# crc: field={field_name} poly=0x{:x} init=0x{:x} xorout=0x{:x} refin={refin} refout={refout} covers={}..{}",
                    poly, init, xorval, covers.0, covers.1
                )
            }
            Self::Checksum {
                len: _,
                covers,
                label,
            } => {
                format!(
                    "# checksum: field={field_name} label={label} covers={}..{}",
                    covers.0, covers.1
                )
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
    covers: (&'a str, &'a str),
}

struct CheckParse<'a> {
    covers: (&'a str, &'a str),
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
                FieldSpec::Crc { covers, .. } | FieldSpec::Checksum { covers, .. } => {
                    if !names.contains(&covers.0) || !names.contains(&covers.1) {
                        return Err(BitkitError::InvalidSpec(format!(
                            "{:?} field reference must be declared before being used in {}",
                            covers,
                            fspec.type_str()
                        )));
                    }
                    if fields.iter().position(|(c, _)| *c == covers.0)
                        > fields.iter().position(|(c, _)| *c == covers.1)
                    {
                        return Err(BitkitError::InvalidSpec(format!(
                            "{} occurs after {}",
                            covers.0, covers.1
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
                crcs.push(Self::parse_crc(crc_line)?);
            } else if let Some(cs_line) = each.strip_prefix("# checksum: ") {
                checks.push(Self::parse_checksum(cs_line)?);
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
                        bits: u128_to_bitvec(
                            parsed.val.ok_or(BitkitError::InvalidSpec(
                                "sync word field should provide a value (val=0x..)".to_string(),
                            ))?,
                            parsed.range.1 - parsed.range.0,
                        ),
                    },
                )),
                FieldType::Fixed => packet.push((
                    parsed.name.to_string(),
                    FieldSpec::Fixed {
                        bits: u128_to_bitvec(
                            parsed.val.ok_or(BitkitError::InvalidSpec(
                                "fixed field should provide a value (val=0x..)".to_string(),
                            ))?,
                            parsed.range.1 - parsed.range.0,
                        ),
                    },
                )),
                FieldType::Payload => packet.push((
                    parsed.name.to_string(),
                    FieldSpec::Payload {
                        len: parsed.range.1 - parsed.range.0,
                    },
                )),
                FieldType::Crc => {
                    let crc = &crcs
                        .iter()
                        .find(|(name, _)| name == parsed.name)
                        .ok_or(BitkitError::InvalidSpec(format!(
                            "Could not find {} in header",
                            parsed.name,
                        )))?
                        .1;
                    packet.push((
                        parsed.name.to_string(),
                        FieldSpec::Crc {
                            width: parsed.range.1 - parsed.range.0,
                            poly: crc.poly,
                            init: crc.init,
                            refin: crc.refin,
                            refout: crc.refout,
                            xorval: crc.xorval,
                            covers: (crc.covers.0.to_string(), crc.covers.1.to_string()),
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
                            covers: (cx.covers.0.to_string(), cx.covers.1.to_string()),
                            label: cx.label.to_string(),
                        },
                    ))
                }
            }
        }
        Self::new(packet)
    }
    fn parse_fieldline(line: &str) -> Result<FieldParse<'_>, BitkitError> {
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
        let range_str = keyvals
            .get("range")
            .ok_or(BitkitError::InvalidSpec(String::from(
                "Spec parsing: no range provided",
            )))?;

        let range = Self::parse_range(range_str)?;
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
    fn parse_crc(crc_line: &str) -> Result<(String, CrcParse<'_>), BitkitError> {
        let keyvals = crc_line
            .split_whitespace()
            .filter_map(|kv| kv.split_once('='))
            .collect::<HashMap<&str, &str>>();
        let fieldname = keyvals
            .get("field")
            .ok_or(BitkitError::InvalidSpec(format!(
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
            value
                .parse::<bool>()
                .map_err(|_| BitkitError::InvalidSpec(format!("invalid refin value: {value}")))?
        } else {
            false
        };
        let refout = if let Some(value) = keyvals.get("refout") {
            value
                .parse::<bool>()
                .map_err(|_| BitkitError::InvalidSpec(format!("invalid refout value: {value}")))?
        } else {
            false
        };
        let covers = keyvals
            .get("covers")
            .ok_or(BitkitError::InvalidSpec(format!(
                "{crc_line} missing \"covers:\"",
            )))?
            .split_once("..")
            .ok_or(BitkitError::InvalidSpec(String::from(
                "Spec parsing: malformed `covers` range",
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
    fn parse_checksum(cs_line: &str) -> Result<(String, CheckParse<'_>), BitkitError> {
        let keyvals = cs_line
            .split_whitespace()
            .filter_map(|kv| kv.split_once('='))
            .collect::<HashMap<&str, &str>>();
        let fieldname = keyvals
            .get("field")
            .ok_or(BitkitError::InvalidSpec(format!(
                "{cs_line} missing \"field:\"",
            )))?;
        let label = keyvals
            .get("label")
            .ok_or(BitkitError::InvalidSpec(format!(
                "{cs_line} missing \"label:\", needed for checksum type",
            )))?;
        let covers = keyvals
            .get("covers")
            .ok_or(BitkitError::InvalidSpec(format!(
                "{cs_line} missing \"covers:\"",
            )))?
            .split_once("..")
            .ok_or(BitkitError::InvalidSpec(String::from(
                "Spec parsing: malformed `covers` range",
            )))?;
        Ok((fieldname.to_string(), CheckParse { covers, label }))
    }
    fn parse_range(range_term: &str) -> Result<(usize, usize), BitkitError> {
        let (start_str, end_str) =
            range_term
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
        Ok(range)
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
    /// Generate packets for the given packet spec.
    /// num_packets: number of packets to generate
    /// exclude_sym: symbol to exclude from data given as a bit vector (msb first)
    pub fn gen_packets(
        &self,
        num_packets: usize,
        exclude_sym: Option<&Vec<u8>>,
    ) -> Result<Vec<String>, BitkitError> {
        let mut contents = self.gen_header();
        let mut rng = rand::rng();
        for _ in 0..num_packets {
            let mut line: Vec<u8> = vec![];
            let mut ranges: HashMap<&str, (usize, usize)> = HashMap::new();
            for (name, field) in self.fields().iter() {
                let range_beg = line.len();
                let res = match field {
                    FieldSpec::Preamble { len } => {
                        ranges.insert(name, (range_beg, range_beg + len));
                        (0..*len).map(|ii| 1 - (ii % 2) as u8).collect::<Vec<u8>>()
                    }
                    FieldSpec::SyncWord { bits } | FieldSpec::Fixed { bits } => {
                        ranges.insert(name, (range_beg, range_beg + bits.len()));
                        bits.to_vec()
                    }
                    FieldSpec::Payload { len } => {
                        ranges.insert(name, (range_beg, range_beg + len));
                        if let Some(ex_sym) = exclude_sym.filter(|s| !s.is_empty()) {
                            let chunk_size = ex_sym.len();
                            if !len.is_multiple_of(chunk_size) {
                                log::info!(
                                    "{len} is not a multiple of chunk size {chunk_size} - may not be able to perfectly exclude {} from the data",
                                    ex_sym
                                        .iter()
                                        .map(|b| (b'0' + b) as char)
                                        .collect::<String>()
                                );
                            }
                            let mut output: Vec<u8> = vec![];
                            for chunk in (0..*len).collect::<Vec<usize>>().chunks(chunk_size) {
                                loop {
                                    let sym = chunk
                                        .iter()
                                        .map(|_| rng.random_bool(0.5) as u8)
                                        .collect::<Vec<u8>>();
                                    if sym != *ex_sym {
                                        output.extend(sym);
                                        break;
                                    }
                                }
                            }
                            output
                        } else {
                            (0..*len)
                                .map(|_| rng.random_bool(0.5) as u8)
                                .collect::<Vec<u8>>()
                        }
                    }
                    FieldSpec::Crc {
                        width,
                        poly,
                        init,
                        refin,
                        refout,
                        xorval,
                        covers,
                    } => {
                        ranges.insert(name, (range_beg, range_beg + width));
                        match ranges
                            .get(covers.0.as_str())
                            .zip(ranges.get(covers.1.as_str()))
                        {
                            Some((beg, end)) => Self::gen_crc(
                                *width,
                                *poly,
                                *init,
                                *refin,
                                *refout,
                                *xorval,
                                &line[beg.0..end.1],
                            ),
                            None => unreachable!(),
                        }
                    }
                    FieldSpec::Checksum { len, covers, label } => {
                        ranges.insert(name, (range_beg, range_beg + len));
                        match ranges
                            .get(covers.0.as_str())
                            .zip(ranges.get(covers.1.as_str()))
                        {
                            Some((beg, end)) => {
                                Self::get_checksum(&line[beg.0..end.1], label, *len)?
                            }
                            None => unreachable!(),
                        }
                    }
                };
                line.extend(res);
            }
            contents.push(
                line.iter()
                    .map(|b| if *b == 0 { '0' } else { '1' })
                    .collect::<String>(),
            );
        }
        Ok(contents)
    }
    fn gen_crc(
        width: usize,
        poly: u128,
        init: u128,
        refin: bool,
        refout: bool,
        xorval: u128,
        data: &[u8],
    ) -> Vec<u8> {
        let mask: u128 = (1u128 << width) - 1;
        let bits: Vec<u8> = if refin {
            crc::reflect_vec(data)
        } else {
            data.to_vec()
        };
        let mut crc_val: u128 = init;
        for &bit in &bits {
            let feedback = ((crc_val >> (width - 1)) & 1) ^ (bit as u128);
            crc_val = (crc_val << 1) & mask;
            if feedback != 0 {
                crc_val ^= poly;
            }
        }
        if refout {
            crc_val = crc::reflect_bits(crc_val, width);
        }
        u128_to_bitvec(crc_val ^ xorval, width)
    }
    fn get_checksum(data: &[u8], label: &str, len: usize) -> Result<Vec<u8>, BitkitError> {
        match label {
            "addmod256" => {
                if !data.len().is_multiple_of(8) {
                    return Err(BitkitError::InvalidSpec(String::from(
                        "Data covered by the checksum is not byte aligned; cannot use addition mod 256",
                    )));
                }
                let val = data.chunks(8).map(bitvec_to_u128).sum::<u128>() % 256;
                Ok(u128_to_bitvec(val, len))
            }
            "xor" => {
                if !data.len().is_multiple_of(8) {
                    return Err(BitkitError::InvalidSpec(String::from(
                        "Data covered by the checksum is not byte aligned; cannot use XOR",
                    )));
                }
                let val = data
                    .chunks(8)
                    .map(bitvec_to_u128)
                    .fold(0u128, |acc, chunk| acc ^ chunk);
                Ok(u128_to_bitvec(val, len))
            }
            _ => Err(BitkitError::InvalidSpec(format!(
                "Unknown checksum type {label}"
            ))),
        }
    }
} // impl PacketSpec

pub fn u128_to_bitvec(val: u128, len: usize) -> Vec<u8> {
    (0..len)
        .map(|ii| ((val >> (len - 1 - ii)) & 1) as u8)
        .collect()
}
pub fn bitvec_to_u128(bits: &[u8]) -> u128 {
    bits.iter().enumerate().fold(0u128, |acc, (ii, &bit)| {
        acc | (bit as u128) << (bits.len() - 1 - ii)
    })
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
            format!("# field: name=test type=fixed range=0..12 val=0xabc")
        );
    }
    #[test]
    fn test_new_packetspec() {
        assert!(PacketSpec::new(vec![]).is_err());
        assert!(
            PacketSpec::new(vec![
                (format!("test1"), FieldSpec::Fixed { bits: vec![] }),
                (format!("test1"), FieldSpec::SyncWord { bits: vec![] })
            ])
            .is_err()
        );
        let crc = FieldSpec::Crc {
            width: 20,
            poly: 7u128,
            init: 0u128,
            refin: false,
            refout: false,
            xorval: 0u128,
            covers: (format!("payload"), format!("payload")),
        };
        // giving it wrong names - crc1 covers "payload"; should fail
        assert!(
            PacketSpec::new(vec![
                (format!("data"), FieldSpec::Payload { len: 25 }),
                (format!("crc1"), crc),
            ])
            .is_err()
        );
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
            covers: (format!("data"), format!("data")),
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
        let _contents = packet.gen_packets(10, None);
    }
    #[test]
    fn test_crc() {
        // Test case using CRC-16/IBM-SDLC
        let poly = 0x1021;
        let init = 0xffff;
        let refin = true;
        let refout = true;
        let xorval = 0xffff;
        let check = 0x906e;
        // 123456789
        let input: Vec<u8> = vec![
            0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0,
            1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0,
            1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1,
        ];
        let checkval = PacketSpec::gen_crc(16, poly, init, refin, refout, xorval, &input);
        assert_eq!(check, bitvec_to_u128(&checkval));
    }
}
