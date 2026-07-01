use quick_xml::de::from_reader;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use thiserror::Error;

#[derive(Deserialize, Clone)]
pub struct Bitstream {
    #[serde(rename = "@bits")]
    bits: String,
}

#[derive(Deserialize)]
struct Messages {
    #[serde(rename = "message")]
    message_list: Vec<Bitstream>,
}

#[derive(Deserialize)]
struct URHProtocol {
    messages: Messages,
}

#[derive(Error, Debug)]
pub enum BitkitError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("XML parsing error: {0}")]
    Xml(#[from] quick_xml::DeError),

    #[error("Invalid bit character: '{0}'")]
    InvalidBit(char),

    #[error("Empty bit string")]
    EmptyString,
}

impl Bitstream {
    pub fn new(bitstring: String) -> Result<Self, BitkitError> {
        // Check to make sure it's a valid bit stream - only 0s and 1s
        if let Some(invalid_bit) = bitstring
            .chars()
            .find(|c| *c != '0' && *c != '1' && *c != '\n' && *c != ' ')
        {
            return Err(BitkitError::InvalidBit(invalid_bit));
        }
        if bitstring.is_empty() || bitstring.trim().is_empty() {
            return Err(BitkitError::EmptyString);
        }
        Ok(Bitstream {
            bits: bitstring
                .chars()
                .filter(|chr| !chr.is_whitespace())
                .collect::<String>(),
        })
    }
    /// Number of bits in the Bitstream
    pub fn len(&self) -> usize {
        self.bits.len()
    }
    /// The Bitstream should never be empty if constructed using Bistream::new()
    pub fn is_empty(&self) -> bool {
        self.bits.is_empty()
    }
    /// Use to index into the Bitstream
    pub fn bit_at(&self, index: usize) -> u8 {
        self.bits.as_bytes()[index] - b'0'
    }
    /// Chunk the Bitstream up into symbols of length `symlen`. The last symbol will be shorter
    /// if the Bitstream is not evenly divisible by `symlen`.
    pub fn symbols(&self, symlen: usize) -> Vec<String> {
        self.bits
            .chars()
            .collect::<Vec<char>>()
            .chunks(symlen)
            .map(|slice_itr| slice_itr.iter().collect::<String>())
            .collect::<Vec<String>>()
    }
    /// Chunk the Bitstream into symbols of length `symlen`, then show those symbols as
    /// hexadecimal. If there is a chunk of bits at the end shorter than symlen, left pad with
    /// zeroes for the purposes of displaying hex.
    /// Thus if the last incomplete chunk is "1" with symlen=4, it becomes "0001".
    pub fn to_hex(&self, symlen: usize) -> String {
        self.symbols(symlen)
            .iter()
            .map(|sym| {
                let sym_val = u8::from_str_radix(&format!("{:0>symlen$}", sym), 2).unwrap();
                format!("{:x}", sym_val)
            })
            .collect::<String>()
    }
    /// Build a frequency map of all symbols of length `symlen` in this Bitstream.
    /// counts_accumulator is passed in so it can be used across multiple Bitstreams.
    /// If the bitstring length is not evenly divisible by symlen, the last chunk of bits is
    /// dropped.
    fn accumulate_sym_counts(&self, symlen: usize, counts_accumulator: &mut HashMap<String, u32>) {
        let syms: Vec<String> = self.symbols(symlen);
        for sym in syms {
            if sym.len() < symlen {
                continue;
            }
            counts_accumulator
                .entry(sym)
                .and_modify(|ct| *ct += 1)
                .or_insert(1);
        }
    }
    /// Build a frequency map of all possible substrings of length `strlen` in this Bitstream.
    /// counts_accumulator is passed in so it can accumulate across multiple Bitstreams.
    fn accumulate_substr_counts(
        &self,
        strlen: usize,
        counts_accumulator: &mut HashMap<String, u32>,
    ) {
        let i_range = self.len() - strlen + 1;
        for i in 0..i_range {
            let slice = &self.bits[i..i + strlen];
            counts_accumulator
                .entry(slice.to_string())
                .and_modify(|ct| *ct += 1)
                .or_insert(1);
        }
    }
    /// Get the frequency count of each symbol of length `symlen` in this Bitstream.
    pub fn get_sym_counts(&self, symlen: usize) -> HashMap<String, u32> {
        let mut counts = HashMap::new();
        self.accumulate_sym_counts(symlen, &mut counts);
        counts
    }
    /// Get the frequency count of each possible substring of length `strlen` in this Bitstream.
    pub fn get_substr_counts(&self, strlen: usize) -> HashMap<String, u32> {
        let mut counts = HashMap::new();
        self.accumulate_substr_counts(strlen, &mut counts);
        counts
    }
    /// Get symbol frequency counts as a percentage (0.0 - 1.0) of all the symbols
    pub fn get_percents(&self, symlen: usize) -> HashMap<String, f32> {
        let counts = self.get_sym_counts(symlen);
        let total = counts.values().copied().sum::<u32>() as f32;
        counts
            .into_iter()
            .map(|(k, v)| (k, v as f32 / total))
            .collect::<HashMap<String, f32>>()
    }
    /// Returns total entropy of the Bitstream (in bits) using symbols of length `symlen`
    /// Comparing the Bitstream entropy using different symbol lengths may help infer what the correct symbol length is.
    pub fn get_total_entropy(&self, symlen: usize) -> f32 {
        let pcts = self.get_percents(symlen);
        pcts.values()
            .filter(|v| **v != 0.0)
            .map(|p| -p * p.log2())
            .sum()
    }
    /// Self-information (in bits) of each symbol found in the Bitstream
    pub fn get_self_information(&self, symlen: usize) -> HashMap<String, f32> {
        let pcts = self.get_percents(symlen);
        pcts.into_iter()
            .filter(|(_, pct)| *pct != 0.0)
            .map(|(sym, pct)| (sym, -pct.log2()))
            .collect::<HashMap<String, f32>>()
    }
} // impl Bitstream

impl fmt::Display for Bitstream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} len={}", self.bits, self.len())
    }
}

// fn find_lcs TODO
/// Find the common prefix bits across multiple Bitstreams.
/// Use to identify potential preamble bits
pub fn find_common_prefix(bitstrs: &[Bitstream]) -> String {
    if bitstrs.is_empty() {
        return String::from("");
    } else if bitstrs.len() == 1 {
        return bitstrs[0].bits.clone();
    }
    let mut prefix = bitstrs[0].bits.clone();
    let bits_iter = bitstrs.iter().skip(1);
    for bitstr in bits_iter {
        let matching = prefix
            .chars()
            .zip(bitstr.bits.chars())
            .take_while(|(x, y)| x == y)
            .map(|(x, _)| x)
            .collect::<String>();
        prefix = matching;
    }

    prefix
}
/// The binary entropy of each bit position in a vector of Bitstreams.
/// Helpful when identifying which bit positions are fixed and which are varying.
/// Assumes the Bitstreams are aligned, and truncates to the shortest Bitstream.
pub fn positionwise_entropy(bitstrs: &[Bitstream]) -> Vec<f32> {
    let min_len = bitstrs.iter().map(|b| b.len()).min().unwrap_or(0);
    if min_len == 0 {
        return vec![];
    }
    let num_bitstrs = bitstrs.len() as f32;
    let mut probs = vec![0.0f32; min_len];
    for bs in bitstrs {
        for (idx, prob) in probs.iter_mut().enumerate().take(min_len) {
            *prob += bs.bit_at(idx) as f32;
        }
    }
    for prob in probs.iter_mut() {
        *prob /= num_bitstrs;
    }
    // Binary entropy:
    // H(X)=-plog(p) - (1-p)log(1-p)
    probs
        .iter()
        .map(|p| {
            if *p == 0.0 || *p == 1.0 {
                0.0
            } else {
                -p * p.log2() - (1_f32 - p) * (1_f32 - p).log2()
            }
        })
        .collect()
}
/// Find the symbol alphabet (the full set of symbols that actually occur)
/// across multiple Bitstreams.
pub fn get_alphabet(bitstrs: &[Bitstream], symlen: usize) -> HashSet<String> {
    let mut counts: HashMap<String, u32> = HashMap::new();
    for bitstr in bitstrs {
        bitstr.accumulate_sym_counts(symlen, &mut counts);
    }
    counts.into_keys().collect::<HashSet<String>>()
}

/// Return frequency counts for the symbol alphabet (the full set of symbols that actually occur)
/// across multiple Bitstreams.
pub fn get_alphabet_counts(bitstrs: &[Bitstream], symlen: usize) -> HashMap<String, u32> {
    let mut counts: HashMap<String, u32> = HashMap::new();
    for bitstr in bitstrs {
        bitstr.accumulate_sym_counts(symlen, &mut counts);
    }
    counts
}

/// Return frequency counts for all possible substrings of length `strlen` across multiple
/// Bitstreams.
pub fn get_substr_counts(bitstrs: &[Bitstream], strlen: usize) -> HashMap<String, u32> {
    let mut counts: HashMap<String, u32> = HashMap::new();
    for bitstr in bitstrs {
        bitstr.accumulate_substr_counts(strlen, &mut counts);
    }
    counts
}

// Bitkit I/O
pub fn from_txt(filepath: impl AsRef<Path>) -> Result<Vec<Bitstream>, BitkitError> {
    let file = File::open(filepath)?;
    let reader = BufReader::new(file);

    reader
        .lines()
        .map(|line| Bitstream::new(line?))
        .collect::<Result<Vec<Bitstream>, BitkitError>>()
}

pub fn from_urh(filepath: impl AsRef<Path>) -> Result<Vec<Bitstream>, BitkitError> {
    let file = File::open(filepath)?;
    let reader = BufReader::new(file);
    let proto: URHProtocol = from_reader(reader)?;
    Ok(proto.messages.message_list)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bits_to_syms() {
        let bs = Bitstream::new("000001010011100101110111".to_string()).unwrap();
        let sym_result = vec!["000", "001", "010", "011", "100", "101", "110", "111"];
        assert_eq!(sym_result, bs.symbols(3));
    }
    #[test]
    fn test_bits_to_hex() {
        let bs = Bitstream::new("1100101010110000000001011110".to_string()).unwrap();
        let hex_result = "cab005e".to_string();
        assert_eq!(hex_result, bs.to_hex(4));
    }
    #[test]
    fn test_bits_to_hex_width_remainder() {
        let bs = Bitstream::new("11001010101100000000010111101".to_string()).unwrap();
        let hex_result = "cab005e1".to_string();
        assert_eq!(hex_result, bs.to_hex(4));
    }
    #[test]
    fn test_bit_counts() {
        let bs = Bitstream::new("110100".to_string()).unwrap();
        let mut hash_result: HashMap<String, u32> = HashMap::new();
        hash_result.insert(String::from("1"), 3);
        hash_result.insert(String::from("0"), 3);
        assert_eq!(hash_result, bs.get_sym_counts(1));
    }
    #[test]
    fn test_substr_counts() {
        let bs = Bitstream::new("10110010111".to_string()).unwrap();
        let mut hash_result: HashMap<String, u32> = HashMap::new();
        hash_result.insert(String::from("101"), 2);
        hash_result.insert(String::from("011"), 2);
        hash_result.insert(String::from("110"), 1);
        hash_result.insert(String::from("100"), 1);
        hash_result.insert(String::from("001"), 1);
        hash_result.insert(String::from("111"), 1);
        hash_result.insert(String::from("010"), 1);
        assert_eq!(hash_result, bs.get_substr_counts(3));
        let bs2 = Bitstream::new("11011010000".to_string()).unwrap();
        hash_result
            .entry("110".to_string())
            .and_modify(|ct| *ct += 2);
        hash_result
            .entry("101".to_string())
            .and_modify(|ct| *ct += 2);
        hash_result
            .entry("011".to_string())
            .and_modify(|ct| *ct += 1);
        hash_result
            .entry("010".to_string())
            .and_modify(|ct| *ct += 1);
        hash_result
            .entry("100".to_string())
            .and_modify(|ct| *ct += 1);
        hash_result.insert("000".to_string(), 2);
        assert_eq!(hash_result, get_substr_counts(&vec![bs, bs2], 3));
    }
    #[test]
    fn test_bit_pcts() {
        let bs = Bitstream::new("110100".to_string()).unwrap();
        let mut hash_result: HashMap<String, f32> = HashMap::new();
        hash_result.insert(String::from("1"), 0.5);
        hash_result.insert(String::from("0"), 0.5);
        assert_eq!(hash_result, bs.get_percents(1));
    }
    #[test]
    fn test_alphabet() {
        let bs_1 = Bitstream::new("1101 0110 1011".to_string()).unwrap();
        let bs_2 = Bitstream::new("0101 0011 1011".to_string()).unwrap();
        assert_eq!(
            ["0", "1"]
                .iter()
                .map(|s| s.to_string())
                .collect::<HashSet<String>>(),
            get_alphabet(&vec![bs_1.clone()], 1)
        );
        assert_eq!(
            ["110", "101", "011"]
                .iter()
                .map(|s| s.to_string())
                .collect::<HashSet<String>>(),
            get_alphabet(&vec![bs_1.clone()], 3)
        );
        assert_eq!(
            ["1101", "0110", "1011", "0101", "0011"]
                .iter()
                .map(|s| s.to_string())
                .collect::<HashSet<String>>(),
            get_alphabet(&vec![bs_1.clone(), bs_2.clone()], 4)
        );
        let hash_result = HashMap::from([
            (String::from("1101"), 1),
            (String::from("0110"), 1),
            (String::from("1011"), 2),
            (String::from("0101"), 1),
            (String::from("0011"), 1),
        ]);
        assert_eq!(hash_result, get_alphabet_counts(&vec![bs_1, bs_2], 4));
    }
    #[test]
    fn test_get_total_entropy() {
        let bs = Bitstream::new("10101010101010".to_string()).unwrap();
        let ent = bs.get_total_entropy(1);
        assert!((ent - 1.0).abs() < 1e-6);
        let bs = Bitstream::new("1110".to_string()).unwrap();
        let ent = bs.get_total_entropy(1);
        let h = -0.75 * (0.75_f32).log2() - 0.25 * (0.25_f32).log2();
        assert!((ent - h).abs() < 1e-6);
    }
    #[test]
    fn test_get_self_info() {
        let bs = Bitstream::new("10101010101010".to_string()).unwrap();
        let self_info = bs.get_self_information(1);
        let mut self_info_itr = self_info.values();
        assert!((self_info_itr.next().unwrap() - 1.0).abs() < 1e-6);
        assert!((self_info_itr.next().unwrap() - 1.0).abs() < 1e-6);
    }
    #[test]
    fn test_common_prefix() {
        let bitstrs = vec![
            Bitstream::new("10010110100001111".to_string()).unwrap(),
            Bitstream::new("10010101".to_string()).unwrap(),
        ];
        let prefix = find_common_prefix(&bitstrs);
        assert_eq!("100101".to_string(), prefix);

        let bitstrs = vec![
            Bitstream::new("10010110".to_string()).unwrap(),
            Bitstream::new("00010110".to_string()).unwrap(),
        ];
        assert_eq!("".to_string(), find_common_prefix(&bitstrs));
    }
    #[test]
    fn test_bit_at() {
        let bs = Bitstream::new("10101011100011".to_string()).unwrap();
        assert_eq!(bs.bit_at(0), 1);
        assert_eq!(bs.bit_at(9), 0);
    }
    #[test]
    fn test_poswise_entropy() {
        let bitstrs = vec![
            Bitstream::new("0000".to_string()).unwrap(),
            Bitstream::new("1010".to_string()).unwrap(),
        ];
        let poswise_entropy = positionwise_entropy(&bitstrs);
        assert!((poswise_entropy[0] - 1.0).abs() < 1e-6);
        assert_eq!(poswise_entropy[1], 0.0);
        assert!((poswise_entropy[2] - 1.0).abs() < 1e-6);
        assert_eq!(poswise_entropy[3], 0.0);
    }
} // mod tests
