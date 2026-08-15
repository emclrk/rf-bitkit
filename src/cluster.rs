use crate::proto::ProtocolStructure;
use crate::{positionwise_entropy, BitkitError, Bitstream};
use std::collections::HashMap;

/// Cluster the bitstreams by their ambiguous bits (based on provided epsilon)
pub fn cluster_by_ambiguous_bits(
    bitstrs: &[Bitstream],
    eps: f32,
) -> Result<HashMap<String, Vec<&Bitstream>>, BitkitError> {
    let ents = positionwise_entropy(bitstrs);
    let ps: ProtocolStructure = ProtocolStructure::infer_structure_tolerance(&ents, eps);
    let mut bmap: HashMap<String, Vec<&Bitstream>> = HashMap::new();
    for bs in bitstrs.iter() {
        let bits = ps.extract_ambiguous_bits(bs)?;
        bmap.entry(bits)
            .and_modify(|ct| ct.push(bs))
            .or_insert(vec![bs]);
    }
    Ok(bmap)
}

/// Cluster the bitstreams by the user-provided bit positions
pub fn cluster_by_selected<'a>(
    bitstrs: &'a [Bitstream],
    positions: &[usize],
) -> Result<HashMap<String, Vec<&'a Bitstream>>, BitkitError> {
    let mut bmap: HashMap<String, Vec<&'a Bitstream>> = HashMap::new();
    for bs in bitstrs.iter() {
        if let Some(idx) = positions.iter().find(|&ii| *ii >= bs.len()) {
            return Err(BitkitError::IndexError(*idx, bs.len()));
        }
        let bits = positions
            .iter()
            .map(|ii| {
                let bitval = bs.bit_at(*ii);
                if bitval == 0 {
                    '0'
                } else {
                    '1'
                }
            })
            .collect::<String>();
        bmap.entry(bits)
            .and_modify(|ct| ct.push(bs))
            .or_insert(vec![bs]);
    }
    Ok(bmap)
}

pub fn cluster_by_length(
    bitstrs: &[Bitstream],
) -> Result<HashMap<usize, Vec<&Bitstream>>, BitkitError> {
    let mut bmap: HashMap<usize, Vec<&Bitstream>> = HashMap::new();
    for bs in bitstrs.iter() {
        bmap.entry(bs.len())
            .and_modify(|ct| ct.push(bs))
            .or_insert(vec![bs]);
    }
    Ok(bmap)
}
