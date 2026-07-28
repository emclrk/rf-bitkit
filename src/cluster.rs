use crate::proto::ProtocolStructure;
use crate::{positionwise_entropy, BitkitError, Bitstream};
use std::collections::HashMap;

/// Cluster the bitstreams by their ambiguous bits (based on provided epsilon)
pub fn cluster_by_ambiguous_bits<'a>(
    bitstrs: &'a [Bitstream],
    eps: f32,
) -> Result<HashMap<String, Vec<&'a Bitstream>>, BitkitError> {
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
