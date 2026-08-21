use crate::proto::ProtocolStructure;
use crate::{BitkitError, Bitstream, positionwise_entropy};
use hdbscan::{DistanceMetric, Hdbscan, HdbscanHyperParams};
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
                if bitval == 0 { '0' } else { '1' }
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

pub fn cluster_hdbscan(
    bitstrs: &[Bitstream],
    minsize: usize,
) -> Result<HashMap<i32, Vec<&Bitstream>>, BitkitError> {
    let mut bmap: HashMap<i32, Vec<&Bitstream>> = HashMap::new();
    let hamm = get_hamming_mat(bitstrs)?;
    let hp = HdbscanHyperParams::builder()
        .dist_metric(DistanceMetric::Precalculated)
        .min_cluster_size(minsize)
        .build();
    let labels = Hdbscan::new(&hamm, hp)
        .cluster()
        .map_err(|e| BitkitError::MiscellaneousError(e.to_string()))?;
    for (ii, lab) in labels.iter().enumerate() {
        bmap.entry(*lab)
            .and_modify(|ct| ct.push(&bitstrs[ii]))
            .or_insert(vec![&bitstrs[ii]]);
    }
    Ok(bmap)
}

fn get_hamming_mat(bitstrs: &[Bitstream]) -> Result<Vec<Vec<f32>>, BitkitError> {
    let num_bs = bitstrs.len();
    let mut dist_mat: Vec<Vec<f32>> = vec![Vec::with_capacity(num_bs); num_bs];
    for ii in 0..num_bs {
        for jj in 0..num_bs {
            if ii == jj {
                dist_mat[ii].push(0.0);
            } else {
                dist_mat[ii].push(bitstrs[ii].get_hamming_dist(&bitstrs[jj])? as f32);
            }
        }
    }
    Ok(dist_mat)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hamming_mat() {
        let bs1 = Bitstream::new("0000".to_string()).unwrap();
        let bs2 = Bitstream::new("1111".to_string()).unwrap();
        let bs3 = Bitstream::new("1100".to_string()).unwrap();
        let bitstrs = vec![bs1, bs2, bs3];
        let mat = get_hamming_mat(&bitstrs).unwrap();
        assert_eq!(mat[0][0], 0.0); // diagonals = 0
        assert_eq!(mat[1][1], 0.0);
        assert_eq!(mat[2][2], 0.0);
        assert_eq!(mat[0][1], mat[1][0]); // should be symmetric
        assert_eq!(mat[0][2], mat[2][0]);
        assert_eq!(mat[1][2], mat[2][1]);
        assert_eq!(mat[0][1], 4.0); // all bits differ
        assert_eq!(mat[0][2], 2.0); // 2 bits differ
    }
}
