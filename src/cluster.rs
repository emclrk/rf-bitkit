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
            .map(|ii| match bs.bit_at(*ii) {
                Ok(bitval) => {
                    if bitval == 0 {
                        '0'
                    } else {
                        '1'
                    }
                }
                Err(_e) => unreachable!(),
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
    use crate::tests::{bitstream_strategy, bitstrs_from_flat};
    use proptest::prelude::*;

    fn get_some_bitstrs() -> Vec<Bitstream> {
        vec![
            Bitstream::new("1000101111".to_string()).unwrap(),
            Bitstream::new("1001100010".to_string()).unwrap(),
            Bitstream::new("1101100010".to_string()).unwrap(),
            Bitstream::new("0000101100".to_string()).unwrap(),
            Bitstream::new("1000101110".to_string()).unwrap(),
            Bitstream::new("1101100011".to_string()).unwrap(),
        ]
    }
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
    #[test]
    fn test_cluster_length() {
        let bitstrs = vec![
            Bitstream::new("1100".to_string()).unwrap(),
            Bitstream::new("1010110".to_string()).unwrap(),
            Bitstream::new("01100".to_string()).unwrap(),
            Bitstream::new("1010".to_string()).unwrap(),
        ];
        let clusters = cluster_by_length(&bitstrs).unwrap();
        let expected = HashMap::from([
            (4, vec![&bitstrs[0], &bitstrs[3]]),
            (5, vec![&bitstrs[2]]),
            (7, vec![&bitstrs[1]]),
        ]);
        assert_eq!(clusters, expected);
    }
    #[test]
    fn test_cluster_selected() {
        let bitstrs = get_some_bitstrs();
        let clusters = cluster_by_selected(&bitstrs, &vec![2, 4, 6]).unwrap();
        let expected = HashMap::from([
            (
                "011".to_string(),
                vec![&bitstrs[0], &bitstrs[3], &bitstrs[4]],
            ),
            (
                "010".to_string(),
                vec![&bitstrs[1], &bitstrs[2], &bitstrs[5]],
            ),
        ]);
        assert_eq!(clusters, expected);
    }
    #[test]
    fn test_cluster_epsilon() {
        let bitstrs = get_some_bitstrs();
        let clusters = cluster_by_ambiguous_bits(&bitstrs, 0.7).unwrap();
        let expected = HashMap::from([
            ("00".to_string(), vec![&bitstrs[3]]),
            (
                "11".to_string(),
                vec![
                    &bitstrs[0],
                    &bitstrs[1],
                    &bitstrs[2],
                    &bitstrs[4],
                    &bitstrs[5],
                ],
            ),
        ]);
        assert_eq!(clusters, expected);
    }
    #[test]
    fn test_cluster_hdbscan() {
        let bitstrs = vec![
            Bitstream::new("0000".to_string()).unwrap(),
            Bitstream::new("0010".to_string()).unwrap(),
            Bitstream::new("0001".to_string()).unwrap(),
            Bitstream::new("1111".to_string()).unwrap(),
            Bitstream::new("0111".to_string()).unwrap(),
            Bitstream::new("1011".to_string()).unwrap(),
        ];
        let clusters = cluster_hdbscan(&bitstrs, 2).unwrap();
        assert_eq!(clusters.len(), 2);
        assert!(clusters.iter().all(|(_k, v)| v.len() == 3));
        assert!(!clusters.iter().any(|(k, _v)| *k == -1));
    }
    fn varying_len_bitstream_strategy() -> impl Strategy<Value = Vec<Bitstream>> {
        prop::collection::vec(
            (1usize..20).prop_flat_map(|lb| prop::collection::vec(0u8..=1, lb)),
            1..10,
        )
        .prop_map(|vecs| {
            vecs.into_iter()
                .map(|bits| {
                    let s: String = bits
                        .iter()
                        .map(|&b| if b == 0 { '0' } else { '1' })
                        .collect();
                    Bitstream::new(s).unwrap()
                })
                .collect()
        })
    }
    #[rustfmt::skip]
    proptest! {
        #[test]
        fn prop_cluster_length(bitstrs in varying_len_bitstream_strategy()) {
            let clusters = cluster_by_length(&bitstrs).unwrap();
            let total: usize = clusters.values().map(|v| v.len()).sum();
            prop_assert_eq!(total, bitstrs.len());
            for (key, val) in clusters.iter() {
                for bs in val.iter() {
                    prop_assert_eq!(*key, bs.len());
                }
            }
            
        }
        #[test]
        fn prop_hamming_matrix((num_bs, len_bs, bits) in bitstream_strategy()) {
            let bitstrs = bitstrs_from_flat(len_bs, &bits);
            let mat = get_hamming_mat(&bitstrs).unwrap();
            prop_assert!(
                mat.iter()
                    .all(|row| row.iter().all(|val| *val >= 0.0 && *val <= len_bs as f32))
            );
            for ii in 0..num_bs {
                prop_assert_eq!(mat[ii][ii], 0.0);
                for jj in 0..num_bs {
                    prop_assert_eq!(mat[ii][jj], mat[jj][ii]);
                }
            }
        }
        #[test]
        fn prop_cluster_total((num_bs, len_bs, bits, pos) in bitstream_strategy().prop_flat_map(
            |(nb, lb, bits)| { 
                let pos_strat = prop::collection::vec(0usize..lb, 1..=lb);
                (Just(nb), Just(lb), Just(bits), pos_strat)
            })
        ) {
            let bitstrs = bitstrs_from_flat(len_bs, &bits);
            let clusters = cluster_by_selected(&bitstrs, &pos).unwrap();
            let total: usize = clusters.iter().map(|(_,v)|v.len()).sum();
            assert_eq!(total, num_bs);
        }
    } // proptest
} // mod tests
