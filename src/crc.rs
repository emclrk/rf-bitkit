use crate::linalg::{BitMatrix, windowed_rank};
use crate::proto::ProtocolStructure;
use crate::{BitkitError, Bitstream, positionwise_entropy};
use rand::prelude::*;
use std::cmp::{max, min};

const MAX_ITERS: usize = 10;

/// CrcResult - parameters of the found CRC
#[derive(Debug, PartialEq, Clone)]
pub struct CrcResult {
    /// `frame_start_col` - firs bit column of the CRC within the overall frame
    pub frame_start_col: usize,
    /// `start_col` - the first bit column of the CRC within the varying bits
    pub start_col: usize,
    /// `width` - number of bits in the CRC
    pub width: usize,
    /// `xor_val` - value to XOR with the result of crc_zero_init
    pub xor_val: u128,
    /// `refin` - reflect in
    pub refin: bool,
    /// `refout` - reflect out
    pub refout: bool,
    /// Score - % of ALL frames that support this CRC result
    pub score: f32,
    /// Number of RANSAC iterations that chose this result
    pub ransac_score: usize,
    /// `crc_polynomial` - the found CRC generator polynomial. poly[i] = coefficient of x^i (LSB-first).
    /// poly[0] = 1 (constant term); poly[width] = 1 (leading term, not used as XOR mask).
    pub crc_polynomial: Vec<u8>,
}
impl CrcResult {
    /// Compare two Crc results for equivalency (ignore score fields)
    fn equivalent(&self, other: &CrcResult) -> bool {
        self.frame_start_col == other.frame_start_col
            && self.start_col == other.start_col
            && self.width == other.width
            && self.xor_val == other.xor_val
            && self.refin == other.refin
            && self.refout == other.refout
            && self.crc_polynomial == other.crc_polynomial
    }
}
/// Find the CRC in the Bitstreams, if present, and the location of the CRC bits in the protocol.
/// Assumptions: Bitstreams are aligned correctly, each one is the same length, and there are enough
/// Bitstreams to reveal the CRC. That exact requirement is tricky to define precisely without
/// knowing how many data bits are in the stream, but if there are fewer samples than data bits in
/// the stream we won't be able to find CRC because we won't have enough degrees of freedom to
/// detect the drop in rank. We'll return an error if we happen to detect that the number of
/// samples is too low, but a lack of an error is not a guarantee that there are enough Bitstreams.
/// That said, if there are at least as many Bitstreams as there are varying bits in the protocol,
/// that should be enough (although it's better to have more for a safe cushion).
/// At the moment we're also assuming that the packet payload strictly precedes the CRC bits and
/// there is only one CRC in the packet.
pub fn find_crc(
    bitstrs: &[Bitstream],
    max_iters: Option<usize>,
    sample_size: Option<usize>,
    exclude_bits: &[usize],
    spec_crc: Vec<usize>,
) -> Result<CrcResult, BitkitError> {
    if bitstrs.is_empty() {
        return Err(BitkitError::EmptyVec);
    }
    let ps = ProtocolStructure::infer_structure(&positionwise_entropy(bitstrs));
    let num_iters: usize = match max_iters {
        Some(mi) => mi,
        None => MAX_ITERS,
    };
    // Use sample size if given. If not, it should be at least a little more than the number of
    // varying bits, but no less than 20, and no more than the # of the bitstrs (if # of bistrs
    // is the limiting factor, it'll most likely fail
    // down the line anyway)
    let k_samples: usize = match sample_size {
        Some(ss) => ss,
        None => min(max(ps.get_num_varying() + 1, 20), bitstrs.len()),
    };
    let mut rng = rand::rng();
    let mut candidates: Vec<Result<CrcResult, BitkitError>> = Vec::with_capacity(num_iters);
    // Try several times, with different random samples, and return the result with the highest
    // score
    let crcspec = spec_crc.first().copied().zip(spec_crc.get(1).copied());
    for _ in 0..num_iters {
        let rand_sample: Vec<_> = bitstrs.sample(&mut rng, k_samples).cloned().collect();
        match find_crc_from_varying(bitstrs, rand_sample, &ps, exclude_bits, crcspec) {
            Ok(crc_result) => {
                if let Some(Ok(existing)) = candidates
                    .iter_mut()
                    .find(|r| r.as_ref().is_ok_and(|cand| cand.equivalent(&crc_result)))
                {
                    existing.score = f32::max(existing.score, crc_result.score);
                    existing.ransac_score += 1;
                } else {
                    candidates.push(Ok(crc_result));
                }
            }
            Err(e) => candidates.push(Err(e)),
        };
    }
    // return candidate with best score
    match candidates
        .iter()
        .filter_map(|a| a.as_ref().ok())
        .max_by(|a, b| {
            a.score
                .total_cmp(&b.score)
                .then_with(|| a.ransac_score.cmp(&b.ransac_score))
        }) {
        Some(res) => Ok(res.clone()),
        None => Err(candidates
            .into_iter()
            .find_map(|r| r.err())
            .unwrap_or(BitkitError::NoCrcFound)),
    }
}
/// Do the actual work to find the CRC. Expects a slice of Bitstreams composed of only the varying
/// bits from the protocol.
pub(crate) fn find_crc_from_varying(
    all_bitstrs: &[Bitstream],
    sampled_bitstrs: Vec<Bitstream>,
    ps: &ProtocolStructure,
    exclude_bits: &[usize],
    spec_crc: Option<(usize, usize)>,
) -> Result<CrcResult, BitkitError> {
    let mut sampled_varying_bitstrs: Vec<Bitstream> = sampled_bitstrs
        .iter()
        .map(|bs| ps.extract_varying_bits(bs).and_then(Bitstream::new))
        .collect::<Result<Vec<_>, _>>()?;
    let varying_locs = ps.extract_varying_locs(&sampled_bitstrs[0])?;
    let exclude_locs = exclude_bits
        .iter()
        .filter_map(|ii| varying_locs.iter().position(|val| val == ii))
        .collect::<Vec<usize>>();
    for bs in sampled_varying_bitstrs.iter_mut() {
        for ii in exclude_locs.iter().rev() {
            bs.remove_bit(*ii);
        }
    }
    let all_bitmat = BitMatrix::new(all_bitstrs)?;
    let mut varying_bitmat = BitMatrix::new(&sampled_varying_bitstrs)?;
    varying_bitmat.remove_affine();
    let base_rank = varying_bitmat.mat_rank()?;
    if base_rank == sampled_varying_bitstrs.len() - 1 {
        let error_msg: String = format!(
            "Matrix rank {} is too low to detect CRC with linear algebra methods. \
                More bitstream samples needed",
            base_rank
        );
        return Err(BitkitError::CrcInsufficientSamples(error_msg));
    }
    let filtered_varying_locs: Vec<usize> = varying_locs
        .iter()
        .enumerate()
        .filter(|(ii, _)| !exclude_locs.contains(ii))
        .map(|(_, &loc)| loc)
        .collect();
    let start_col = match spec_crc.filter(|(c, _)| filtered_varying_locs.contains(c)) {
        Some((startcol, _)) => filtered_varying_locs
            .iter()
            .position(|val| *val == startcol)
            .expect("guaranteed by filter above"),
        None => {
            // warn if spec_crc was provided but filtered out
            if spec_crc.is_some() {
                log::warn!(
                    "--spec-crc start column is not a varying bit; falling back to auto-detection"
                );
            }
            let ranks = windowed_rank(&varying_bitmat)?;
            let mut rank_drop: Vec<_> = ranks.iter().filter(|res| res.diff > 0).collect();
            if rank_drop.is_empty() {
                let error_msg = String::from(
                    "No rank drop detected - no CRC present or maybe insufficient data",
                );
                return Err(BitkitError::MiscellaneousError(error_msg));
            }
            rank_drop.sort_by_key(|r| r.width);
            let mut prev = rank_drop[0];
            // Check for contiguous CRC bits
            for entry in &rank_drop[1..] {
                if entry.width != prev.width + 1 || entry.rank != prev.rank {
                    // Candidate CRC fields are NOT contiguous. Either something unexpected is going on
                    // (weird data) or the CRC is interleaved or something. More investigation needed.
                    let global_exclude_locs: Vec<_> =
                        exclude_locs.iter().map(|ii| varying_locs[*ii]).collect();
                    let mod_ps = ps.set_exclude_to_fixed(&global_exclude_locs);
                    return Err(BitkitError::CrcFieldDiscontinuity(ranks, mod_ps));
                }
                prev = *entry;
            }
            rank_drop[0].width - 1
        }
    };
    debug_assert!(base_rank <= varying_bitmat.num_rows());
    let crc_width = if let Some((_, width)) = spec_crc {
        width
    } else {
        varying_bitmat.num_cols() - base_rank
    };
    let mut cands = construct_crc(&varying_bitmat, start_col, crc_width, base_rank)?;
    let sample = sampled_bitstrs[0].clone(); // TODO...does it matter which one we use for finding xor val?
    // Score candidates
    for cand in cands.iter_mut() {
        cand.frame_start_col = filtered_varying_locs[cand.start_col]; // update with location in frame
        cand.xor_val = get_xor_val(
            &sample,
            &cand.crc_polynomial,
            cand.frame_start_col,
            cand.refin,
            cand.refout,
        );
        for row in 0..all_bitmat.num_rows() {
            let calc_crc_val = crc_zero_init(
                &cand.crc_polynomial,
                &all_bitmat[row][0..cand.frame_start_col],
                cand.refin,
                cand.refout,
            );
            let crc_packed = all_bitmat[row]
                [cand.frame_start_col..cand.frame_start_col + crc_width]
                .iter()
                .enumerate()
                .fold(0u128, |acc, (ii, &bit)| {
                    acc | ((bit as u128) << (crc_width - 1 - ii))
                }); // first bit in frame → bit (crc_width-1); matches crc_zero_init output
            if calc_crc_val ^ cand.xor_val == crc_packed {
                cand.score += 1.0;
            }
        }
    }
    // TODO - handle cases of ties - maybe return both?
    if let Ok(mut best) = cands
        .into_iter()
        .max_by_key(|cand| cand.score as u32)
        .ok_or(BitkitError::NoCrcFound)
    {
        best.score /= all_bitmat.num_rows() as f32;
        Ok(best)
    } else {
        Err(BitkitError::NoCrcFound)
    }
}
/// Construct candidate CRCs. Will construct all (4) combinations of refin and refout
fn construct_crc(
    bitmat: &BitMatrix,
    start_col: usize,
    crc_width: usize,
    base_rank: usize,
) -> Result<Vec<CrcResult>, BitkitError> {
    let mut bitmats: Vec<_> = vec![(bitmat.clone(), false, false)];
    // refin=true
    let refin_mat = reflect_mat(bitmat.clone(), 0, start_col);
    // refout=true
    let refinout_mat = reflect_mat(refin_mat.clone(), start_col, crc_width);
    bitmats.push((refinout_mat, true, true));
    bitmats.push((refin_mat, true, false));
    // refin=false, refout=true
    let refout_mat = reflect_mat(bitmat.clone(), start_col, crc_width);
    bitmats.push((refout_mat, false, true));
    let mut crc_results: Vec<CrcResult> = vec![];
    for (mat, refin, refout) in bitmats.into_iter() {
        let solved = mat.rref()?;
        // k=start_col, w=crc_width, polynomial at G[k-w-1]
        let g_mat = solved.window(start_col, crc_width)?;
        let mut polynomial = g_mat[base_rank - 1].to_vec();
        polynomial.reverse(); // MSB first in the matrix; needs to be LSB first
        polynomial.push(1); // add leading x^w term
        crc_results.push(CrcResult {
            frame_start_col: start_col, // temporary - we dont have frame context here
            start_col,
            width: crc_width,
            xor_val: 0x0, // placeholder - this needs to be computed from a full frame
            refin,
            refout,
            ransac_score: 1,
            score: 0f32,
            crc_polynomial: polynomial,
        });
    }
    Ok(crc_results)
}
/// Do bit reflection in the matrix (for refin/refout cases)
fn reflect_mat(mut bitmat: BitMatrix, start_col: usize, num_bits: usize) -> BitMatrix {
    for row in 0..bitmat.num_rows() {
        let refl_data = reflect_vec(&bitmat[row][start_col..start_col + num_bits]);
        bitmat[row][start_col..start_col + num_bits].copy_from_slice(&refl_data);
    }
    bitmat
}
/// Reflect the bits in the data vector. If data is byte aligned, each byte will be individually
/// reflected; if not (as in, say, CRC-5/USB header), the entire thing will be reflected.
pub(crate) fn reflect_vec(data: &[u8]) -> Vec<u8> {
    if data.len().is_multiple_of(8) {
        data.chunks(8)
            .flat_map(|chunk| chunk.iter().rev().copied())
            .collect::<Vec<_>>()
    } else {
        data.iter().rev().copied().collect::<Vec<_>>()
    }
}
/// Reverse bit order of the low `width` bits of `val` (for implementing refout)
pub(crate) fn reflect_bits(val: u128, width: usize) -> u128 {
    (0..width).fold(0u128, |acc, i| acc | (((val >> i) & 1) << (width - 1 - i)))
}
// LSB-first: bit i of the result = coefficient of x^i = poly[i]. Drops the leading x^w term.
// Distinct from bitvec_to_u128, which is MSB-first numeric packing.
fn poly_to_u128(poly: &[u8]) -> u128 {
    poly[..poly.len() - 1]
        .iter()
        .enumerate()
        .fold(0u128, |acc, (i, &b)| acc | ((b as u128) << i))
}
// CRC of our polynomial on a data frame with zero-state input.
// Returns a u128 where bit (width-1) is the first-transmitted CRC bit (register MSB).
// Consistent with crc_packed convention: first bit in frame → bit (width-1).
// (polynomial is still LSB-first)
fn crc_zero_init(poly: &[u8], data_vec: &[u8], refin: bool, refout: bool) -> u128 {
    let width = poly.len() - 1;
    let poly_mask = poly_to_u128(poly);
    let mask: u128 = (1u128 << width) - 1;
    let bits: Vec<u8> = if refin {
        reflect_vec(data_vec)
    } else {
        data_vec.to_vec()
    };
    let mut crc: u128 = 0;
    for &bit in &bits {
        let feedback = ((crc >> (width - 1)) & 1) ^ (bit as u128);
        crc = (crc << 1) & mask;
        if feedback != 0 {
            crc ^= poly_mask;
        }
    }
    if refout {
        reflect_bits(crc, width)
    } else {
        crc
    }
}
/// Get the value to XOR with the output of the zero-state CRC
/// If you generate a CRC using this polynomial from a data vector, XOR with the result of this
/// function. It encapsulates any initial value and final XOR value that may be used in the
/// original CRC protocol. (also depends on the data length - this will only be valid for
/// bitstreams of the same length)
fn get_xor_val(bs: &Bitstream, poly: &[u8], start_col: usize, refin: bool, refout: bool) -> u128 {
    let num_crc_bits = poly.len() - 1;
    let bits = bs.bits_as_bytes();
    let data_vec: Vec<u8> = bits[..start_col]
        .iter()
        .chain(bits[start_col + num_crc_bits..].iter())
        .copied()
        .collect();
    let crc_packed = bits[start_col..start_col + num_crc_bits]
        .iter()
        .enumerate()
        .fold(0u128, |acc, (ii, &bit)| {
            acc | ((bit as u128) << (num_crc_bits - 1 - ii))
        }); // first bit in frame → bit (num_crc_bits-1); matches crc_zero_init output
    let linear = crc_zero_init(poly, &data_vec, refin, refout);
    crc_packed ^ linear
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{get_more_bitstrs, get_some_bitstrs};
    use crate::{bitvec_to_u128, from_txt};
    use proptest::prelude::*;

    fn test_crc(
        bitstrs: &[Bitstream],
        expected_poly: u128,
        max_iters: Option<usize>,
        exclude_bits: &[usize],
        crc_loc: Vec<usize>,
    ) -> CrcResult {
        let result = find_crc(&bitstrs, max_iters, None, exclude_bits, crc_loc).unwrap();
        assert_eq!(poly_to_u128(&result.crc_polynomial), expected_poly);
        let bits = bitstrs[2].bits_as_bytes();
        let data_vec: Vec<_> = bits[0..result.frame_start_col]
            .iter()
            .chain(bits[result.frame_start_col + result.width..].iter())
            .copied()
            .collect();
        let crc_packed = bits[result.frame_start_col..result.frame_start_col + result.width]
            .iter()
            .enumerate()
            .fold(0u128, |acc, (ii, &bit)| {
                acc | ((bit as u128) << (result.width - 1 - ii))
            });
        let recovered = crc_zero_init(
            &result.crc_polynomial,
            &data_vec,
            result.refin,
            result.refout,
        ) ^ result.xor_val;
        assert_eq!(crc_packed, recovered);
        result
    }

    #[test]
    fn test_crc_interlaken() {
        // refin=false refout=false, nonzero init and xorout
        // also tests alternating data and fixed fields
        let bitstrs = from_txt("./tests/test_packets_00.txt").unwrap();
        let result = test_crc(&bitstrs, 0x3, Some(10), &[], vec![]);
        assert_eq!(result.frame_start_col, 108);
    }
    #[test]
    fn test_crc_interlaken_corrupted() {
        let mut bitstrs = from_txt("./tests/test_packets_00.txt").unwrap();
        let mut byte_vec = bitstrs[0].bitstring().into_bytes();
        byte_vec[55] ^= 1;
        bitstrs[0] = Bitstream::new(String::from_utf8(byte_vec).unwrap()).unwrap();
        let result = test_crc(&bitstrs, 0x3, Some(50), &[], vec![]);
        assert_eq!(result.frame_start_col, 108);
    }
    #[ignore]
    #[test]
    fn test_crc_usb5_header() {
        // refin=true refout=true, nonzero init and xorout, not byte aligned (11 bits)
        let bitstrs = from_txt("./tests/test_bits_crc5usb.txt").unwrap();
        let _ = test_crc(&bitstrs, 0x5, Some(1), &[], vec![]);
    }
    #[test]
    fn test_crc_7mmc() {
        // byte-aligned, refin=false/refout=false, no init or xorout
        let bitstrs = from_txt("./tests/test_bits_crc7mmc.txt").unwrap();
        let _ = test_crc(&bitstrs, 0x9, Some(1), &[], vec![]);
    }
    #[test]
    fn test_crc_8_bluetooth() {
        // refin=true and refout=true, byte aligned
        let bitstrs = from_txt("./tests/test_packets_01.txt").unwrap();
        let _ = test_crc(&bitstrs, 0xa7, Some(1), &[], vec![]);
    }
    #[test]
    fn test_crc_12umts() {
        // refin=false, refout=true, crc_width=12 (%8!=0)
        let bitstrs = from_txt("./tests/test_bits_crc12umts.txt").unwrap();
        let _ = test_crc(&bitstrs, 0x80f, Some(1), &[], vec![]);
    }
    #[test]
    fn test_reflect() {
        let matrix = BitMatrix::new(&vec![
            Bitstream::new(String::from("01010101")).unwrap(),
            Bitstream::new(String::from("10101010")).unwrap(),
            Bitstream::new(String::from("01010101")).unwrap(),
            Bitstream::new(String::from("10101010")).unwrap(),
        ])
        .unwrap();
        let expected = BitMatrix::new(&vec![
            Bitstream::new(String::from("10101010")).unwrap(),
            Bitstream::new(String::from("01010101")).unwrap(),
            Bitstream::new(String::from("10101010")).unwrap(),
            Bitstream::new(String::from("01010101")).unwrap(),
        ])
        .unwrap();
        assert_eq!(expected, reflect_mat(matrix, 0, 8));
    }
    #[test]
    fn test_schrader_bitexclude() {
        let bitstrs = from_txt("./tests/test_schrader_rtl433.txt").unwrap();
        let err_result = find_crc(&bitstrs, None, None, &[], vec![]);
        assert!(err_result.is_err());
        assert!(matches!(
            err_result,
            Err(BitkitError::CrcFieldDiscontinuity(..))
        ));
        let exclude = vec![11];
        let _ = test_crc(&bitstrs, 0x7, None, &exclude, vec![]);
    }
    #[test]
    fn test_get_xor_val() {
        let bitstr =
            Bitstream::new("011001001101101111001101010011111100101100000100".to_string()).unwrap();
        let xor = get_xor_val(&bitstr, &vec![1, 0, 1, 1, 0, 0, 1], 12, false, false);
        println!("val: {:x}", xor);
        assert_eq!(xor, 0x3D);
    }
    #[test]
    fn test_find_crc_errorpaths() {
        let bitstrs: Vec<Bitstream> = get_some_bitstrs()
            .into_iter()
            .chain(get_more_bitstrs())
            .collect();
        assert!(matches!(
            find_crc(&vec![], None, None, &vec![], vec![]),
            Err(BitkitError::EmptyVec)
        ));
        // there are 20 varying bits, so 8 streams is definitely not enough
        assert!(matches!(
            find_crc(&bitstrs[..8], None, None, &vec![], vec![]),
            Err(BitkitError::CrcInsufficientSamples(_))
        ));
        // remove the crc bits
        let new_bitstrs = bitstrs
            .into_iter()
            .map(|bs| bs.truncate(bs.len() - 8).unwrap())
            .collect::<Vec<_>>();
        assert!(matches!(
            find_crc(&new_bitstrs, None, Some(new_bitstrs.len()), &vec![], vec![]),
            Err(BitkitError::MiscellaneousError(_))
        ));
    }
    #[rustfmt::skip]
    proptest! {
        #[test]
        fn prop_reflect_vec(
            (_num_bits, bits) in ((1usize..20).prop_flat_map(|nb|
                (Just(nb), prop::collection::vec(0u8..=1u8, nb)))
        )) {
           let refl_vec = reflect_vec(&bits);
           let refl_vec2 =  reflect_vec(&refl_vec);
           let bitvec_u128: u128 = bitvec_to_u128(&bits).unwrap();
           let refl_bits = reflect_bits(bitvec_u128, bits.len());
           let refl_bits2 = reflect_bits(refl_bits, bits.len());
           prop_assert_eq!(bits, refl_vec2);
           prop_assert_eq!(bitvec_u128, refl_bits2);
        }
        #[test]
        fn prop_gencrc_crczero(
            (width, poly, refin, refout, data) in (1usize..=16).prop_flat_map(|width| {
                let max_val = (1u128 << width) - 1;
                (
                    Just(width),
                    0u128..=max_val, // poly
                    any::<bool>(), // refin
                    any::<bool>(), // refout
                    prop::collection::vec(0u8..=1u8, 1..=64)
                )
        })
        ) {
            let mut poly_vec: Vec<u8> = (0..width).map(|ii| ((poly >> ii) & 1) as u8).collect();
            poly_vec.push(1);  // leading 1
            let gen_result = bitvec_to_u128(
                &crate::spec::PacketSpec::gen_crc(width, poly, 0, refin, refout, 0, &data).unwrap()
            ).unwrap();
            let zero_init_result = crc_zero_init(&poly_vec, &data, refin, refout);
            prop_assert_eq!(gen_result, zero_init_result);
        }
    } // proptest
} // mod tests
