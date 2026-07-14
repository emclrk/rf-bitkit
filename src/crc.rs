use crate::linalg::{berlekamp_massey, BitMatrix};
use crate::proto::{extract_varying, ProtocolStructure};
use crate::{positionwise_entropy, BitkitError, Bitstream};
use rayon::prelude::*;

/// RankResult - result of the windowed rank analysis.
/// `rank` : the row rank of the windowed matrix
/// `width`: the width of the windowed matrix (going from index=0 to index=width - 1)
/// `diff` : the difference between the width of the window and the rank of the matrix. diff=0 means
///          full rank, diff>0 signals probable CRC bit(s) entering the window
#[derive(Debug, PartialEq, Clone, Copy)]
struct RankResult {
    rank: usize,
    width: usize,
    diff: usize,
}
/// CrcResult - parameters of the found CRC
/// `start_col` - the first bit column of the CRC
/// `width` - number of bits in the CRC
/// `xor_val` - value to XOR with the result of crc_zero_init
/// `crc_polynomial` - the found CRC generator polynomial
#[derive(Debug, PartialEq)]
pub struct CrcResult {
    pub start_col: usize,
    pub width: usize,
    pub xor_val: u128,
    pub refin: bool,
    pub refout: bool,
    pub score: f32,
    pub crc_polynomial: Vec<u8>,
}
/// Find the CRC in the Bitstreams, if present, and the location of the CRC bits in the protocol.
/// Assumptions: Bitstreams are aligned correctly, each one is the same length, **the bitstreams are
/// noiseless** (will implement improvements to loosen that requirement later) and there are enough
/// Bitstreams to reveal the CRC. That exact requirement is tricky to define precisely without
/// knowing how many data bits are in the stream, but if there are fewer samples than data bits in
/// the stream we won't be able to find CRC because we won't have enough degrees of freedom to
/// detect the drop in rank. We'll return an error if we happen to detect that the number of
/// samples is too low, but a lack of an error is not a guarantee that there are enough Bitstreams.
/// That said, if there are at least as many Bitstreams as there are varying bits in the protocol,
/// that should be enough (although it's better to have more for a safe cushion).
pub fn find_crc(bitstrs: &[Bitstream]) -> Result<CrcResult, BitkitError> {
    let ps = ProtocolStructure::infer_structure(&positionwise_entropy(bitstrs));
    let varying_bitstrs: Vec<Bitstream> = bitstrs
        .iter()
        .map(|bs| extract_varying(bs, &ps).and_then(Bitstream::new))
        .collect::<Result<Vec<_>, _>>()?;
    find_crc_from_varying(varying_bitstrs)
}
/// Do the actual work to find the CRC. Expects a slice of Bitstreams composed of only the varying
/// bits from the protocol.
pub fn find_crc_from_varying(varying_bitstrs: Vec<Bitstream>) -> Result<CrcResult, BitkitError> {
    // XORing to remove any affine element (eg if the CRC was initialized or XOR'd by a constant)
    let orig_bitmat = BitMatrix::new(&varying_bitstrs)?;
    let mut bitmat = orig_bitmat.clone();
    for ii in 1..bitmat.num_rows() {
        for jj in 0..bitmat.num_cols() {
            bitmat[ii][jj] ^= bitmat[0][jj];
        }
    }
    // zero out this row - since it was xor'd with everything else it's no longer contributing to
    // the rowspace
    for jj in 0..bitmat.num_cols() {
        bitmat[0][jj] = 0;
    }
    let base_rank = bitmat.mat_rank();
    if base_rank == varying_bitstrs.len() - 1 {
        let error_msg: String = format!(
            "Matrix rank {} is too low to detect CRC with linear algebra methods. \
                More bitstream samples needed",
            base_rank
        );
        return Err(BitkitError::MiscellaneousError(error_msg));
    }
    // For now, we're doing an exhaustive search, fully aware that this is dumb, but at least it's
    // threaded. We don't want to miss it if it's in weird place.
    let mut rank_drop: Vec<RankResult> = (1..=bitmat.num_cols())
        .into_par_iter()
        .map(|width| {
            let rank = bitmat.window(0, width).unwrap().mat_rank();
            RankResult {
                rank,
                width,
                diff: width - rank,
            }
        })
        .filter(|res| res.diff > 0)
        .collect();
    if rank_drop.is_empty() {
        let error_msg =
            String::from("No rank drop detected - no CRC present or maybe insufficient data");
        return Err(BitkitError::MiscellaneousError(error_msg));
    }
    rank_drop.sort_by_key(|r| r.width);
    let mut prev = rank_drop[0];
    // Check for contiguous CRC bits
    for entry in &rank_drop[1..] {
        if entry.width != prev.width + 1 || entry.rank != prev.rank {
            return Err(BitkitError::MiscellaneousError(
                "Candidate CRC fields are NOT contiguous. Either something unexpected is going on\
                (weird data) or the CRC is interleaved or something. More investigation needed."
                    .to_string(),
            ));
        }
        prev = *entry;
    }
    // TODO
    // construct bitmat from the *found* potetntial crc locations
    let start_col = rank_drop[0].width - 1;
    let crc_width = bitmat.num_cols() - base_rank;
    let mut cands = construct_crc(&bitmat, &varying_bitstrs[0], start_col, crc_width)?;
    for cand in cands.iter_mut() {
        for row in 0..bitmat.num_rows() {
            let calc_crc_val = crc_zero_init(
                &cand.crc_polynomial,
                &orig_bitmat[row][0..start_col],
                cand.refin,
                cand.refout,
            );
            let crc_packed = orig_bitmat[row][start_col..start_col + crc_width]
                .iter()
                .enumerate()
                .fold(0u128, |acc, (ii, &bit)| {
                    acc | ((bit as u128) << (crc_width - 1 - ii))
                }); // make sure to order MSB
            if calc_crc_val ^ cand.xor_val == crc_packed {
                cand.score += 1.0;
            }
        }
    }
    if let Ok(mut best) = cands
        .into_iter()
        .max_by_key(|cand| cand.score as u32)
        .ok_or_else(|| BitkitError::MiscellaneousError("No CRC candidates found".to_string()))
    {
        best.score /= bitmat.num_rows() as f32;
        Ok(best)
    } else {
        Err(BitkitError::MiscellaneousError(
            "No CRC candidates found".to_string(),
        ))
    }
}
/// Construct candidate CRCs. Will construct all (4) combinations of refin and refout
fn construct_crc(
    bitmat: &BitMatrix,
    sample: &Bitstream,
    start_col: usize,
    crc_width: usize,
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
        let ns = mat.nullspace();
        let k = ns.num_rows() - ns.num_cols();
        // TODO test all null vecs and return the most frequent answer for robustness?
        let null_vecs = ns.row_window(k)?.transpose();
        let polynomial = berlekamp_massey(&null_vecs[0]);
        let width = polynomial.len() - 1;
        if width != crc_width {
            continue; // polynomial is the wrong width -skip
        }
        let xor_result = get_xor_val(sample, &polynomial, start_col, refin, refout);
        crc_results.push(CrcResult {
            start_col,
            width,
            xor_val: xor_result,
            refin,
            refout,
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
fn reflect_vec(data: &[u8]) -> Vec<u8> {
    if data.len() % 8 == 0 {
        data.chunks(8)
            .flat_map(|chunk| chunk.iter().rev().copied())
            .collect::<Vec<_>>()
    } else {
        data.into_iter().rev().copied().collect::<Vec<_>>()
    }
}
/// Reverse bit order of the low `width` bits of `val` (for implementing refout)
fn reflect_bits(val: u128, width: usize) -> u128 {
    (0..width).fold(0u128, |acc, i| acc | (((val >> i) & 1) << (width - 1 - i)))
}
// convert polynomial to u128 "sans width" - without the highest order element
// (standard representation)
fn poly_to_u128(poly: &[u8]) -> u128 {
    poly[..poly.len() - 1]
        .iter()
        .enumerate()
        .fold(0u128, |acc, (i, &b)| acc | ((b as u128) << i))
}
/// CRC of our polynomial on a data frame with zero-state input
fn crc_zero_init(poly: &[u8], data_vec: &[u8], refin: bool, refout: bool) -> u128 {
    let width = poly.len() - 1;
    let poly_mask = poly_to_u128(&poly);
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
        }); // make sure to order MSB
    let linear = crc_zero_init(poly, &data_vec, refin, refout);
    crc_packed ^ linear
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::from_txt;
    fn test_crc(bitstrs: &[Bitstream], expected_poly: u128) {
        let result = find_crc(&bitstrs).unwrap();
        assert_eq!(poly_to_u128(&result.crc_polynomial), expected_poly);
        // this uses the full bitstrs, will need to update if we add any tests that have fixed
        // preambles
        let bits = bitstrs[2].bits_as_bytes();
        let data_vec: Vec<_> = bits[..result.start_col]
            .iter()
            .chain(bits[result.start_col + result.width..].iter())
            .copied()
            .collect();
        let crc_packed = bits[result.start_col..result.start_col + result.width]
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
    }

    #[test]
    fn test_crc_interlaken() {
        // refin=false refout=false, nonzero init and xorout
        let bitstrs = from_txt("./tests/test_bits_interlaken.txt").unwrap();
        test_crc(&bitstrs, 0x3);
    }
    #[ignore]
    #[test]
    fn test_crc_usb5_header() {
        // refin=true refout=true, nonzero init and xorout, not byte aligned (11 bits)
        let bitstrs = from_txt("./tests/test_bits_crc5usb.txt").unwrap();
        test_crc(&bitstrs, 0x5);
    }
    #[test]
    fn test_crc_7mmc() {
        // byte-aligned, refin=false/refout=false, no init or xorout
        let bitstrs = from_txt("./tests/test_bits_crc7mmc.txt").unwrap();
        test_crc(&bitstrs, 0x9);
    }
    #[test]
    fn test_crc_8_bluetooth() {
        // refin=true and refout=true, byte aligned
        let bitstrs = from_txt("./tests/test_bits_crc8bt.txt").unwrap();
        test_crc(&bitstrs, 0xa7);
    }
    #[ignore]
    #[test]
    fn test_crc_12umts() {
        // refin=false, refout=true, crc_width=12 (%8!=0)
        let bitstrs = from_txt("./tests/test_bits_crc12umts.txt").unwrap();
        test_crc(&bitstrs, 0x80f);
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
}
