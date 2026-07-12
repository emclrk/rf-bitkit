use crate::linalg::{berlekamp_massey, BitMatrix};
use crate::proto::{extract_varying, ProtocolStructure};
use crate::{positionwise_entropy, BitkitError, Bitstream};
use crcany::crc::Computer;
use crcany::model::BitwiseModel;
use crcany::spec::Spec;
use rayon::prelude::*;

/// RankResult - result of the windowed rank analysis.
/// `rank` : the row rank of the windowed matrix
/// `width`: the width of the windowed matrix (going from index=0 to index=width - 1)
/// `diff` : the difference between the width of the window and the rank of the matrix. diff=0 means
///          full rank, diff>0 signals probable CRC bit(s) entering the window
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct RankResult {
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
    start_col: usize,
    width: usize,
    xor_val: u128,
    crc_polynomial: Vec<u8>,
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
    let mut bitmat = BitMatrix::new(&varying_bitstrs).unwrap();
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

    let ns = bitmat.nullspace();
    let k = ns.num_rows() - ns.num_cols();
    let null_vecs = ns.row_window(k).transpose();
    let polynomial = berlekamp_massey(&null_vecs[0]);
    Ok(CrcResult {
        start_col: rank_drop[0].width,
        width: polynomial.len() - 1,
        xor_val: get_xor_val(&varying_bitstrs[0], &polynomial),
        crc_polynomial: polynomial,
    })
}
/// CRC of our polynomial on a data frame with zero-state input
pub fn crc_zero_init(poly: &[u8], data_vec: &[u8]) -> u128 {
    let poly_val = poly[..poly.len() - 1]
        .iter()
        .enumerate()
        .fold(0u128, |acc, (i, &b)| acc | ((b as u128) << i));
    let spec = Spec {
        width: poly.len() as u16 - 1,
        poly: poly_val,
        init: 0u128,
        refin: false,
        refout: false,
        xorout: 0u128,
        check: 0u128,
        residue: 0u128,
        name: String::from("rf-bitkit"),
    };
    let packed: Vec<_> = data_vec
        .chunks(8)
        .map(|chunk| {
            chunk
                .iter()
                .enumerate()
                .fold(0u8, |acc, (i, &b)| acc | (b << (7 - i)))
        })
        .collect();
    let bitwise = BitwiseModel::from_spec(spec);
    Computer::crc(bitwise, &packed)
}
/// Get the value to XOR with the output of the zero-state CRC
/// If you generate a CRC using this polynomial from a data vector, XOR with the result of this
/// function. It encapsulates any initial value and final XOR value that may be used in the
/// original CRC protocol. (also depends on the data length - this will only be valid for
/// bitstreams of the same length)
pub fn get_xor_val(bs: &Bitstream, poly: &[u8]) -> u128 {
    let num_crc_bits = poly.len() - 1;
    let bits = bs.bits_as_bytes();
    let data_vec = bits[..bits.len() - num_crc_bits].to_vec();
    let crc_packed = bits[bits.len() - num_crc_bits..]
        .iter()
        .enumerate()
        .fold(0u128, |acc, (ii, &bit)| {
            acc | ((bit as u128) << (num_crc_bits - 1 - ii))
        }); // make sure to order MSB
    let linear = crc_zero_init(poly, &data_vec);
    crc_packed ^ linear
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::from_txt;

    #[test]
    fn test_crc() {
        let bitstrs = from_txt("./tests/test_bits_interlaken.txt").unwrap();
        let result = find_crc(&bitstrs).unwrap();
        assert_eq!(result.crc_polynomial, vec![1, 1, 0, 0, 1]);
        assert_eq!(result.xor_val, 0x2);
        let bits = bitstrs[2].bits_as_bytes();
        let data_vec = bits[..bits.len() - result.width].to_vec();
        let crc_packed = bits[bits.len() - result.width..]
            .iter()
            .enumerate()
            .fold(0u128, |acc, (ii, &bit)| {
                acc | ((bit as u128) << (result.width - 1 - ii))
            });
        let recovered = crc_zero_init(&result.crc_polynomial, &data_vec) ^ result.xor_val;
        assert_eq!(crc_packed, recovered);
    }
    #[test]
    fn test_crc_6() {
        let bitstrs = from_txt("./tests/test_bits_crc6.txt").unwrap();
        let result = find_crc(&bitstrs).unwrap();
        assert_eq!(result.crc_polynomial, vec![1, 1, 1, 0, 0, 1, 1]);
        let bits = bitstrs[1].bits_as_bytes();
        let data_vec = bits[..bits.len() - result.width].to_vec();
        let crc_packed = bits[bits.len() - result.width..]
            .iter()
            .enumerate()
            .fold(0u128, |acc, (ii, &bit)| {
                acc | ((bit as u128) << (result.width - 1 - ii))
            });
        let recovered = crc_zero_init(&result.crc_polynomial, &data_vec) ^ result.xor_val;
        assert_eq!(crc_packed, recovered);
    }
}
