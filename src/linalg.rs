use crate::{BitkitError, Bitstream};
use rayon::prelude::*;
use std::fmt;
use std::ops::{Index, IndexMut, Mul};

/// RankResult - result of the windowed rank analysis.
/// `rank` : the row rank of the windowed matrix
/// `width`: the width of the windowed matrix (going from index=0 to index=width - 1)
/// `diff` : the difference between the width of the window and the rank of the matrix. diff=0 means
///          full rank, diff>0 signals probable CRC bit(s) entering the window
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct RankResult {
    pub rank: usize,
    pub width: usize,
    pub diff: usize,
}

/// Matrix of bits. Each row is a Bitstream. It's assumed that all Bitstreams are of the same
/// length.
#[derive(Debug, PartialEq, Clone)]
pub struct BitMatrix {
    /// bit matrix, stored row-wise
    bits: Vec<u8>,
    /// equivalent to column length
    num_rows: usize,
    /// equivalent to row length
    num_cols: usize,
    /// bool - is this a reduced row echelon form matrix
    is_rref: bool,
}

impl BitMatrix {
    /// Given a slice of Bitstreams, create a BitMatrix. Assumes all Bitstreams are of equal
    /// length.
    pub fn new(bitstrs: &[Bitstream]) -> Result<Self, BitkitError> {
        Self::new_with_rref(bitstrs, false)
    }
    pub fn from_params(
        bits: Vec<u8>,
        num_rows: usize,
        num_cols: usize,
        is_rref: bool,
    ) -> Result<Self, BitkitError> {
        if bits.len() != num_rows * num_cols {
            return Err(BitkitError::MiscellaneousError(format!(
                "Incompatible dimensions: bitvec len {} != rows*cols {}",
                bits.len(),
                num_rows * num_cols
            )));
        }
        Ok(BitMatrix {
            bits,
            num_rows,
            num_cols,
            is_rref,
        })
    }
    fn new_with_rref(bitstrs: &[Bitstream], is_rref: bool) -> Result<Self, BitkitError> {
        if bitstrs.is_empty() || bitstrs[0].is_empty() {
            return Err(BitkitError::EmptyString);
        }

        let num_rows = bitstrs.len();
        let num_cols = bitstrs[0].len();
        if let Some(bs) = bitstrs.iter().find(|x| x.len() != num_cols) {
            return Err(BitkitError::LengthMismatch(num_cols, bs.len()));
        }
        let mut bitvec: Vec<u8> = Vec::with_capacity(num_rows * num_cols);
        for bs in bitstrs {
            for bit in bs.bits.as_bytes() {
                bitvec.push(bit - b'0');
            }
        }
        assert!(bitvec.len() == num_rows * num_cols);
        Self::from_params(bitvec, num_rows, num_cols, is_rref)
    }
    pub fn new_identity(dim: usize) -> Result<Self, BitkitError> {
        if dim == 0 {
            Err(BitkitError::MiscellaneousError(
                "Can't create empty BitMatrix".to_string(),
            ))
        } else {
            let mut bitmat = Self::from_params(vec![0; dim * dim], dim, dim, true)?;
            for ii in 0..dim {
                bitmat[ii][ii] = 1;
            }
            Ok(bitmat)
        }
    }
    /// XOR to remove any affine element (eg, if a CRC was initialized or XOR'd by a constant)
    pub fn remove_affine(&mut self) {
        // xor everything with first row
        for ii in 1..self.num_rows() {
            for jj in 0..self.num_cols() {
                self[ii][jj] ^= self[0][jj];
            }
        }
        // zero out this row - since it was xor'd with everything else it no longer contributes to
        // rowspace
        for jj in 0..self.num_cols() {
            self[0][jj] = 0;
        }
    }
    pub fn is_zero(&self) -> bool {
        self.bits.iter().all(|&b| b == 0)
    }
    pub fn num_rows(&self) -> usize {
        self.num_rows
    }
    pub fn num_cols(&self) -> usize {
        self.num_cols
    }
    /// Return a new matrix that is a vertical window of this matrix.
    /// Size will be num_rows x width
    pub fn window(&self, col_start: usize, width: usize) -> Result<Self, BitkitError> {
        if col_start + width > self.num_cols || width == 0 {
            return Err(BitkitError::IndexError(col_start + width, self.num_cols));
        }
        let mut bitvec: Vec<u8> = Vec::with_capacity(self.num_rows * width);
        for ii in 0..self.num_rows {
            // indexing self returns a row slice
            bitvec.extend_from_slice(&self[ii][col_start..col_start + width]);
        }

        assert!(bitvec.len() == self.num_rows * width);
        Self::from_params(bitvec, self.num_rows, width, false)
    }
    /// Return a new matrix that is a vertical window of this matrix.
    /// Size will be height x num_cols
    pub fn row_window(&self, height: usize) -> Result<Self, BitkitError> {
        if height > self.num_rows || height == 0 {
            return Err(BitkitError::IndexError(height, self.num_rows));
        }
        Self::from_params(
            self.bits[..height * self.num_cols].to_vec(),
            height,
            self.num_cols,
            false,
        )
    }
    /// Return a new BitMatrix that is the transpose of this one
    pub fn transpose(&self) -> Result<Self, BitkitError> {
        let mut bitvec: Vec<u8> = vec![0; self.num_rows * self.num_cols];
        for row in 0..self.num_rows {
            for col in 0..self.num_cols {
                bitvec[col * self.num_rows + row] = self[row][col];
            }
        }
        Self::from_params(bitvec, self.num_cols, self.num_rows, false)
    }
    /// Swap two rows
    fn swap_rows(&mut self, row_1_idx: usize, row_2_idx: usize) {
        if row_1_idx == row_2_idx {
            return;
        }
        let row_1 = self[row_1_idx].to_vec();
        let row_2 = self[row_2_idx].to_vec();
        self.bits[row_1_idx * self.num_cols..(row_1_idx + 1) * self.num_cols]
            .copy_from_slice(&row_2);
        self.bits[row_2_idx * self.num_cols..(row_2_idx + 1) * self.num_cols]
            .copy_from_slice(&row_1);
    }

    /// Get rank of the matrix
    pub fn mat_rank(&self) -> Result<usize, BitkitError> {
        if self.is_rref {
            Ok((0..self.num_rows)
                .filter(|&ii| self[ii].iter().any(|&x| x != 0))
                .count())
        } else {
            let reduced = self.clone().rref()?;
            Ok((0..reduced.num_rows)
                .filter(|&ii| reduced[ii].iter().any(|&x| x != 0))
                .count())
        }
    } // rank
    /// Get row echelon form of the matrix
    fn row_echelon_form(self) -> Result<Self, BitkitError> {
        let mut row_ech = self;
        let mut min_row = 0;
        let mut min_col = 0;
        'outer: loop {
            let mut pivot: Option<usize> = None;
            while pivot.is_none() {
                for ii in min_row..row_ech.num_rows {
                    if row_ech[ii][min_col] == 1 {
                        pivot = Some(ii);
                        break;
                    }
                }
                if pivot.is_none() {
                    if min_col < row_ech.num_cols - 1 {
                        min_col += 1;
                    } else {
                        break 'outer;
                    }
                }
            }
            if let Some(p) = pivot {
                row_ech.swap_rows(min_row, p);
                if min_row + 1 < row_ech.num_rows {
                    for ii in min_row + 1..row_ech.num_rows {
                        if row_ech[ii][min_col] == 1 {
                            for jj in min_col..row_ech.num_cols {
                                row_ech[ii][jj] ^= row_ech[min_row][jj];
                            }
                        }
                    }
                }
                min_row += 1;
                min_col += 1;
                if min_row >= row_ech.num_rows || min_col >= row_ech.num_cols {
                    break 'outer;
                }
            }
        }
        Ok(row_ech)
    } // row_echelon_form
    /// Get reduced row echelon form of a matrix
    pub fn rref(self) -> Result<Self, BitkitError> {
        let mut result = self.row_echelon_form()?;
        for row in (0..result.num_rows).rev() {
            if let Some(pivot_col) = result[row].iter().position(|&x| x == 1) {
                let pivot_row = result[row].to_vec();
                for ii in (0..row).rev() {
                    if result[ii][pivot_col] == 1 {
                        for jj in pivot_col..result.num_cols {
                            result[ii][jj] ^= pivot_row[jj];
                        }
                    }
                }
            }
        }
        result.is_rref = true;
        Ok(result)
    } // reduced row echelon form
    /// Find the nullspace basis vectors
    pub fn nullspace(&self) -> Result<Self, BitkitError> {
        let reduced = if self.is_rref {
            self.clone()
        } else {
            self.clone().rref()?
        };
        let pivot_locs: Vec<_> = (0..reduced.num_rows())
            .map(|ii| (ii, reduced[ii].iter().position(|&x| x == 1)))
            .collect();
        let free_cols: Vec<_> = (0..reduced.num_cols())
            .filter(|ii| {
                pivot_locs
                    .iter()
                    .find(|(_x, y)| y.is_some() && y.unwrap() == *ii)
                    .is_none()
            })
            .collect();
        // make a nullspace vector for each free column
        let mut nullvecs = Vec::with_capacity(reduced.num_cols() * free_cols.len());
        for col_pos in 0..reduced.num_cols() {
            for col_num in free_cols.iter() {
                if col_pos == *col_num {
                    nullvecs.push(1);
                } else if let Some(loc) = pivot_locs.iter().find(|loc| loc.1 == Some(col_pos)) {
                    nullvecs.push(reduced[loc.0][*col_num]);
                } else {
                    nullvecs.push(0);
                }
            }
        }
        Self::from_params(nullvecs, reduced.num_cols(), free_cols.len(), false)
    } // find nullspace basis vectors
} // impl BitMatrix

impl Index<usize> for BitMatrix {
    type Output = [u8];
    fn index(&self, row: usize) -> &[u8] {
        let start = row * self.num_cols;
        &self.bits[start..start + self.num_cols]
    }
}

impl IndexMut<usize> for BitMatrix {
    fn index_mut(&mut self, row: usize) -> &mut [u8] {
        let start = row * self.num_cols;
        &mut self.bits[start..start + self.num_cols]
    }
}

impl fmt::Display for BitMatrix {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for ii in 0..self.num_rows {
            for bit in &self[ii] {
                write!(f, "| {} ", bit)?;
            }
            writeln!(f, "|")?;
        }
        Ok(())
    }
}

impl Mul for &BitMatrix {
    type Output = Result<BitMatrix, BitkitError>;

    fn mul(self, rhs: &BitMatrix) -> Self::Output {
        mat_mul_gf2(self, rhs)
    }
}

/// Find the rank in a left-to-right growing window across the BitMatrix. The rank at each position
/// is the rank of the matrix up to and including that column.
pub fn windowed_rank(bitmat: &BitMatrix) -> Result<Vec<RankResult>, BitkitError> {
    // For now, we're doing an exhaustive search, fully aware that this is dumb, but at least it's
    // threaded. We don't want to miss it if it's in weird place.
    let mut rank: Vec<RankResult> = (1..=bitmat.num_cols())
        .into_par_iter()
        .map(|width| -> Result<RankResult, BitkitError> {
            let rk = bitmat.window(0, width)?.mat_rank()?;
            Ok(RankResult {
                rank: rk,
                width,
                diff: width - rk,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    rank.sort_by_key(|r| r.width);
    Ok(rank)
}

/// Compute the dot product of two vectors over GF(2). Add = XOR, mul = AND.
pub(crate) fn dot_prod_gf2(vec1: &[u8], vec2: &[u8]) -> Result<u8, BitkitError> {
    if vec1.len() != vec2.len() {
        return Err(BitkitError::LengthMismatch(vec1.len(), vec2.len()));
    }
    Ok(vec1
        .iter()
        .zip(vec2.iter())
        .map(|(x, y)| x & y)
        .fold(0, |acc, x| acc ^ x))
}

/// Multiply two matrices over GF(2). Add = XOR, Mul = AND
pub(crate) fn mat_mul_gf2(mat1: &BitMatrix, mat2: &BitMatrix) -> Result<BitMatrix, BitkitError> {
    // sizes: nxm and mxk
    if mat1.num_cols != mat2.num_rows {
        return Err(BitkitError::MatrixMultDimError(
            mat1.num_rows,
            mat1.num_cols,
            mat2.num_rows,
            mat2.num_cols,
        ));
    }
    let mut result_vec: Vec<u8> = vec![0; mat1.num_rows * mat2.num_cols];
    let mat2_t = mat2.transpose()?;
    for row_idx in 0..mat1.num_rows {
        for col_idx in 0..mat2.num_cols {
            result_vec[row_idx * mat2.num_cols + col_idx] =
                dot_prod_gf2(&mat1[row_idx], &mat2_t[col_idx])?;
        }
    }
    BitMatrix::from_params(result_vec, mat1.num_rows, mat2.num_cols, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_window_fn() {
        let matrix = BitMatrix::new(&vec![
            Bitstream::new(String::from("10000")).unwrap(),
            Bitstream::new(String::from("11000")).unwrap(),
            Bitstream::new(String::from("11100")).unwrap(),
            Bitstream::new(String::from("11110")).unwrap(),
            Bitstream::new(String::from("11111")).unwrap(),
        ])
        .unwrap();
        let expect = BitMatrix::new(&vec![
            Bitstream::new(String::from("000")).unwrap(),
            Bitstream::new(String::from("100")).unwrap(),
            Bitstream::new(String::from("110")).unwrap(),
            Bitstream::new(String::from("111")).unwrap(),
            Bitstream::new(String::from("111")).unwrap(),
        ])
        .unwrap();
        assert_eq!(expect, matrix.window(1, 3).unwrap());
        assert!(matrix.window(7, 12).is_err());
        assert!(matrix.window(1, 7).is_err());
        assert!(matrix.window(0, 0).is_err());
    }
    #[test]
    fn test_dot_prod_gf2() {
        let v1 = vec![1, 0, 1, 0, 1, 0];
        let v2 = vec![1, 1, 0, 1, 1, 0];
        assert_eq!(dot_prod_gf2(&v1, &v2).unwrap(), 0);
        let v1 = vec![1, 0, 1, 1, 1, 1];
        let v2 = vec![1, 1, 0, 1, 1, 0];
        assert_eq!(dot_prod_gf2(&v1, &v2).unwrap(), 1);
        let v3 = vec![1, 0, 1];
        assert!(dot_prod_gf2(&v1, &v3).is_err());
    }
    #[test]
    fn test_matmul_gf2_nonsquare() {
        let mat1 = BitMatrix::new(&vec![
            Bitstream::new(String::from("011")).unwrap(),
            Bitstream::new(String::from("101")).unwrap(),
        ])
        .unwrap();
        let mat1_t = mat1.transpose().unwrap();
        let expect = BitMatrix::new(&vec![
            Bitstream::new(String::from("01")).unwrap(),
            Bitstream::new(String::from("10")).unwrap(),
        ])
        .unwrap();
        assert_eq!((&mat1 * &mat1_t).unwrap(), expect);
        let mat2 = BitMatrix::new(&vec![
            Bitstream::new("00110111000101".to_string()).unwrap(),
            Bitstream::new("11001000101111".to_string()).unwrap(),
            Bitstream::new("01010101010101".to_string()).unwrap(),
            Bitstream::new("11001100110011".to_string()).unwrap(),
        ])
        .unwrap();
        // mismatched dimensions
        assert!((&mat1 * &mat2).is_err());
    }
    #[test]
    fn test_row_ech() {
        let matrix = BitMatrix::new(&vec![
            Bitstream::new(String::from("10110")).unwrap(),
            Bitstream::new(String::from("01010")).unwrap(),
            Bitstream::new(String::from("10101")).unwrap(),
            Bitstream::new(String::from("11000")).unwrap(),
            Bitstream::new(String::from("11111")).unwrap(),
        ])
        .unwrap();
        let row_ech = matrix.row_echelon_form().unwrap();
        let expected = BitMatrix::new(&vec![
            Bitstream::new(String::from("10110")).unwrap(),
            Bitstream::new(String::from("01010")).unwrap(),
            Bitstream::new(String::from("00100")).unwrap(),
            Bitstream::new(String::from("00011")).unwrap(),
            Bitstream::new(String::from("00000")).unwrap(),
        ])
        .unwrap();
        assert_eq!(row_ech, expected);
    }
    #[test]
    fn test_red_row_ech() {
        let matrix = BitMatrix::new(&vec![
            Bitstream::new(String::from("10110")).unwrap(),
            Bitstream::new(String::from("01010")).unwrap(),
            Bitstream::new(String::from("10101")).unwrap(),
            Bitstream::new(String::from("11000")).unwrap(),
            Bitstream::new(String::from("11111")).unwrap(),
        ])
        .unwrap();
        let rrow_ech = matrix.rref().unwrap();
        let expected = BitMatrix::new_with_rref(
            &vec![
                Bitstream::new(String::from("10001")).unwrap(),
                Bitstream::new(String::from("01001")).unwrap(),
                Bitstream::new(String::from("00100")).unwrap(),
                Bitstream::new(String::from("00011")).unwrap(),
                Bitstream::new(String::from("00000")).unwrap(),
            ],
            true,
        )
        .unwrap();
        assert_eq!(rrow_ech, expected);
    }
    #[test]
    fn test_nullspace() {
        let matrix = BitMatrix::new(&vec![
            Bitstream::new(String::from("10011")).unwrap(),
            Bitstream::new(String::from("01001")).unwrap(),
            Bitstream::new(String::from("00110")).unwrap(),
        ])
        .unwrap();
        let ns = matrix.nullspace().unwrap();
        let expected = BitMatrix::new(&vec![
            Bitstream::new(String::from("11")).unwrap(),
            Bitstream::new(String::from("01")).unwrap(),
            Bitstream::new(String::from("10")).unwrap(),
            Bitstream::new(String::from("10")).unwrap(),
            Bitstream::new(String::from("01")).unwrap(),
        ])
        .unwrap();
        assert_eq!(ns, expected);
    }
    #[test]
    fn test_err_paths() {
        assert!(BitMatrix::new(&vec![]).is_err());
        assert!(
            BitMatrix::new(&vec![
                Bitstream::new("101001".to_string()).unwrap(),
                Bitstream::new("010".to_string()).unwrap()
            ])
            .is_err()
        );
    }
    #[rustfmt::skip]
    #[test]
    fn test_windowed_rank() {
        // cols 0, 1, 3, 4, 7 are indpendent
        // col2 = col0^col1
        // col5 = col0^col2
        // col6 = col3^col4
        let bits = vec![
            1, 0, 1, 1, 0, 0, 1, 0,
            0, 0, 0, 0, 0, 0, 0, 1,
            0, 1, 1, 0, 1, 1, 1, 0,
            1, 0, 1, 0, 1, 0, 1, 0,
            1, 0, 1, 1, 1, 0, 0, 1,
            0, 1, 1, 0, 1, 1, 1, 0,
            1, 0, 1, 0, 1, 0, 1, 0,
            0, 0, 0, 1, 0, 0, 1, 1,
            0, 0, 0, 0, 0, 0, 0, 1,
            0, 0, 0, 0, 1, 0, 1, 1
        ];
        let bitmat = BitMatrix::from_params(bits, 10, 8, false).unwrap();
        let winrank = windowed_rank(&bitmat).unwrap();
        let ranks: Vec<_> = winrank.iter().map(|res| res.rank).collect();
        assert_eq!(ranks, vec![1, 2, 2, 3, 4, 4, 4, 5]);
    }
    // proptest helpers
    fn matrix_from_bitvec(_rows: usize, cols: usize, bits: &[u8]) -> BitMatrix {
        let bitstrs = bits
            .chunks(cols)
            .map(|row| {
                let s: String = row
                    .iter()
                    .map(|&b| if b == 0 { '0' } else { '1' })
                    .collect();
                Bitstream::new(s).unwrap()
            })
            .collect::<Vec<_>>();
        BitMatrix::new(&bitstrs).unwrap()
    }
    fn bitstream_strategy() -> impl Strategy<Value = (usize, usize, Vec<u8>)> {
        (1usize..100, 1usize..100)
            .prop_flat_map(|(nr, nc)| (Just(nr), Just(nc), prop::collection::vec(0u8..=1, nr * nc)))
    }
    #[rustfmt::skip]
    proptest! {
        #[test]
        fn prop_transpose((rows, cols, bits) in bitstream_strategy()) {
            let bitmat = matrix_from_bitvec(rows, cols, &bits);
            let tx = bitmat.transpose().unwrap();
            prop_assert_eq!(tx.num_rows(), bitmat.num_cols());  // num_rows -> num_cols
            prop_assert_eq!(tx.num_cols(), bitmat.num_rows());  // num_cols -> num_rows
            prop_assert_eq!(
                bitmat.mat_rank().unwrap(),
                tx.mat_rank().unwrap());  // transpose doesnt change rank
            for row in 0..rows {
                for col in 0..cols {
                    prop_assert_eq!(bitmat[row][col], tx[col][row]);
                }
            }
            let txt = tx.transpose().unwrap();
            prop_assert_eq!(txt, bitmat); // transpose(transpose(A)) == A
        }
        #[test]
        fn prop_rank_rref((rows, cols, bits) in bitstream_strategy()) {
            let bitmat = matrix_from_bitvec(rows, cols, &bits);
            let orig_rank = bitmat.mat_rank().unwrap();
            let nullspace = bitmat.nullspace().unwrap();
            let bitmat_rref = bitmat.clone().rref().unwrap();
            let rref_rank = bitmat_rref.mat_rank().unwrap();
            let rref_rref = bitmat_rref.clone().rref().unwrap();
            // rank(A) + nullity(A) = num_cols(A)
            prop_assert_eq!(orig_rank + nullspace.num_cols(), bitmat.num_cols());
            prop_assert_eq!(orig_rank, rref_rank);   // rank(A) = rank(rref(A))
            prop_assert_eq!(bitmat_rref, rref_rref); // rref(A) = rref(rref(A))
        }
        #[test]
        fn prop_window((rows, cols, bits) in bitstream_strategy()) {
            let bitmat = matrix_from_bitvec(rows, cols, &bits);
            for col_start in 0..cols {
                let max_width = cols - col_start;
                let w = bitmat.window(col_start, max_width).unwrap();
                prop_assert_eq!(w.num_rows(), rows);
                prop_assert_eq!(w.num_cols(), max_width);
                for row in 0..rows {
                    for col in 0..max_width {
                        prop_assert_eq!(w[row][col], bitmat[row][col_start + col]);
                    }
                }
            }
        }
        #[test]
        fn prop_windowed_rank_monotone((rows, cols, bits) in bitstream_strategy()) {
            let bitmat = matrix_from_bitvec(rows, cols, &bits);
            let ranks = windowed_rank(&bitmat).unwrap();
            for window in ranks.windows(2) {
                prop_assert!(window[1].rank >= window[0].rank);
            }
            prop_assert_eq!(ranks.last().unwrap().rank, bitmat.mat_rank().unwrap())
        }
        #[test]
        fn prop_nullspace((rows, cols, bits) in bitstream_strategy()) {
            let bitmat = matrix_from_bitvec(rows, cols, &bits);
            let nullspace = bitmat.nullspace().unwrap();
            let result = (&bitmat * &nullspace).unwrap();
            prop_assert!(result.is_zero());
            // also test is_zero while we're here
            prop_assert_eq!(bitmat.is_zero(), bits.iter().all(|b| *b == 0));
        }
        #[test]
        fn prop_affine_removal((rows, cols, bits) in bitstream_strategy()) {
            let mut bitmat = matrix_from_bitvec(rows, cols, &bits);
            let orig_rank = bitmat.mat_rank().unwrap();
            bitmat.remove_affine();
            let new_rank = bitmat.mat_rank().unwrap();
            prop_assert!(bitmat[0].iter().all(|b| *b == 0));
            prop_assert!(new_rank >= orig_rank.saturating_sub(1));
        }
        #[test]
        fn prop_row_window((rows, cols, bits) in bitstream_strategy()) {
            let bitmat = matrix_from_bitvec(rows, cols, &bits);
            for ht in 1..rows {
                let win = bitmat.row_window(ht).unwrap();
                prop_assert_eq!(win.num_rows(), ht);
                prop_assert_eq!(win.num_cols(), cols);
                for ii in 0..ht {
                    for jj in 0..cols {
                        prop_assert_eq!(bitmat[ii][jj], win[ii][jj]);
                    }
                }
            }
        }
        #[test]
        fn prop_identity((rows, cols, bits) in bitstream_strategy()) {
            let bitmat = matrix_from_bitvec(rows, cols, &bits);
            let ident_rt = BitMatrix::new_identity(cols).unwrap();
            // A*I = A
            prop_assert_eq!(mat_mul_gf2(&bitmat, &ident_rt).unwrap(), bitmat.clone());
            let ident_lt = BitMatrix::new_identity(rows).unwrap();
            prop_assert_eq!(mat_mul_gf2(&ident_lt, &bitmat).unwrap(), bitmat);
        }
    } // proptest
} // mod tests
