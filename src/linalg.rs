use crate::{BitkitError, Bitstream};
use std::fmt;
use std::ops::{Index, IndexMut, Mul};

/// Matrix of bits. Each row is a Bitstream. It's assumed that all Bitstreams are of the same
/// length.
#[derive(Debug, PartialEq, Clone)]
pub struct BitMatrix {
    bits: Vec<u8>,   // bit matrix, stored row-wise
    num_rows: usize, // equivalent to column length
    num_cols: usize, // equivalent to row length
    is_rref: bool,   // bool - is this a reduced row echelon form matrix
}

impl BitMatrix {
    /// Given a slice of Bitstreams, create a BitMatrix. Assumes all Bitstreams are of equal
    /// length.
    pub fn new(bitstrs: &[Bitstream]) -> Result<Self, BitkitError> {
        Self::new_with_rref(bitstrs, false)
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

        Ok(BitMatrix {
            bits: bitvec,
            num_rows,
            num_cols,
            is_rref,
        })
    }
    pub fn is_zero(&self) -> bool {
        self.bits.iter().all(|&b| b != 0)
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
        Ok(BitMatrix {
            bits: bitvec,
            num_rows: self.num_rows,
            num_cols: width,
            is_rref: false,
        })
    }
    /// Return a new matrix that is a vertical window of this matrix.
    /// Size will be num_cols x height
    pub fn row_window(&self, height: usize) -> Result<Self, BitkitError> {
        if height > self.num_rows {
            return Err(BitkitError::IndexError(height, self.num_rows));
        }
        Ok(BitMatrix {
            bits: self.bits[..height * self.num_cols].to_vec(),
            num_rows: height,
            num_cols: self.num_cols,
            is_rref: false,
        })
    }
    /// Return a new BitMatrix that is the transpose of this one
    pub fn transpose(&self) -> Self {
        let mut bitvec: Vec<u8> = vec![0; self.num_rows * self.num_cols];
        for row in 0..self.num_rows {
            for col in 0..self.num_cols {
                bitvec[col * self.num_rows + row] = self[row][col];
            }
        }
        BitMatrix {
            bits: bitvec,
            num_rows: self.num_cols,
            num_cols: self.num_rows,
            is_rref: false,
        }
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
    pub fn mat_rank(&self) -> usize {
        if self.is_rref {
            (0..self.num_rows)
                .filter(|&ii| self[ii].iter().any(|&x| x != 0))
                .count()
        } else {
            let reduced = self.clone().rref();
            (0..reduced.num_rows)
                .filter(|&ii| reduced[ii].iter().any(|&x| x != 0))
                .count()
        }
    } // rank
    /// Get row echelon form of the matrix
    fn row_echelon_form(self) -> Self {
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
        row_ech
    } // row_echelon_form
    /// Get reduced row echelon form of a matrix
    fn rref(self) -> Self {
        let mut result = self.row_echelon_form();
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
        result
    } // reduced row echelon form
    /// Find the nullspace basis vectors
    pub fn nullspace(&self) -> Self {
        let reduced = if self.is_rref {
            self.clone()
        } else {
            self.clone().rref()
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
        BitMatrix {
            bits: nullvecs,
            num_rows: reduced.num_cols(),
            num_cols: free_cols.len(),
            is_rref: false,
        }
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

/// Compute the dot product of two vectors over GF(2). Add = XOR, mul = AND.
pub fn dot_prod_gf2(vec1: &[u8], vec2: &[u8]) -> Result<u8, BitkitError> {
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
pub fn mat_mul_gf2(mat1: &BitMatrix, mat2: &BitMatrix) -> Result<BitMatrix, BitkitError> {
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
    let mat2_t = mat2.transpose();
    for row_idx in 0..mat1.num_rows {
        for col_idx in 0..mat2.num_cols {
            result_vec[row_idx * mat2.num_cols + col_idx] =
                dot_prod_gf2(&mat1[row_idx], &mat2_t[col_idx])?;
        }
    }
    Ok(BitMatrix {
        bits: result_vec,
        num_rows: mat1.num_rows,
        num_cols: mat2.num_cols,
        is_rref: false,
    })
}

/// Berlekamp-Massey algorithm
pub fn berlekamp_massey(null_vec: &[u8]) -> Vec<u8> {
    if null_vec.is_empty() {
        // empty null vec --> LFSR of length 0 is represented by the trivial polynomial
        // w/no feedback taps
        return vec![1];
    }
    // Step 1 - initialize
    let mut l_assumed_errs = 0; // current number of assumed errors
    let mut cx_potential: Vec<u8> = vec![0; null_vec.len()];
    let mut bx_prev_cx: Vec<u8> = vec![0; null_vec.len()];
    cx_potential[0] = 1;
    bx_prev_cx[0] = 1;
    let mut m_iters_since_update = 1;
    let mut disc;
    for n in 0..null_vec.len() {
        // step 2 - calculate discrepancy
        disc = (1..=l_assumed_errs).fold(null_vec[n], |acc, ii| {
            acc ^ (cx_potential[ii] & null_vec[n - ii])
        });
        if disc == 0 {
            // Step 3
            m_iters_since_update += 1;
        } else if 2 * l_assumed_errs <= n {
            // Step 5
            let tx_temp_cx = cx_potential.clone();
            // C(x) = C(x) - d b−1 x^m B(x);
            // In GF(2), - is XOR, d/b is 1 (bc they're nonzero by virtue of reaching this point in
            // the code), x^m shifts B(x) by m
            for ii in m_iters_since_update..cx_potential.len() {
                cx_potential[ii] ^= bx_prev_cx[ii - m_iters_since_update];
            }
            l_assumed_errs = n + 1 - l_assumed_errs;
            bx_prev_cx = tx_temp_cx;
            m_iters_since_update = 1;
        } else {
            // step 4
            for ii in m_iters_since_update..cx_potential.len() {
                cx_potential[ii] ^= bx_prev_cx[ii - m_iters_since_update];
            }
            m_iters_since_update += 1;
        }
    }
    while cx_potential.last() == Some(&0) {
        cx_potential.pop();
    }
    cx_potential
}

#[cfg(test)]
mod tests {
    use super::*;

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
    }
    #[test]
    fn test_dot_prod_gf2() {
        let v1 = vec![1, 0, 1, 0, 1, 0];
        let v2 = vec![1, 1, 0, 1, 1, 0];
        assert_eq!(dot_prod_gf2(&v1, &v2).unwrap(), 0);
        let v1 = vec![1, 0, 1, 1, 1, 1];
        let v2 = vec![1, 1, 0, 1, 1, 0];
        assert_eq!(dot_prod_gf2(&v1, &v2).unwrap(), 1);
    }
    #[test]
    fn test_matmul_gf2_identity() {
        let matrix = BitMatrix::new(&vec![
            Bitstream::new(String::from("10110")).unwrap(),
            Bitstream::new(String::from("01010")).unwrap(),
            Bitstream::new(String::from("10101")).unwrap(),
            Bitstream::new(String::from("11000")).unwrap(),
            Bitstream::new(String::from("11111")).unwrap(),
        ])
        .unwrap();
        let matrix_i = BitMatrix::new(&vec![
            Bitstream::new(String::from("10000")).unwrap(),
            Bitstream::new(String::from("01000")).unwrap(),
            Bitstream::new(String::from("00100")).unwrap(),
            Bitstream::new(String::from("00010")).unwrap(),
            Bitstream::new(String::from("00001")).unwrap(),
        ])
        .unwrap();
        assert_eq!(mat_mul_gf2(&matrix, &matrix_i).unwrap(), matrix);
    }
    #[test]
    fn test_matmul_gf2_nonsquare() {
        let mat1 = BitMatrix::new(&vec![
            Bitstream::new(String::from("011")).unwrap(),
            Bitstream::new(String::from("101")).unwrap(),
        ])
        .unwrap();
        let mat1_t = mat1.transpose();
        let expect = BitMatrix::new(&vec![
            Bitstream::new(String::from("01")).unwrap(),
            Bitstream::new(String::from("10")).unwrap(),
        ])
        .unwrap();
        assert_eq!((&mat1 * &mat1_t).unwrap(), expect);
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
        let row_ech = matrix.row_echelon_form();
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
        let rrow_ech = matrix.rref();
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
        let ns = matrix.nullspace();
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
    fn test_berlekamp_massey() {
        let seq: Vec<u8> = vec![1, 1, 0, 1, 1, 0];
        assert_eq!(berlekamp_massey(&seq), vec![1, 1, 1]);
    }
} // mod tests
