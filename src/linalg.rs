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
}

impl BitMatrix {
    /// Given a slice of Bitstreams, create a BitMatrix. Assumes all Bitstreams are of equal
    /// length.
    pub fn new(bitstrs: &[Bitstream]) -> Result<Self, BitkitError> {
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
        })
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
        }
    }
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
    pub fn rank(&self) -> usize {
        let row_ech = self.row_echelon_form();
        let mut row_rank = 0;
        for ii in 0..row_ech.num_rows {
            if row_ech[ii].iter().any(|x| *x != 0) {
                row_rank += 1;
            }
        }
        row_rank
    }
    /// Get row echelon form of the matrix
    pub fn row_echelon_form(&self) -> Self {
        let mut row_ech = self.clone();
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
                if min_row >= row_ech.num_rows || min_col >= row_ech.num_cols {
                    break 'outer;
                }
            }
        }
        row_ech
    } // fn ref
    /// Get reduced row echelon form of a matrix
    pub fn rref(&self) -> Self {
        let mut rrow_ech = self.row_echelon_form();
        for row in (0..rrow_ech.num_rows).rev() {
            if let Some(pivot_col) = rrow_ech[row].iter().position(|&x| x == 1) {
                let pivot_row = rrow_ech[row].to_vec();
                for ii in (0..row).rev() {
                    if rrow_ech[ii][pivot_col] == 1 {
                        for jj in pivot_col..rrow_ech.num_cols {
                            rrow_ech[ii][jj] ^= pivot_row[jj];
                        }
                    }
                }
            }
        }
        rrow_ech
    }
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
    })
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
        let expected = BitMatrix::new(&vec![
            Bitstream::new(String::from("10001")).unwrap(),
            Bitstream::new(String::from("01001")).unwrap(),
            Bitstream::new(String::from("00100")).unwrap(),
            Bitstream::new(String::from("00011")).unwrap(),
            Bitstream::new(String::from("00000")).unwrap(),
        ])
        .unwrap();
        assert_eq!(rrow_ech, expected);
    }
} // mod tests
