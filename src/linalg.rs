use crate::{BitkitError, Bitstream};
use std::fmt;
use std::ops::{Index, Mul};

/// Matrix of bits. Each row is a Bitstream. It's assumed that all Bitstreams are of the same
/// length.
#[derive(Debug, PartialEq)]
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
    /// Get reduced row echelon form of a matrix
    pub fn rref(&self) -> Result<Self, BitkitError> {
        // stub, not yet implemented
        Ok(BitMatrix {
            bits: vec![],
            num_rows: 0,
            num_cols: 0,
        })
    }
    /// Get rank of the matrix
    pub fn rank(&self) -> usize {
        // get reduced row echelon form of the matrix
        // stub, not yet implemented
        0
    }
} // impl BitMatrix

impl Index<usize> for BitMatrix {
    type Output = [u8];
    fn index(&self, row: usize) -> &[u8] {
        let start = row * self.num_cols;
        &self.bits[start..start + self.num_cols]
    }
}

impl fmt::Display for BitMatrix {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for ii in 0..self.num_rows {
            for bit in &self[ii] {
                write!(f, "| {} ", bit)?;
            }
            write!(f, "|\n")?;
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
        println!("{}", matrix);
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
        println!("mat1:\n{mat1}\n mat1_t:\n{mat1_t}");
        assert_eq!((&mat1 * &mat1_t).unwrap(), expect);
    }
} // mod tests
