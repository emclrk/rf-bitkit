## Approach for reversing CRC
A CRC is a special type of checksum. It is formed as a linear combination of the data. That means that if we create a matrix of the data stream, with each frame as a row in the matrix, and each protocol bit position as a column of the matrix, the CRC bits *aren't contributing to the row space*. We use this fact to find the location and length of the CRC bits by "windowing" the matrix, taking a column at a time, and noting exactly where the rank of the matrix plateaus (this piece was inspired by the work in [1]). Since the column is the bit position, when we see columns that aren't contributing to the rank we know they were formed as a linear combination of the data, and they belong to the CRC.

To recover the CRC itself, compute the reduced row echelon form of the matrix[2], which will clearly separate the data portion of the matrix (which has the pivot columns) from the nullspace portion of the matrix (the free columns). The generator polynomial is extracted from the [k-1]th row of the matrix (windowed to the free column portion of the matrix), where k=the number of data varying bits. Why it works: in the RREF, row i of the CRC-column submatrix encodes x^{k-1-i+w} mod p. At i = k-1 (the last
  data row), that gives x^w mod p = p̃, which is exactly the polynomial without its leading x^w term. After reversing the bit order (the matrix stores MSB-first; poly_to_u128 expects LSB-first) and appending the leading 1, you have the full generator polynomial.


Some CRC protocols have an affine component. To handle this we preprocess by XOR-ing the first Bitstream into every Bitstream that follows. This removes a degree of freedom from the matrix, but since we can't know ahead of time whether the CRC protocol XORs a constant we just live with that.

Some important caveats:

- In its pure form, this algorithm will fail if even a single bit is flipped (well, unless you get insanely lucky and the bit flips happen to form a valid codeword, but the probability of that happening is negligible by design - CRC is a linear error detection code and valid codewords have a minimum hamming distance between them. So don't count on it). To counter this, we use a RANSAC approach: randomly sample some of the bitstreams, run them through the algorithm, and iterate a few times to increase the probability of getting an uncorrupted matrix (or increase confidence in the solution if you get the same thing more than once!)

- The bitstreams must be perfectly aligned and exactly the same length (use other algorithms and/or find the sync word to make sure the bitstreams are lined up before attempting to find the CRC). 

- There must be enough protocol samples (Bitstreams) provided to reveal the CRC - at least one more than the number of data bits in the protocol, but more is safer. If the rank of the formed matrix is not greater than the number of Bitstreams, we just bail.

- As of now, the algorithm assumes that the CRC strictly follows the data. If it sends them in a weird order we're probably not prepared for that.

- It also assumes that there's only one CRC in the bitstream. If there's multiple CRC fields (like if there's a CRC in the header and one for the payload). Handling that is a TODO - or if you believe there's multiple CRCs, partition the packet and deal with each one separately.

[1] G. Burel, “Blind Estimation of Encoder and Interleaver Characteristics in a Non Cooperative Context,” Academia.edu, Nov. 05, 2015. https://www.academia.edu/17802718/blind_estimation_of_encoder_and_interleaver_characteristics_in_a_non_cooperative_context (accessed July 10, 2026).

[2] “AN ALGORITHM FOR REDUCING A MATRIX TO ROW ECHELON FORM.” Accessed: July 10, 2026. [Online]. Available: https://www.math.purdue.edu/~shao92/documents/Algorithm%20REF.pdf

