## Approach for reversing CRC
A CRC is a special type of checksum. It is formed as a linear combination of the data. That means that if we create a matrix of the data stream, with each frame as a row in the matrix, and each protocol bit position as a column of the matrix, the CRC bits *aren't contributing to the row space*. We use this fact to find the location and length of the CRC bits by "windowing" the matrix, taking a column at a time, and noting exactly where the rank of the matrix plateaus (this piece was inspired by the work in [1]). Since the column is the bit position, when we see columns that aren't contributing to the rank we know they were formed as a linear combination of the data, and they belong to the CRC.

To recover the CRC itself, compute the reduced row echelon form of the matrix[2], which will clearly separate the data portion of the matrix (which has the pivot columns) from the nullspace portion of the matrix (the free columns). Then, we use Berlekamp-Massey[3] on any of the nullspace basis vectors to find the shortest LFSR that could generate it. That same LFSR is the actual CRC generator polynomial of the protocol.

Some CRC protocols have an affine component. To handle this we preprocess by XOR-ing the first Bitstream into every Bitstream that follows. This removes a degree of freedom from the matrix, but since we can't know ahead of time whether the CRC protocol XORs a constant we just live with that.

Some important caveats:

- This algorithm will fail if even a single bit is flipped (well, unless you get insanely lucky and the bit flips happen to form a valid codeword, but the probability of that happening is negligible by design - CRC is a linear error detection code and valid codewords have a minimum hamming distance between them. So don't count on it). Hopefully for consumer-level devices/hobbyist RE you can have pretty clean signals - but I have a TODO to make this more resilient.

- The bitstreams must be perfectly aligned and exactly the same length (use other algorithms and/or find the sync word to make sure the bitstreams are lined up before attempting to find the CRC). 

- There must be enough protocol samples (Bitstreams) provided to reveal the CRC - at least one more than the number of data bits in the protocol, but more is safer. If the rank of the formed matrix is not greater than the number of Bitstreams, we just bail.

- In order for the Berlekamp-Massey algorithm to work, there must be at least twice as many data bits as CRC bits; if not, brute-force known CRCs instead.

- As of now, the algorithm assumes that the CRC strictly follows the data. If it sends them in a weird order we're probably not prepared for that.

- It also assumes that there's only one CRC in the bitstream. If there's multiple CRC fields (like if there's a CRC in the header and one for the payload). Handling that is a TODO.

[1] G. Burel, “Blind Estimation of Encoder and Interleaver Characteristics in a Non Cooperative Context,” Academia.edu, Nov. 05, 2015. https://www.academia.edu/17802718/blind_estimation_of_encoder_and_interleaver_characteristics_in_a_non_cooperative_context (accessed July 10, 2026).

[2] “AN ALGORITHM FOR REDUCING A MATRIX TO ROW ECHELON FORM.” Accessed: July 10, 2026. [Online]. Available: https://www.math.purdue.edu/~shao92/documents/Algorithm%20REF.pdf

[3] J. Massey, “Shift-register synthesis and BCH decoding,” IEEE Transactions on Information Theory, vol. 15, no. 1, pp. 122–127, Jan. 1969, doi: 10.1109/tit.1969.1054260.

