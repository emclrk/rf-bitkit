# rf-bitkit

An RF protocol reverse engineering/analysis engine.

The goal of this tool is to surface information to be interpreted by the analyst, especially when there are multiple plausible interpretations. Design philosophy: the tool should not make decisions or draw conclusions, just provide all the relevant information and allow the analyst to decide what it means, and provide it in a clear, repeatable way.

A workflow might look like this:
```
Unknown signal
    |
    |
    V
Capture I/Q (SDR++/gqrx/etc)
    |
    | samples
    V
Demodulate (gnuradio/URH/rtl_433)
    |
    | bits
    V
Analyze protocol (rf-bitkit)
```

rf-bitkit does not require you to have any prior information about the protocol. Given a list of bitstrings (demodulated rf captures) it can:
- Detect which fields are fixed/varying via entropy measurements
- Determine whether a CRC is present, where it is, and its polynomial, width, refin/refout, and init/xorout. This is not a brute-force search- it uses linear algebra over GF(2) to find the relationship between the data bits and the CRC bits. You don't have to know ahead of time where the CRC is or its length.
- Find the CRC parameters even in the presence of some noise. The method uses RANSAC (consensus sampling) to offer robustness to corrupted frames.
- Perform rank analysis, revealing linearly dependent bit positions. These could be CRC outputs, parity bits, or correlated flags.

In the future it will also be able to identify:
- Field boundaries
- Candidate sync words
- More sophisticated clustering

## Installation

```
cargo install rf-bitkit
```

Or build from source:

```
git clone https://github.com/emclrk/rf-bitkit
cd rf-bitkit
cargo install --path .
```

## Example
This example uses the Schrader TPMS data from the rtl_433 test corpus.

```
$ bitkit infer tests/test_schrader_rtl433.txt

=== Protocol Structure: tests/test_schrader_rtl433.txt ===

Min varying entropy: 0.2580
H(1/N) = 0.1511  (single-packet anomaly reference)

Entropy profile:
  ▁▁▁▁▁▃▄▁▁█▇▇▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁█▇▇▇███▆▁▁▁▁▁▁▅▇████████

Inferred Structure:
  Fixed(5) | Varying(2, H:0.26–0.43) | Fixed(2) | Varying(3, H:0.91–1.00) | Fixed(28) | Varying(8, H:0.71–1.00) | Fixed(6) | Varying(10, H:0.56–1.00)

Summary:
  Bitstream samples: 46
  Fixed:     41 bits
  Varying:   23 bits
  Total:     64 bits
```

Now, we'll take a look at the rank analysis of this dataset.
```
$ bitkit rank tests/test_schrader_rtl433.txt

Rank graph - _ = fixed, █ = independent, ▄ = dependent

[  0]   _____██__██▄____________________________████████______██▄▄▄▄▄▄▄▄
Locations of dependent columns:
[11, 56, 57, 58, 59, 60, 61, 62, 63]

```
The eight dependent columns at the end of the packet are likely CRC bits. The bit at column 11 is a flag bit correlated with the data somehow, and it will break the CRC analysis, so I'll exclude it:

```
$ bitkit crc tests/test_schrader_rtl433.txt --exclude-bits 11

=== CRC: tests/test_schrader_rtl433.txt ===

Polynomial:  0x7 (8-bit)
Location:    bit 56 in frame (0-indexed)
refin:       false
refout:      false
xor_val:     0xbd
Score:       100.0%
Poly found:  6/10 iterations
```

From the rtl_433 documentation, the polynomial is 0x7 and the xor init value is 0xf0. Note the xor_val we come up with here is not directly equivalent to the init value, since it's the cumulative effect of the initial value after it's propagated through the shift register. The xor_val would be different with a different data length, but it's an equivalent way to parameterize the CRC, and our result of 0xbd is consistent with an xor init value of 0xf0 and 56 bits of data. When I run a 56-bit frame of zeros through a CRC computation with polynomial=0x7 and xor init=0xf0 (just like the rtl_433 documentation) I get a result of `10111101 = 0xbd`.

Excluding bit 11 allowed us to find the polynomial in 6/10 iterations with 100% confidence (when scoring, the tool runs each data frame through the found CRC and compares its result to what is actually in the frame. Here, the found polynomial is consistent with 100% of data frames). The reason it was only found in 6/10 iterations is because some subsets of samples end up having spurious linear dependencies, either causing the algorithm to produce the wrong answer or to be unable to run at all. Since this data is clean, I can rerun `bitkit crc` with a larger sample size or more iterations to improve my confidence in the result.

In general, with a larger sample size the risk of coincidental/spurious dependencies decreases, but if this signal did have noise a higher sample size would increase the probability of including corrupted frames. There are always tradeoffs!

## CLI Tool

All commands operate on a .txt file (one bitstream per line) or a URH .xml protocol export file.

|Command|Description|
|-------|-----------|
|info|basic stats and a hex representation of each bitstream|
|infer|compute positionwise entropy and infer the protocol field structure. Optionally cluster by low-entropy bit positions.|
|prefix|find common prefix across all bitstreams|
|sweep|show normalized entropy at each symbol length|
|alphabet|show symbol alphabet and frequency counts across bitstreams|
|substrings|show most common substrings of a given length|
|correlate|cross-correlate 2 bitstreams from a file|
|rank|show a left-to-right rank graph of the bitstream columns (w/affine element removed)|
|crc|detect crc polynomial, bit location, and parameters|

## Library

rf-bitkit is also a Rust library. Add it to your `Cargo.toml`:

```toml
[dependencies]
rf-bitkit = "0.3.0"
```

## Status and Roadmap

The exact roadmap and timeline is a little hazy, because I am trying to develop against real signals and write new features as the need arises. Hopefully the result will be a well tested, rigorous, flexible tool that performs well on real signals, not just idealized or synthetic data. 

However, here are a few things I have in mind:

- Sync word detection in the presence of misaligned packets (cross-correlation is implemented; evaluating Smith-Waterman for handling bit insertions/deletions)
- Protocol field boundary detection using mutual information measures
- More sophisticated clustering to identify and separate different emitters, message types, etc
- Probabilistic prefix detection

Some user-friendliness upgrades:
- A REPL/shell-like interface that will allow the user to load in a file once and iteratively test hypotheses
- User-defined tags for labeling bitstream families (e.g. Frame A vs Frame B)
- JSON/TOML config file support for scripting multi-step analyses
- More visualizations


## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.
