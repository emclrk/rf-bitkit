# rf-bitkit

A Rust library and CLI tool for reverse engineering RF protocols.

I wrote this after finding URH's protocol analysis tab a little clunky and limited. rf-bitkit provides a collection of analysis functions for working with demodulated bitstreams - finding fixed and varying fields, detecting CRC/checksum fields, identifying symbol alphabets, measuring entropy, and correlating captures. It accepts plain text files (one bitstream per line) or XML exports directly from URH.

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

## Quick Example

```
$ bitkit infer my_captures.txt

=== Protocol Structure: my_captures.txt ===

Min varying entropy: 0.9153
H(1/N) = 0.2145  (single-packet anomaly reference)

Entropy profile:
  ▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁████████████████▁▁▁▁▁▁▁▁

Inferred Structure:
  Fixed(32) | Varying(16, H:0.92–1.00) | Fixed(8)
```

## CLI Tool

The `bitkit` binary provides the following subcommands. All commands accept either a `.txt` file (one bitstream per line) or a URH `.xml` export.

### `info`
Show basic stats and a hex representation of each bitstream.
```
bitkit info <file> [-s <symlen>] [--skip <n>] [--verbose]
```

### `infer`
Compute positionwise entropy and infer the protocol field structure. This is the key command — given a series of bitstreams, it identifies which bit positions are fixed across all captures and which vary. Output includes a sparkline entropy profile, per-field entropy ranges in the structure annotation, a reference entropy value `H(1/N)` marking the threshold at which a single packet differs from all others, and a histogram of ambiguous bit patterns (low-but-nonzero entropy positions that often indicate device IDs or transmitter-specific fields). Use `--verbose` for the full per-position entropy table.

Use `--eps` to set a tolerance for classifying ambiguous bits. Use `--cluster-min-size N` with `--eps` to split the capture into clusters by ambiguous bit pattern and run `infer` on each cluster separately — useful when the capture contains mixed message types or multiple transmitters. `--write-clusters` saves each cluster to a separate file for further analysis.
```
bitkit infer <file> [--eps <tolerance>] [--verbose] [--cluster-min-size <n>] [--write-clusters]
```

### `prefix`
Find the common prefix across all bitstreams. A long common prefix is a preamble or sync word candidate.
```
bitkit prefix <file>
```

### `sweep`
Show normalized entropy at each symbol length to help identify the correct symbol size. Look for a sudden drop in entropy — that's a signal that the chunking is aligning with the actual symbol boundaries.
```
bitkit sweep <file> [--max-symlen <n>] [--skip <n>]
```

### `alphabet`
Show the symbol alphabet and frequency counts across all bitstreams at a given symbol length.
```
bitkit alphabet <file> [-s <symlen>] [--skip <n>]
```

### `substrings`
Show the most frequently occurring substrings of a given length. Useful for finding sync word candidates.
```
bitkit substrings <file> [-l <len>] [-t <top>] [--skip <n>]
```

### `correlate`
Cross-correlate two bitstreams from a file by index. Useful for identifying misalignment between captures.
```
bitkit correlate <file> -a <index> -b <index> [-t <top>]
```

### `crc`
Detect the CRC polynomial, bit location, reflection parameters, and XOR constant across a set of captures. Uses GF(2) linear algebra to recover the generator polynomial without any prior knowledge of the CRC scheme. Uses RANSAC — each iteration draws a random subsample of frames, which provides resilience against a small number of corrupted or malformed packets. Output includes the number of RANSAC iterations that agreed on the result. Use `--max-iters` to control the number of iterations (default 10) and `--sample-size` to fix the subsample size.
```
bitkit crc <file> [--max-iters <n>] [--sample-size <n>]
```

## Library

rf-bitkit is also a Rust library. Add it to your `Cargo.toml`:

```toml
[dependencies]
rf-bitkit = "0.2.2"
```

Key functions:

- `from_txt` / `from_urh` — load bitstreams from a text file or URH XML export
- `positionwise_entropy` — compute per-bit-position entropy across a set of bitstreams
- `ProtocolStructure::infer_structure` — infer fixed/varying field layout from entropy values
- `get_alphabet_counts` — count symbol occurrences at a given symbol length
- `get_substr_counts` — count substring occurrences across all bitstreams
- `get_cross_correlation` — cross-correlate two bitstreams across all offsets
- `get_hamming_dist` — compute Hamming distance between two bitstreams
- `find_common_prefix` — find the longest prefix shared by all bitstreams
- `crc::find_crc` — recover CRC polynomial, location, refin/refout, and XOR constant from a set of bitstreams; returns a `crc::CrcResult`

## Status and Roadmap

This is an early release. Current planned work includes:

- Sync word detection in the presence of misaligned packets (cross-correlation is implemented; evaluating Smith-Waterman for handling bit insertions/deletions)
- User-defined tags for labeling bitstream families (e.g. Frame A vs Frame B)
- JSON/TOML config file support for scripting multi-step analyses
- Visualizations

Longer term, I'd like to build a DSP layer and work toward a standalone URH replacement in Rust.

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.
