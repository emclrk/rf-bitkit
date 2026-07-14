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

Inferred Structure:
  Fixed(3) | Varying(2) | Fixed(2) | Varying(2) | Fixed(2) | Varying(2) | Fixed(1)
```

## CLI Tool

The `bitkit` binary provides the following subcommands. All commands accept either a `.txt` file (one bitstream per line) or a URH `.xml` export.

### `info`
Show basic stats and a hex representation of each bitstream.
```
bitkit info <file> [-s <symlen>] [--skip <n>]
```

### `infer`
Compute positionwise entropy and infer the protocol field structure. This is the key command — given a series of bitstreams, it identifies which bit positions are fixed across all captures and which vary.
```
bitkit infer <file> [--eps <tolerance>]
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
Detect the CRC polynomial, bit location, reflection parameters, and XOR constant across a set of captures. Uses GF(2) linear algebra to recover the generator polynomial without any prior knowledge of the CRC scheme.
```
bitkit crc <file>
```

## Library

rf-bitkit is also a Rust library. Add it to your `Cargo.toml`:

```toml
[dependencies]
rf-bitkit = "0.2.0"
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
