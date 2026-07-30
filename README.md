# rf-bitkit

An RF protocol reverse engineering/analysis engine. The goal of this tool is to surface information to be interpreted by the analyst, especially when there are multiple plausible interpretations. Design philosophy: the tool should not make decisions or draw conclusions, just provide all the relevant information and allow the analyst to decide what it means, and provide it in a clear, repeatable way.

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

rf-bitkit does not require you to have any prior information about the protocol. Given a list of bitstrings (demodulated rf captures) it can infer:
- Which fields are fixed/varying
- What symbols appear in the bitstream
- Whether a CRC is present, where it is, and what its parameters are

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
|crc|detect crc polynomial, bit location, and parameters|

## Library

rf-bitkit is also a Rust library. Add it to your `Cargo.toml`:

```toml
[dependencies]
rf-bitkit = "0.2.2"
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
