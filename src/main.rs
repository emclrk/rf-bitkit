use clap::{Parser, Subcommand};
use rf_bitkit::cluster::cluster_by_ambiguous_bits;
use rf_bitkit::crc::find_crc;
use rf_bitkit::linalg::{windowed_rank, BitMatrix, RankResult};
use rf_bitkit::proto::{ProtoField, ProtocolStructure};
use rf_bitkit::{
    find_common_prefix, from_txt, from_urh, get_alphabet_counts, get_cross_correlation,
    get_substr_counts, positionwise_entropy, BitkitError, Bitstream,
};
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::Path;

#[derive(Parser)]
#[command(name = "bitkit", about = "Radio protocol bitstream analysis tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show basic stats and hex representation of each bitstream
    Info {
        file: String,
        #[arg(short, long, default_value_t = 4)]
        symlen: usize,
        #[arg(long, default_value_t = 0)]
        skip: usize,
        #[arg(long)]
        verbose: bool,
    },
    /// Find the common prefix across all bitstreams (preamble candidate)
    Prefix { file: String },
    /// Compute positionwise entropy and infer protocol field structure. Given a series of
    /// bitstreams, it identifies which bit positions are fixed across all captures and which vary,
    /// and how much they vary. Output includes a sparkline entropy profile, per-field entropy
    /// ranges in the structure annotation, a reference entropy value `H(1/N)` marking the
    /// threshold at which a single packet differs from all the others, and a histogram of
    /// ambiguous bit patterns (low but nonzero entropy positions. They may indicate device IDs or
    /// transmitter specific fields, or bit errors in fields that should be fixed. Provide --eps,
    /// an epsilon value, to see ambiguous bit fields). The `--verbose` flag provides the full
    /// per-position entropy table. Optionally, cluster by low-entropy bit positions and infer
    /// structure on the clusters, which may help separate different emitters in the capture.
    Infer {
        file: String,
        /// Entropy tolerance: positions with entropy <= eps are marked ambiguous
        #[arg(long)]
        eps: Option<f32>,
        /// Print full per-position entropy table
        #[arg(long)]
        verbose: bool,
        /// When provided, cluster the bitstreams using low entropy fields and infer on each
        /// cluster separately. To evaluate all clusters, provide a min size of 0. Requires --eps.
        #[arg(long)]
        cluster_min_size: Option<usize>,
        /// When used with --cluster-min-size, writes the clusters to text files
        #[arg(long)]
        write_clusters: bool,
    },
    /// Show normalized entropy at each symbol length to help infer symbol size. Look for a sudden
    /// drop in entropy, which may indicate the chunking is aligning with the actual symbol
    /// boundaries. (Note the entropy will tend to decrease with increasing symbol length).
    Sweep {
        file: String,
        #[arg(long, default_value_t = 8)]
        max_symlen: usize,
        #[arg(long, default_value_t = 0)]
        skip: usize,
    },
    /// Show symbol alphabet and frequency counts across all bitstreams at a given symbol length
    Alphabet {
        file: String,
        #[arg(short, long, default_value_t = 1)]
        symlen: usize,
        #[arg(long, default_value_t = 0)]
        skip: usize,
    },
    /// Show the most frequent substrings of a given length. Can help find sync word candidates.
    Substrings {
        file: String,
        /// Substring length
        #[arg(short, long, default_value_t = 8)]
        len: usize,
        /// Number of results to show
        #[arg(short, long, default_value_t = 10)]
        top: usize,
        #[arg(long, default_value_t = 0)]
        skip: usize,
    },
    /// Print a graph of the rank of the matrix formed by the bitstreams. Columns are analyzed
    /// *after* subtracting a reference row (XOR with first packet). The graph will show fixed
    /// bit columns, independent, and dependent columns. Dependent columns in the graph are those
    /// that are dependent on some combination of columns *preceding* it (that is, to the left).
    /// This can help identify fields like flags, parity bits, and CRC fields.
    Rank { file: String },
    /// Detect CRC polynomial, location, and parameters. CRC is found using linear algebra methods
    /// over GF(2), and random sampling of the bitstreams is also used to protect against small
    /// numbers of bit errors, which would break the linearity the method depends on.
    Crc {
        file: String,
        #[arg(long)]
        max_iters: Option<usize>,
        #[arg(long)]
        sample_size: Option<usize>,
    },
    /// Cross-correlate two bitstreams from a file by index - may help identify misalignment
    /// between captures
    Correlate {
        file: String,
        /// Index of the first bitstream
        #[arg(short)]
        a: usize,
        /// Index of the second bitstream
        #[arg(short)]
        b: usize,
        /// Number of top results to show
        #[arg(short, long, default_value_t = 10)]
        top: usize,
    },
}

fn load_file(filepath: &str) -> Result<Vec<Bitstream>, BitkitError> {
    match Path::new(filepath).extension().and_then(|e| e.to_str()) {
        Some("xml") => from_urh(filepath),
        _ => from_txt(filepath),
    }
}

fn field_name(ft: &ProtoField) -> &'static str {
    match ft {
        ProtoField::Fixed => "Fixed",
        ProtoField::Varying => "Varying",
        ProtoField::Ambiguous => "Ambiguous",
    }
}

fn sparkline(ents: &[f32]) -> String {
    const BLOCKS: &[char] = &['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    ents.iter()
        .map(|&e| BLOCKS[((e * 7.0).round() as usize).min(7)])
        .collect()
}

fn print_rank_graph(rank_results: &[RankResult], ps: &ProtocolStructure) {
    const BLOCKS: &[char] = &['_', '▄', '█'];
    let mut rank_idx: usize = 0;
    let mut graph: Vec<char> = Vec::with_capacity(rank_results.len());
    let mut prev_rank = 0;
    for (field, size) in ps.get_fields() {
        match field {
            ProtoField::Fixed => {
                for _ in 0..size {
                    graph.push(BLOCKS[0]);
                }
            }
            ProtoField::Varying | ProtoField::Ambiguous => {
                for _ in 0..size {
                    if rank_results[rank_idx].rank > prev_rank {
                        graph.push(BLOCKS[2]);
                    } else {
                        graph.push(BLOCKS[1]);
                    }
                    prev_rank = rank_results[rank_idx].rank;
                    rank_idx += 1;
                }
            }
        }
    }
    println!(
        "Rank graph - {} = fixed, {} = independent, {} = dependent\n",
        BLOCKS[0], BLOCKS[2], BLOCKS[1]
    );
    let graph_str = graph.iter().collect::<String>();
    let chunk_len = 64;
    for (ii, chunk) in graph_str
        .chars()
        .collect::<Vec<_>>()
        .chunks(chunk_len)
        .enumerate()
    {
        let pos = ii * chunk_len;
        let chunk_str: String = chunk.iter().collect();
        println!("[{pos:3}]   {chunk_str}");
    }
    let dependent = graph
        .iter()
        .enumerate()
        .filter(|(_, x)| **x == BLOCKS[1])
        .map(|(ii, _)| ii)
        .collect::<Vec<_>>();
    println!("Locations of dependent columns:");
    for chunk in dependent.chunks(chunk_len) {
        println!("{:?}", chunk.iter().collect::<Vec<_>>());
    }
}
fn annotated_structure(fields: &[(ProtoField, usize)], ents: &[f32]) -> String {
    let mut parts = Vec::new();
    let mut offset = 0;
    for (ft, count) in fields {
        let field_ents = &ents[offset..offset + count];
        offset += count;
        let s = match ft {
            ProtoField::Fixed => format!("Fixed({count})"),
            _ => {
                let min_e = field_ents.iter().cloned().fold(f32::INFINITY, f32::min);
                let max_e = field_ents.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
                format!("{}({count}, H:{min_e:.2}–{max_e:.2})", field_name(ft))
            }
        };
        parts.push(s);
    }
    parts.join(" | ")
}

fn do_infer(
    bitstrs: &[Bitstream],
    ents: &[f32],
    ps: &ProtocolStructure,
    verbose: bool,
    label: &str,
) -> Result<(), BitkitError> {
    println!("=== Protocol Structure: {label} ===");
    println!();

    let p = 1.0 / bitstrs.len() as f32;
    let hx = -p * p.log2() - (1_f32 - p) * (1_f32 - p).log2();
    let min_varying = ents
        .iter()
        .cloned()
        .filter(|&e| e > 0.0)
        .fold(f32::INFINITY, f32::min);
    if min_varying.is_finite() {
        println!("Min varying entropy: {min_varying:.4}");
    }
    println!("H(1/N) = {hx:.4}  (single-packet anomaly reference)");
    println!();

    println!("Entropy profile:");
    println!("  {}", sparkline(ents));
    println!();

    if verbose {
        println!("Positionwise Entropy:");
        for (i, e) in ents.iter().enumerate() {
            println!("  [{i:3}] {e:.4}");
        }
        println!();
    }

    let fields = ps.get_fields();
    println!("Inferred Structure:");
    println!("  {}", annotated_structure(&fields, ents));
    println!();

    let summary = ps.summarize();
    if summary[&ProtoField::Ambiguous] > 0 {
        let mut ambiguous_strs: HashMap<String, u32> = HashMap::new();
        for bs in bitstrs.iter() {
            ambiguous_strs
                .entry(ps.extract_ambiguous_bits(bs)?)
                .and_modify(|ct| *ct += 1)
                .or_insert(1);
        }
        let mut sorted: Vec<_> = ambiguous_strs.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        println!("Ambiguous bit patterns:");
        for (pattern, ct) in &sorted {
            println!("  {pattern}  ×{ct}");
        }
        println!();
    }

    println!("Summary:");
    println!("  Bitstream samples: {}", bitstrs.len());
    println!("  Fixed:     {} bits", summary[&ProtoField::Fixed]);
    println!("  Varying:   {} bits", summary[&ProtoField::Varying]);
    if summary[&ProtoField::Ambiguous] > 0 {
        println!("  Ambiguous: {} bits", summary[&ProtoField::Ambiguous]);
    }
    println!("  Total:     {} bits", summary.values().sum::<usize>());
    Ok(())
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), BitkitError> {
    match cli.command {
        Commands::Info {
            file,
            symlen,
            skip,
            verbose,
        } => {
            let bitstrs = load_file(&file)?;
            let lengths: Vec<usize> = bitstrs.iter().map(|b| b.len()).collect();
            let min_len = lengths.iter().min().copied().unwrap_or(0);
            let max_len = lengths.iter().max().copied().unwrap_or(0);
            let avg_len = lengths.iter().sum::<usize>() as f32 / lengths.len() as f32;

            println!("=== Info: {file} ===");
            println!("Bitstreams: {}", bitstrs.len());
            println!("Lengths: min={min_len}, max={max_len}, avg={avg_len:.1}");
            println!();
            if verbose {
                for (i, bs) in bitstrs.iter().enumerate() {
                    println!(
                        "[{i:3}] {}  ({} bits)",
                        bs.skip(skip).to_hex(symlen),
                        bs.len()
                    );
                }
            }
        }

        Commands::Prefix { file } => {
            let bitstrs = load_file(&file)?;
            let prefix = find_common_prefix(&bitstrs);
            println!("=== Common Prefix: {file} ===");
            if prefix.is_empty() {
                println!("No common prefix found.");
            } else {
                println!("Prefix: {prefix} ({} bits)", prefix.len());
            }
        }

        Commands::Infer {
            file,
            eps,
            verbose,
            cluster_min_size,
            write_clusters,
        } => {
            let bitstrs = load_file(&file)?;
            if let Some(min_size) = cluster_min_size {
                if let Some(eval) = eps {
                    let bmap = cluster_by_ambiguous_bits(&bitstrs, eval)?;
                    let clusters: Vec<(&String, &Vec<&Bitstream>)> = match min_size {
                        0 => bmap.iter().collect(),
                        _ => bmap
                            .iter()
                            .filter(|(_key, val)| val.len() >= min_size)
                            .collect(),
                    };
                    for (key, cluster) in clusters {
                        let copied: Vec<Bitstream> = cluster.iter().map(|&b| b.clone()).collect();
                        if write_clusters {
                            let path = Path::new(&file);
                            let parent = path.parent().unwrap_or(Path::new("."));
                            let stem = path.file_stem().unwrap().to_str().unwrap();
                            let outfile = parent.join(format!("{stem}_{key}_eps-{eval}.txt"));
                            let mut fout = File::create(&outfile).map_err(BitkitError::Io)?;
                            for bs in copied.iter() {
                                writeln!(fout, "{}", bs.bitstring()).map_err(BitkitError::Io)?;
                            }
                            println!("Cluster written to {}", outfile.display());
                        }
                        if copied.len() == 1 {
                            println!("Cluster of size 1 - no infer performed");
                            continue;
                        }
                        let ents = positionwise_entropy(&copied);
                        let ps = ProtocolStructure::infer_structure_tolerance(&ents, eval);
                        do_infer(&copied, &ents, &ps, verbose, key)?;
                    }
                } else {
                    return Err(BitkitError::MiscellaneousError(String::from(
                        "Argument error - clustering requires --eps",
                    )));
                }
            } else {
                let ents = positionwise_entropy(&bitstrs);
                let ps = match eps {
                    Some(e) => ProtocolStructure::infer_structure_tolerance(&ents, e),
                    None => ProtocolStructure::infer_structure(&ents),
                };
                do_infer(&bitstrs, &ents, &ps, verbose, &file)?;
            }
        }
        Commands::Sweep {
            file,
            max_symlen,
            skip,
        } => {
            let bitstrs = load_file(&file)?;
            let skipped: Vec<Bitstream> = bitstrs.iter().map(|bs| bs.skip(skip)).collect();
            println!("=== Entropy Sweep: {file} ===");
            println!();
            println!(
                "{:>8}  {:>14}  {:>12}",
                "symlen", "norm_entropy", "unique_syms"
            );

            let mut results = Vec::new();
            for symlen in 1..=max_symlen {
                let avg = skipped
                    .iter()
                    .map(|bs| bs.get_normed_entropy(symlen))
                    .sum::<f32>()
                    / skipped.len() as f32;
                let unique = get_alphabet_counts(&bitstrs, symlen, skip).len();
                results.push((symlen, avg, unique));
            }
            for (symlen, entropy, unique) in &results {
                println!("{:>8}  {:>14.4}  {:>12}", symlen, entropy, unique);
            }
        }

        Commands::Alphabet { file, symlen, skip } => {
            let bitstrs = load_file(&file)?;
            let counts = get_alphabet_counts(&bitstrs, symlen, skip);
            let mut sorted: Vec<_> = counts.iter().collect();
            sorted.sort_by(|a, b| b.1.cmp(a.1));

            println!("=== Alphabet (symlen={symlen}): {file} ===");
            println!();
            println!("{:<16}  {:>8}", "symbol", "count");
            for (sym, ct) in &sorted {
                println!("{:<16}  {:>8}", sym, ct);
            }
        }

        Commands::Substrings {
            file,
            len,
            top,
            skip,
        } => {
            let bitstrs = load_file(&file)?;
            let counts = get_substr_counts(&bitstrs, len, skip);
            let mut sorted: Vec<_> = counts.iter().collect();
            sorted.sort_by(|a, b| b.1.cmp(a.1));

            println!("=== Top {top} Substrings (len={len}): {file} ===");
            println!();
            println!("{:<16}  {:>8}", "substring", "count");
            for (substr, ct) in sorted.iter().take(top) {
                println!("{:<16}  {:>8}", substr, ct);
            }
        }

        Commands::Rank { file } => {
            let bitstrs = load_file(&file)?;
            let ps = ProtocolStructure::infer_structure(&positionwise_entropy(&bitstrs));
            let varying_bitstrs: Vec<Bitstream> = bitstrs
                .iter()
                .map(|bs| ps.extract_varying_bits(bs).and_then(Bitstream::new))
                .collect::<Result<Vec<_>, _>>()?;
            let mut bitmat = BitMatrix::new(&varying_bitstrs)?;
            // XOR to remove affine element
            for ii in 1..bitmat.num_rows() {
                for jj in 0..bitmat.num_cols() {
                    bitmat[ii][jj] ^= bitmat[0][jj];
                }
            }
            for jj in 0..bitmat.num_cols() {
                bitmat[0][jj] = 0;
            }
            let ranks = windowed_rank(&bitmat);
            print_rank_graph(&ranks, &ps);
        }

        Commands::Crc {
            file,
            max_iters,
            sample_size,
        } => {
            let bitstrs = load_file(&file)?;
            let num_iters = max_iters.unwrap_or(10);
            match find_crc(&bitstrs, Some(num_iters), sample_size) {
                Ok(result) => {
                    let poly_val: u128 = result.crc_polynomial[..result.crc_polynomial.len() - 1]
                        .iter()
                        .enumerate()
                        .fold(0u128, |acc, (i, &b)| acc | ((b as u128) << i));
                    println!("=== CRC: {file} ===");
                    println!();
                    println!("Polynomial:  0x{poly_val:x} ({}-bit)", result.width);
                    println!(
                        "Location:    bit {} in frame (0-indexed)",
                        result.frame_start_col
                    );
                    println!("refin:       {}", result.refin);
                    println!("refout:      {}", result.refout);
                    println!("xor_val:     0x{:x}", result.xor_val);
                    println!("Score:       {:.1}%", result.score * 100.0);
                    println!(
                        "Poly found:  {}/{num_iters} iterations",
                        result.ransac_score
                    );
                    println!();
                }
                Err(BitkitError::CrcFieldDiscontinuity(rank_results, ps)) => {
                    println!("No CRC found in {num_iters} iterations.");
                    print_rank_graph(&rank_results, &ps);
                }
                Err(e) => return Err(e),
            }
        }

        Commands::Correlate { file, a, b, top } => {
            let bitstrs = load_file(&file)?;
            if a >= bitstrs.len() || b >= bitstrs.len() {
                eprintln!(
                    "Index out of range. File has {} bitstreams (0-indexed).",
                    bitstrs.len()
                );
                std::process::exit(1);
            }
            let corr = get_cross_correlation(&bitstrs[a], &bitstrs[b]);

            println!("=== Correlation: stream[{a}] vs stream[{b}] in {file} ===");
            println!();

            let peak = corr.iter().max_by_key(|r| r.matches()).unwrap();
            println!(
                "Peak: offset={}, matches={}/{} ({:.1}%)",
                peak.offset(),
                peak.matches(),
                peak.overlap(),
                100.0 * peak.score()
            );
            println!();

            let mut sorted = corr.iter().collect::<Vec<_>>();
            sorted.sort_by(|a, b| b.score().partial_cmp(&a.score()).unwrap());

            println!("Top {top} results by score:");
            println!(
                "{:>8}  {:>8}  {:>8}  {:>8}",
                "offset", "matches", "overlap", "score"
            );
            for r in sorted.iter().take(top) {
                println!(
                    "{:>8}  {:>8}  {:>8}  {:>8.4}",
                    r.offset(),
                    r.matches(),
                    r.overlap(),
                    r.score()
                );
            }
        }
    }
    Ok(())
}
