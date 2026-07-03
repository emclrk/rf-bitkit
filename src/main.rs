use clap::{Parser, Subcommand};
use rf_bitkit::proto::{ProtoField, ProtocolStructure};
use rf_bitkit::{
    find_common_prefix, from_txt, from_urh, get_alphabet_counts, get_cross_correlation,
    get_substr_counts, positionwise_entropy, BitkitError, Bitstream,
};
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
    },
    /// Find the common prefix across all bitstreams (preamble candidate)
    Prefix { file: String },
    /// Compute positionwise entropy and infer protocol field structure
    Infer {
        file: String,
        /// Entropy tolerance: positions with entropy <= eps are marked ambiguous
        #[arg(long)]
        eps: Option<f32>,
    },
    /// Show normalized entropy at each symbol length to help infer symbol size
    Sweep {
        file: String,
        #[arg(long, default_value_t = 8)]
        max_symlen: usize,
        #[arg(long, default_value_t = 0)]
        skip: usize,
    },
    /// Show symbol alphabet and frequency counts across all bitstreams
    Alphabet {
        file: String,
        #[arg(short, long, default_value_t = 1)]
        symlen: usize,
        #[arg(long, default_value_t = 0)]
        skip: usize,
    },
    /// Show the most frequent substrings of a given length
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
    /// Cross-correlate two bitstreams from a file by index
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

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), BitkitError> {
    match cli.command {
        Commands::Info { file, symlen, skip } => {
            let bitstrs = load_file(&file)?;
            let lengths: Vec<usize> = bitstrs.iter().map(|b| b.len()).collect();
            let min_len = lengths.iter().min().copied().unwrap_or(0);
            let max_len = lengths.iter().max().copied().unwrap_or(0);
            let avg_len = lengths.iter().sum::<usize>() as f32 / lengths.len() as f32;

            println!("=== Info: {file} ===");
            println!("Bitstreams: {}", bitstrs.len());
            println!("Lengths: min={min_len}, max={max_len}, avg={avg_len:.1}");
            println!();
            for (i, bs) in bitstrs.iter().enumerate() {
                println!(
                    "[{i:3}] {}  ({} bits)",
                    bs.skip(skip).to_hex(symlen),
                    bs.len()
                );
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

        Commands::Infer { file, eps } => {
            let bitstrs = load_file(&file)?;
            let ents = positionwise_entropy(&bitstrs);
            let ps = match eps {
                Some(e) => ProtocolStructure::infer_structure_tolerance(&ents, e),
                None => ProtocolStructure::infer_structure(&ents),
            };

            println!("=== Protocol Structure: {file} ===");
            println!();
            println!("Positionwise Entropy:");
            for (i, e) in ents.iter().enumerate() {
                println!("  [{i:3}] {e:.4}");
            }
            println!();
            let fields = ps.get_fields();
            let structure_str = fields
                .iter()
                .map(|(ft, ct)| format!("{}({ct})", field_name(ft)))
                .collect::<Vec<_>>()
                .join(" | ");
            println!("Inferred Structure:");
            println!("  {structure_str}");
            println!();
            let summary = ps.summarize();
            println!("Summary:");
            println!("  Fixed:   {} bits", summary[&ProtoField::Fixed]);
            println!("  Varying: {} bits", summary[&ProtoField::Varying]);
            if summary[&ProtoField::Ambiguous] > 0 {
                println!("  Ambiguous: {} bits", summary[&ProtoField::Ambiguous]);
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
