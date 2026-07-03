use clap::Parser;

#[derive(Parser)]
struct Args {
    symlen: usize,
}

fn main() {
    let args = Args::parse();
}
