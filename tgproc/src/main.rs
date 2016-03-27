mod cli;

use cli::parse_opts;

fn main() {
    let cli_opts = parse_opts();

    println!("{}", cli_opts.logfile);
}
