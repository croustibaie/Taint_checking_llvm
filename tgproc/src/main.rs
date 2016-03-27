mod cli;
mod graph;

use cli::parse_opts;
use graph::Graph;

fn main() {
    let cli_opts = parse_opts();

    let graph = Graph::new(&cli_opts);
}
