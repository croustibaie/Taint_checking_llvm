#[macro_use] extern crate lazy_static;
extern crate ansi_term;

mod cli;
mod graph;

use cli::parse_opts;
use graph::Graph;
use graph::meta::SimpleMetaDB;

fn main() {
    let cli_opts = parse_opts();

    let graph = Graph::<SimpleMetaDB>::new(&cli_opts);
}
