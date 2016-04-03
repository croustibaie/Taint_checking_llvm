#[macro_use] extern crate lazy_static;
extern crate ansi_term;

mod cli;
mod graph;

use cli::parse_opts;
use graph::Graph;
use graph::meta::TgMetaDb;
use graph::meta::SimpleMetaDB;

fn main() {
    let cli_opts = parse_opts();

    let mut meta_db = SimpleMetaDB::new();
    match Graph::new(cli_opts, Some(&mut meta_db)) {
        Ok(graph) => graph.print_traces(&mut meta_db),
        Err(x) => println!("{}", x)
    }
}
