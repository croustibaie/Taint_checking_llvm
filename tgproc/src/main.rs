#[macro_use] extern crate lazy_static;
extern crate ansi_term;

mod cli;
mod graph;

use cli::parse_opts;
use graph::Graph;
use graph::GraphPrinter;
use graph::meta::TgMetaDb;
use graph::meta::SimpleMetaDB;

fn main() {
    let cli_opts = parse_opts();

    let mut meta_db = SimpleMetaDB::new();
    match Graph::new(cli_opts, Some(&mut meta_db)) {
        Ok(graph) => {
            if ! graph.options.mark_taint {
                let mut x = GraphPrinter {
                    graph: &graph,
                    meta_db: &mut meta_db
                };
                
                //let x: GraphPrinter<SimpleMetaDB> = GraphPrinter::new(&graph, &mut meta_db);
                x.print_traces();
            }
        },
        Err(x) => println!("{}", x)
    }
}
