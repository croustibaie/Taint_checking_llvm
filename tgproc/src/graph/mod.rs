mod tgnode;

use std::collections::HashMap;
use std::io::BufReader;
use std::io::BufRead;
use std::fs::File;
use std::path::Path;
use std::io::Result;
use std::rc::Rc;

use self::tgnode::TgNode;
use super::cli::Options;

pub struct Graph<'a> {
    ops : HashMap<&'a str, Rc<TgNode>>,
    sinks : Vec<Rc<TgNode>>,
    options : &'a Options
}

impl<'a> Graph<'a> {
    fn is_tg_op_line(line: &str) -> bool {
        line.split(" | ").count() == 5
    }
    
    pub fn new(options: &Options) -> Result<Graph> {
        let mut graph = Graph {
            ops : HashMap::new(),
            sinks : vec![],
            options: options
        };

        let f = try!(File::open(&options.logfile));
        let file = BufReader::new(&f);
        for (idx, line) in file.lines().enumerate() {
            let l : String = line.unwrap();

            if ! Graph::is_tg_op_line(&l) {
                continue;
            }

            let tgo = TgNode::new(&l, idx, &graph.ops);

            if tgo.is_def() {
                if graph.ops.contains_key(tgo.var) {
                    panic!(format!("ERROR: Duplicated definition in lines {} and {}",
                                   graph.ops.get(tgo.var).unwrap().idx + 1,
                                   idx+1));
                }
                graph.ops.insert(tgo.var, tgo.clone());
            }

            if tgo.is_sink() {
                graph.sinks.push(tgo.clone());
            }
        };

        Ok(graph)
    }
}
