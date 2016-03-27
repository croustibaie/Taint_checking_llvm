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
    sinks : Vec<Rc<TgNode>>,
    options : &'a Options
}

impl<'a> Graph<'a> {
    fn is_tg_op_line(line: &str) -> bool {
        line.split(" | ").count() == 5
    }
    
    pub fn new(options: &Options) -> Result<Graph> {
        let mut tg_ops: HashMap<String, Rc<TgNode>> = HashMap::new();
        
        let mut graph = Graph {
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

            let l_split = l.split(" | ");
            let tnt_flow = l_split.skip(4).next().unwrap();
            
            let (var, tgo) = TgNode::new(&tnt_flow, idx, &tg_ops);

            match var {
                Some(v) => {
                    match tg_ops.get(&v) {
                        Some(op) => panic!(format!("ERROR: Duplicated definition in lines {} and {}",
                                                   op.idx + 1,
                                                   idx+1)),
                        None => {}
                    }
                    tg_ops.insert(v, tgo.clone());
                },
                None => {}
            }

            if tgo.is_sink() {
                graph.sinks.push(tgo.clone());
            }
        };

        Ok(graph)
    }
}
