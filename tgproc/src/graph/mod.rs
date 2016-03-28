mod tgnode;

use std::collections::HashMap;
use std::collections::VecDeque;
use std::io::BufReader;
use std::io::BufRead;
use std::fs::File;
use std::path::Path;
use std::io::Result;
use std::rc::Rc;

use self::tgnode::TgNode;
use self::tgnode::TgNodeMap;
use super::cli::Options;

const PRINT_TRACE_VERBOSITY: u8 = 20;

pub struct Graph<'a> {
    sinks : Vec<Rc<TgNode>>,
    options : &'a Options,
    idxwidth : usize
}

impl<'a> Graph<'a> {
    fn is_tg_op_line(line: &str) -> bool {
        line.split(" | ").count() == 5
    }
    
    pub fn new(options: &Options) -> Result<Graph> {
        assert!(options.sink_lines.is_empty(), "Manually setting sink lines not yet implemented");
        
        let mut tg_ops: TgNodeMap = HashMap::new();
        
        let mut graph = Graph {
            sinks : vec![],
            options: options,
            idxwidth: 8
        };

        let f = try!(File::open(&options.logfile));
        let file = BufReader::new(&f);
        for (idx, line) in file.lines().enumerate() {
            graph.idxwidth = (idx+1).to_string().len();
            
            let l : String = line.unwrap();

            if ! Graph::is_tg_op_line(&l) {
                continue;
            }

            let mut l_split = l.split(" | ");
            let loc_part = l_split.next().unwrap();
            let cmd_part = l_split.next().unwrap();
            let tnt_flow = l_split.nth(2).unwrap();
            
            let tgo: Rc<TgNode> = TgNode::new(&loc_part, &cmd_part, &tnt_flow, idx, &tg_ops);

            match tgo.var {
                Some(ref v) => {
                    let vx: &str = v;
                    match tg_ops.get(vx) {
                        Some(op) => panic!(format!("ERROR: Duplicated definition in lines {} and {}",
                                                   op.idx + 1,
                                                   idx+1)),
                        None => {}
                    }
                    tg_ops.insert(vx.to_string(), tgo.clone());
                },
                None => {}
            }

            if tgo.is_sink() {
                graph.sinks.push(tgo.clone());
            }
        };

        Ok(graph)
    }

    pub fn get_traces(&self, sink: Rc<TgNode>) {
        // we can't use recursion here because the graph can be VERY huge and the
        // stack depth is just not enough for that
        //let mut sources = vec![];

        // all nodes that still need to be processed
        let mut queue = VecDeque::new();
        queue.push_back(sink);

        // a map from detected nodes to their successors
        //let mut detected = HashMap::new();
        //detected.insert(sink, None);

        while ! queue.is_empty() {
            if self.options.verbosity >= PRINT_TRACE_VERBOSITY {
                print!("{:>30}  ",
                       format!("{:?}", queue.iter().map(|n| n.idx+1).collect::<Vec<usize>>()))
            }

            let op = queue.pop_front();

            if self.options.verbosity >= PRINT_TRACE_VERBOSITY {
                // TODO
            }
        }
    }
}
