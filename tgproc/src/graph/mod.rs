mod tgnode;

use std::collections::HashMap;
use std::collections::VecDeque;
use std::iter::Iterator;
use std::cmp::Ordering;
use std::io::BufReader;
use std::io::BufRead;
use std::fs::File;
use std::io::Result;
use std::rc::Rc;

use self::tgnode::TgNode;
use self::tgnode::TgNodeMap;
use super::cli::Options;

const PRINT_DETECTION_VERBOSITY: u8 = 20;

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

    pub fn get_traces<'l>(&self, sink: &'l Rc<TgNode>) -> Vec<Vec<&'l Rc<TgNode>>> {
        let print_detection = self.options.verbosity >= PRINT_DETECTION_VERBOSITY;
        
        // we can't use recursion here because the graph can be VERY huge and the
        // stack depth is just not enough for that
        let mut sources = vec![];

        // all nodes that still need to be processed
        let mut queue: VecDeque<&Rc<TgNode>> = VecDeque::new();
        queue.push_back(sink);

        // a map from detected nodes to their successors
        let mut detected : HashMap<&Rc<TgNode>, Option<&Rc<TgNode>>> = HashMap::new();
        detected.insert(sink, None);

        while let Some(op) = queue.pop_front() {
            if print_detection {
                print!("{:>30}  detecting {:2$}",
                       format!("{:?}", queue.iter().map(|n| n.idx+1).collect::<Vec<usize>>()),
                       op.idx+1,
                       self.idxwidth);
                match *detected.get(op).unwrap() {
                    Some(ref successor) => print!(" from {:1$}  --  ", successor.idx+1, self.idxwidth),
                    None => print!("{:1$}  --  ", " ", self.idxwidth + 6)
                }
            }

            if op.is_source() {
                if print_detection { print!("found source") }
                sources.push(op);
            } else {
                let all_preds : Vec<&Rc<TgNode>> = if op.is_sink() {
                    op.sink_reasons.iter().collect()
                } else {
                    op.preds.iter().filter_map(|pred| pred.as_ref()).collect()
                };

                // get all preds that are Some, non-green and haven't been detected yet
                let (mut preds, skipped) : (Vec<&Rc<TgNode>>, Vec<&Rc<TgNode>>) = all_preds.iter()
                    .partition(|&p| (! p.is_green()) && (! detected.contains_key(p)));

                // put the red ones first
                preds.sort_by(|a, b| {
                    match (a.is_red(), b.is_red()) {
                        (true, true) => Ordering::Equal,
                        (true, false) => Ordering::Less,
                        (false, true) => Ordering::Greater,
                        (false, false) => Ordering::Equal
                    }
                });
                
                if print_detection {
                    println!("adding preds {:?} (skipping {:?})",
                             preds.iter().map(|p| p.idx + 1).collect::<Vec<usize>>(),
                             skipped.iter().map(|p| p.idx + 1).collect::<Vec<usize>>());
                }

                for pred in preds.iter() {
                    queue.push_back(pred);
                    detected.insert(pred, Some(op)); // link from where we found this one
                }
            }
        }

        let mut paths = vec![];

        for src in sources {
            let mut trace = vec![];
            let mut cur_opt : &Option<&Rc<TgNode>> = &Some(src);

            while let Some(cur) = *cur_opt {
                trace.push(cur);
                cur_opt = detected.get(cur).unwrap();
            }

            paths.push(trace);
        }

        paths
    }
}
