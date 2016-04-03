mod tgnode;
pub mod meta;

use std::collections::HashMap;
use std::collections::VecDeque;
use std::iter::Iterator;
use std::cmp::Ordering;
use std::io::BufReader;
use std::io::BufRead;
use std::fs::File;
use std::io::Result;
use std::rc::Rc;
use ansi_term::Colour;

use self::tgnode::TgNode;
use self::tgnode::TgNodeMap;
use self::meta::TgMetaDb;
use self::meta::TgMetaNode;
use super::cli::Options;

const PRINT_DETECTION_VERBOSITY: u8 = 20;

pub struct Graph {
    pub sinks : Vec<Rc<TgNode>>,
    options : Options,
    idxwidth : usize,
}

struct LineParts<'a> {
    loc : &'a str,
    cmd : &'a str,
    tnt_flow : &'a str
}

impl<'a> LineParts<'a> {
    fn new(line: &'a str) -> Option<LineParts<'a>> {
        let mut l_split = line.split(" | ");

        let loc_part = l_split.next();
        let cmd_part = l_split.next();
        let tnt_flow = l_split.nth(2);

        tnt_flow.map(|flow| {
            LineParts {
                loc: loc_part.unwrap(),
                cmd: cmd_part.unwrap(),
                tnt_flow: flow
            }
        })
    }
}

impl Graph {
    pub fn new<T: TgMetaDb>(options: Options, mut meta_db: Option<&mut T>) -> Result<Graph> {
        assert!(options.sink_lines.is_empty(), "Manually setting sink lines not yet implemented");
        
        let mut tg_ops: TgNodeMap = HashMap::new();
        
        let mut graph = Graph {
            sinks : vec![],
            options: options,
            idxwidth: 8
        };

        let f = try!(File::open(&graph.options.logfile));
        let file = BufReader::new(&f);
        for (idx, line) in file.lines().enumerate() {
            graph.idxwidth = (idx+1).to_string().len();
            
            let l : String = line.unwrap();

            if let Some(lparts) = LineParts::new(&l) {
                let tgo: Rc<TgNode> = TgNode::new(lparts.loc,
                                              lparts.cmd,
                                              lparts.tnt_flow,
                                              idx,
                                              &tg_ops);

                let mut kept = false;
                
                if let Some(ref v) = tgo.var {
                    let vx: &str = v;
                    if let Some(op) = tg_ops.get(vx) {
                        panic!(format!("ERROR: Duplicated definition in lines {} and {}",
                                       op.idx + 1,
                                       idx+1))
                    }
                    tg_ops.insert(vx.to_string(), tgo.clone());
                    kept = true;
                }
                
                if tgo.is_sink() {
                    graph.sinks.push(tgo.clone());
                    kept = true;
                }
                
                if graph.options.mark_taint {
                    print!("{:8}   ", tgo.idx+1);
                    if graph.options.color {
                        println!("{}", tgo.taint.color(&l));
                    } else {
                        println!("[{}]  {}", tgo.taint.abbrv(), l);
                    }
                }
                
                if kept {
                    if let Some(ref mut mdb) = meta_db.as_mut() {
                        mdb.insert(idx, l.clone(), lparts.loc);
                    }
                }
            }
        }

        Ok(graph)
    }

    pub fn get_traces<'l>(&self, sink: &'l TgNode) -> Vec<Vec<&'l TgNode>> {
        let print_detection = self.options.verbosity >= PRINT_DETECTION_VERBOSITY;
        
        // we can't use recursion here because the graph can be VERY huge and the
        // stack depth is just not enough for that
        let mut sources = vec![];

        // all nodes that still need to be processed
        let mut queue: VecDeque<&TgNode> = VecDeque::new();
        queue.push_back(sink);

        // a map from detected nodes to their successors
        let mut detected : HashMap<&TgNode, Option<&TgNode>> = HashMap::new();
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
                let all_preds : Vec<&TgNode> = if op.is_sink() {
                    op.sink_reasons.iter().map(|pred| pred.as_ref()).collect()
                } else {
                    op.preds.iter().filter_map(|pred| pred.as_ref().map(|p| p.as_ref())).collect()
                };

                // get all preds that are Some, non-green and haven't been detected yet
                let (mut preds, skipped) : (Vec<&TgNode>, Vec<&TgNode>) = all_preds.iter()
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
            let mut cur_opt : &Option<&TgNode> = &Some(src);

            while let Some(cur) = *cur_opt {
                trace.push(cur);
                cur_opt = detected.get(cur).unwrap();
            }

            paths.push(trace);
        }

        paths
    }

    pub fn print_traces_of<T: TgMetaDb>(&self, sink: &TgNode, meta_db: &mut T) {
        for (tidx,trace) in self.get_traces(sink).iter().enumerate() {
            // separate each source
            if tidx > 0 {
                let sep = "--------------------------------------------------------------------------------";
                if self.options.color {
                    println!("{}", Colour::Yellow.paint(sep));
                } else {
                    println!("{}", sep);
                }
            }

            println!(">>>> The origin of the taint should be just here <<<<");

            if self.options.src_only {
                let src = trace[0];
                let l = meta_db.get(src);

                
                
                //println!("{} {}", src.taint.abbrv(), l);
            }
        }
    }

    pub fn print_traces<T: TgMetaDb>(&self, meta_db: &mut T) {
        for (sidx,sink) in self.sinks.iter().enumerate() {
            // separate each sink
            if sidx > 0 {
                let sep = "================================================================================";
                if self.options.color {
                    println!("{}", Colour::Green.paint(sep));
                } else {
                    println!("{}", sep);
                }
            }

            self.print_traces_of(sink, meta_db);
        }
    }
}
