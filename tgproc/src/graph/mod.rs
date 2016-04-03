mod tgnode;
pub mod meta;

use std::collections::HashMap;
use std::collections::HashSet;
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
use self::meta::DebugInfoDb;
use super::cli::Options;

const PRINT_DETECTION_VERBOSITY: u8 = 20;

pub struct Graph {
    pub sinks : Vec<Rc<TgNode>>,
    pub options : Options,
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
    #[allow(unused_parens)]
    pub fn new<T: TgMetaDb>(options: Options, mut meta_db: Option<&mut T>) -> Result<Graph> {
        let mut tg_ops: TgNodeMap = HashMap::new();
        let mut locations = HashSet::new();
        
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
                let mut tgo: Rc<TgNode> = TgNode::new(lparts.loc,
                                                  lparts.cmd,
                                                  lparts.tnt_flow,
                                                  idx,
                                                  &tg_ops);
                let meta_node = TgMetaNode::new(l.clone(), lparts.loc);
                
                let mut kept = false;

                // if the sinks were set manually we have to fix the reasons
                if ! graph.options.sink_lines.is_empty() {
                    let inc_idx = idx+1;
                    
                    if graph.options.sink_lines.contains(&inc_idx) {
                        if ! tgo.is_sink() {
                            let reasons = tgo.preds
                                .iter()
                                .filter_map(|p| p.clone())
                                .collect::<Vec<Rc<TgNode>>>();
                            Rc::get_mut(&mut tgo).unwrap().sink_reasons.extend_from_slice(reasons.as_slice())
                        }
                    } else {
                        let sr: &mut Vec<Rc<TgNode>> = &mut Rc::get_mut(&mut tgo).unwrap().sink_reasons;
                        
                        sr.clear()
                    }
                }
                
                if let Some(ref v) = tgo.var {
                    if let Some(op) = tg_ops.get(v.as_str()) {
                        panic!(format!("ERROR: Duplicated definition in lines {} and {}",
                                       op.idx + 1,
                                       idx+1))
                    }

                    let mut node_for_var = Some(tgo.clone());
                    kept = true;

                    // filter out unnecessary nodes
                    if ((graph.options.no_tmp_instr && tgo.has_tmp_var()) ||
                        (graph.options.no_libs && meta_node.is_lib()) ||
                        (graph.options.unique_locs && !locations.insert(meta_node.loc.addr))) {
                        if tgo.preds.is_empty() {
                            if graph.options.verbosity >= 20 {
                                println!("REPLACING   {}", l);
                                println!("BY          NONE");
                            }
                            node_for_var = None;
                            kept = false;
                        } else if tgo.preds.len() == 1 {
                            if let Some(ref pred) = tgo.preds[0] {
                                if pred.taint == tgo.taint { // no taint change occurred
                                    if graph.options.verbosity >= 20 {
                                        println!("REPLACING   {}", l);
                                        println!("BY          {}", meta_db.as_mut().unwrap().get_mut(pred).unwrap().line);
                                    }
                                    // we just replace the node in the map with its pred
                                    node_for_var = Some(pred.clone());
                                    kept = false;
                                }
                            } else {
                                if graph.options.verbosity >= 20 {
                                    println!("REPLACING   {}", l);
                                    println!("BY          NONE");
                                }
                                node_for_var = None;
                                kept = false;
                            }
                        }
                    }

                    if let Some(nfv) = node_for_var {
                        tg_ops.insert(v.to_string(), nfv);
                    }
                }

                if tgo.is_sink() {
                    graph.sinks.push(tgo.clone());
                    kept = true;
                }
                
                if graph.options.mark_taint {
                    print!("{:8}   ", tgo.idx+1);
                    if graph.options.color {
                        println!("{}", tgo.taint.paint(&l));
                    } else {
                        println!("[{}]  {}", tgo.taint.abbrv(), l);
                    }
                }
                
                if kept {
                    if let Some(ref mut mdb) = meta_db.as_mut() {
                        mdb.insert(idx, meta_node);
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
                if print_detection { println!("found source") }
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

    pub fn print_traces_of<T: TgMetaDb>(&self,
                                        sink: &TgNode,
                                        meta_db: &mut T,
                                        debug_db: &mut DebugInfoDb) {
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
                let meta = meta_db.get_mut(src).unwrap();
                meta.loc.complete_info(debug_db);
                src.print(meta, self.options.color);
            } else if self.options.mark_trace {
                let f = File::open(&self.options.logfile).unwrap();
                let file = BufReader::new(&f);

                let mut trace_iter = trace.iter().peekable();
                
                for (idx, l) in file.lines().enumerate() {
                    let line = l.unwrap();
                    print!("{:8}   ", idx+1);

                    if trace_iter.peek().map_or(false, |n| n.idx == idx) {
                        let node = trace_iter.next().unwrap();

                        if self.options.color {
                            let clr = node.taint.color();
                            if node.is_sink() {
                                println!("{}", clr.bold().paint(line))
                            } else {
                                println!("{}", clr.paint(line))
                            }
                        } else {
                            if node.is_sink() {
                                print!("*{}*  ", node.taint.abbrv())
                            } else {
                                print!("[{}]  ", node.taint.abbrv())
                            }
                            println!("{}", line);
                        }
                        
                    } else {
                        if ! self.options.color {
                            print!("     ");
                        }
                        println!("{}", line);
                    }
                }
            } else {
                for node in trace {
                    let mut meta: &mut TgMetaNode = meta_db.get_mut(node).unwrap();

                    if self.options.taintgrind_trace {
                        println!("{}", node.taint.paint(&meta.line))
                    } else {
                        meta.loc.complete_info(debug_db);
                        node.print(meta, self.options.color)
                    }
                }
            }
        }
    }

    pub fn print_traces<T: TgMetaDb>(&self, meta_db: &mut T) {
        let mut debug_db = DebugInfoDb::new();
        
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

            self.print_traces_of(sink, meta_db, &mut debug_db);
        }
    }
}
