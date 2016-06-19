use super::Graph;
use super::meta::TgMetaDb;
use super::TgNode;
use super::meta::TgMetaNode;
use super::meta::DebugInfoDb;
use ansi_term::Colour;
use std::io::BufReader;
use std::io::BufRead;
use std::fs::File;

pub struct GraphPrinter<'a> {
    graph: &'a Graph
}

impl<'a> GraphPrinter<'a> {
    pub fn new<'b>(graph: &'b Graph) -> GraphPrinter {
        let graph = GraphPrinter {
            graph: graph
        };

        graph
    }

    pub fn print_traces_of<T: TgMetaDb>(&self,
                                        sink: &TgNode,
                                        meta_db: &mut T,
                                        debug_db: &mut DebugInfoDb) {
        for (tidx,trace) in self.graph.get_traces(sink).iter().enumerate() {
            // separate each source
            if tidx > 0 {
                let sep = "--------------------------------------------------------------------------------";
                if self.graph.options.color {
                    println!("{}", Colour::Yellow.paint(sep));
                } else {
                    println!("{}", sep);
                }
            }

            println!(">>>> The origin of the taint should be just here <<<<");

            if self.graph.options.src_only {
                // print only the source, not the whole trace
                let src = trace[0];
                let meta = meta_db.get_mut(src).unwrap();
                meta.loc.complete_info(debug_db);
                src.print(meta, self.graph.options.color);
            } else if self.graph.options.mark_trace {
                // print the whole taintgrind trace
                let f = File::open(&self.graph.options.logfile).unwrap();
                let file = BufReader::new(&f);

                let mut trace_iter = trace.iter().peekable();
                
                for (idx, l) in file.lines().enumerate() {
                    let line = l.unwrap();
                    print!("{:8}   ", idx+1);

                    if trace_iter.peek().map_or(false, |n| n.idx == idx) {
                        let node = trace_iter.next().unwrap();

                        if self.graph.options.color {
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
                        if ! self.graph.options.color {
                            print!("     ");
                        }
                        println!("{}", line);
                    }
                }
            } else if self.graph.options.taintgrind_trace {
                // print the taintgrind lines of the trace instead of the source lines
                for node in trace {
                    let meta: &mut TgMetaNode = meta_db.get_mut(node).unwrap();
                    println!("{}", node.taint.paint(&meta.line))
                }
            } else {
                // default behavior: print the source lines of the trace
                for node in trace {
                    let meta: &mut TgMetaNode = meta_db.get_mut(node).unwrap();
                    meta.loc.complete_info(debug_db);
                }

                let mut prev_meta : Option<&TgMetaNode> = None;
                let mut prev_node : Option<&TgNode> = None;
                
                for node in trace {
                    let meta: &TgMetaNode = meta_db.get(node).unwrap();

                    if let Some(ref pn) = prev_node {
                        let pm = prev_meta.unwrap();
                        // don't print the same line twice, however, we have to print the last
                        // occurrence in order to get the taint right
                        if meta.loc != pm.loc {
                            pn.print(pm, self.graph.options.color);
                        }
                    }

                    prev_node = Some(node);
                    prev_meta = Some(meta)
                }

                if let Some(ref pn) = prev_node {
                    pn.print(prev_meta.unwrap(), self.graph.options.color);
                }
            }
        }
    }

    pub fn print_traces<T: TgMetaDb>(&mut self, meta_db: &mut T) {
        let mut debug_db = DebugInfoDb::new();
        
        for (sidx,sink) in self.graph.sinks.iter().enumerate() {
            // separate each sink
            if sidx > 0 {
                let sep = "================================================================================";
                if self.graph.options.color {
                    println!("{}", Colour::Green.paint(sep));
                } else {
                    println!("{}", sep);
                }
            }

            self.print_traces_of(sink, meta_db, &mut debug_db);
        }
    }
}
