use super::Graph;
use super::meta::TgMetaDb;
use super::TgNode;
use super::meta::TgMetaNode;
use super::meta::DebugInfoDb;
use ansi_term::Colour;
use std::io::BufReader;
use std::io::BufRead;
use std::fs::File;
use std::collections::HashSet;

pub struct GraphPrinter<'a, T: 'a + TgMetaDb> {
    graph: &'a Graph,
    meta_db: &'a mut T,
    debug_db: DebugInfoDb,
    printed_srcs: HashSet<u64>,
    printed_sinks: HashSet<u64>,
    skipped_traces: u32
}

impl<'a, T: TgMetaDb> GraphPrinter<'a, T> {
    pub fn new<'b, U: TgMetaDb>(graph: &'b Graph, meta_db: &'b mut U) -> GraphPrinter<'b, U> {
        GraphPrinter {
            graph: graph,
            meta_db: meta_db,
            debug_db: DebugInfoDb::new(),
            printed_srcs: HashSet::new(),
            printed_sinks: HashSet::new(),
            skipped_traces: 0
        }
    }

    /**
     * @return true if this one was completely skipped
     */
    pub fn print_traces_of(&mut self,
                           sink: &TgNode) -> bool {
        let mut completely_skipped = true;
        if self.graph.options.single_sink {
            let sink_addr = self.meta_db.get(sink).unwrap().loc.addr;
            if !self.printed_sinks.insert(sink_addr) {
                // if printed_sinks already contains this address we skip this one
                self.skipped_traces += 1;
                return completely_skipped;
            }
        }

        for (tidx,trace) in self.graph.get_traces(sink).iter().enumerate() {
            if self.graph.options.single_src {
                let src = trace[0];
                let src_addr = self.meta_db.get(src).unwrap().loc.addr;
                if !self.printed_sinks.insert(src_addr) {
                    // if printed_srcs already contains this address we skip this one
                    self.skipped_traces += 1;
                    continue;
                }
            }
            
            // separate each source
            if tidx > 0 {
                self.print_sep("--------------------------------------------------------------------------------", Colour::Yellow);
            }

            println!(">>>> The origin of the taint should be just here <<<<");
            completely_skipped = false;

            if self.graph.options.src_only {
                // print only the source, not the whole trace
                let src = trace[0];
                let meta = self.meta_db.get_mut(src).unwrap();
                meta.loc.complete_info(&mut self.debug_db);
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
                    let meta: &mut TgMetaNode = self.meta_db.get_mut(node).unwrap();
                    println!("{}", node.taint.paint(&meta.line))
                }
            } else {
                // default behavior: print the source lines of the trace
                for node in trace {
                    let meta: &mut TgMetaNode = self.meta_db.get_mut(node).unwrap();
                    meta.loc.complete_info(&mut self.debug_db);
                }

                let mut prev_meta : Option<&TgMetaNode> = None;
                let mut prev_node : Option<&TgNode> = None;
                
                for node in trace {
                    let meta: &TgMetaNode = self.meta_db.get(node).unwrap();

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

        completely_skipped
    }

    pub fn print_traces(&mut self) {
        self.printed_srcs.clear();
        self.printed_sinks.clear();
        self.skipped_traces = 0;

        let mut skipped_last = false;
        
        for (sidx,sink) in self.graph.sinks.iter().enumerate() {
            // separate each sink
            if sidx > 0 && !skipped_last {
                self.print_sink_sep();
            }

            skipped_last = self.print_traces_of(sink);
        }

        if self.graph.options.single_src || self.graph.options.single_sink {
            if !skipped_last {
                self.print_sink_sep();
            }
            println!("{} traces skipped.", self.skipped_traces);
        }
    }

    fn print_sink_sep(&self) {
        self.print_sep("================================================================================", Colour::Green);
    }

    fn print_sep(&self, sep: &str, color: Colour) {
        if self.graph.options.color {
            println!("{}", color.paint(sep));
        } else {
            println!("{}", sep);
        }
    }
}
