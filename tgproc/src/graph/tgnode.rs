extern crate regex;

use std::iter::Filter;
use std::slice::Iter;
use std::collections::HashMap;
use std::rc::Rc;
use std::cmp::PartialEq;
use std::cmp::Eq;
use std::hash::Hash;
use std::hash::Hasher;
use self::regex::Regex;

#[derive(PartialEq)]
pub enum Taint {
    Red,
    Blue,
    Green
}

/// As there might be very many tg nodes floating around it is very important
/// to keep the memory footprint minimal w/o loosing information. Because of that
/// a TgNode only contains the absolutely necessary information needed for the
/// graph search. For convenience one a TgNode is usually wrapped in a TgMetaNode
/// that stores additional information about the node.
/// If performance is necessary this construct allows us to easily loose all
/// irrelevant information to keep the memory footprint small.
pub struct TgNode {
    pub idx: usize, // the index of the line in the taintgrind log
    pub var: Option<String>,
    pub preds: Vec<Option<Rc<TgNode>>>,
    pub sink_reasons: Vec<Rc<TgNode>>,
    pub taint: Taint
}

pub struct TgMetaNode {
    pub tgnode: TgNode,

    pub line: String,
    pub func: String,

    addr: String,
    file: String,
    lineno: usize
}

pub type TgNodeMap = HashMap<String, Rc<TgNode>>;

impl TgNode {
    pub fn new(loc_part: &str,
               cmd_part: &str,
               tnt_flow: &str,
               idx: usize,
               graph: &TgNodeMap) -> Rc<TgNode> {
        let mut node = TgNode {
            idx: idx,
            var: None,
            preds: vec![],
            sink_reasons: vec![],
            taint: Taint::Green
        };

        // connect to predecessors + find some sink_reasons
        node.analyze_taint_flow(tnt_flow, graph);
        
        // calculate the taint
        node.calc_taint(cmd_part);

        node.calc_sink(loc_part, cmd_part);
        
        Rc::new(node)
    }

    /// Analyze the taint flow
    ///
    /// Returns the variable that is defined in this node if any
    fn analyze_taint_flow(&mut self,
                          tnt_flow: &str,
                          graph: &TgNodeMap) {
        lazy_static! {
            static ref RE_TNT_FLOW: Regex = Regex::new(r"^(.+?) <-?(\*?)- (.+?)$").unwrap();
        }
        
        for pred in tnt_flow.split("; ") {
            if let Some(cap) = RE_TNT_FLOW.captures(pred) {
                if cap.at(2).unwrap().is_empty() {
                    // e.g. t54_1741 <- t42_1773, t29_4179
                    match self.var {
                        Some(ref s) => assert!(s == cap.at(1).unwrap()),
                        None => self.var = Some(cap.at(1).unwrap().to_string())
                    }
                    
                    for f in cap.at(3).unwrap().split(", ") {
                        self.preds.push(graph.get(f).map(|n| n.clone()));
                    }
                } else {
                    // e.g. t78_744 <*- t72_268 (for dereferencing)
                    // or t78_744 <-*- t72_268 (for storing)
                    // we MUST not dereference or store a red value,
                        // however this does not count as taintflow
                    for f in cap.at(3).unwrap().split(", ") {
                        if let Some(n) = graph.get(f) {
                            if n.is_red() {
                                self.sink_reasons.push(n.clone());
                            }
                        }
                    }
                }
            } else { // e.g. t54_1741
                for f in pred.split(", ") {
                    self.preds.push(graph.get(f).map(|n| n.clone()));
                }
            }
        }
    }

    #[allow(unused_parens)]
    fn calc_taint(&mut self, cmd_part: &str) {
        self.inherit_taint();

        lazy_static! {
            static ref RE_SUB_CMD: Regex = Regex::new(r"^Sub\d\d? .+ (.+)").unwrap();
        }
                
        // we cannot get from green to red and we cannot go back from red
        // so further checking is only interesting if we are blue
        if self.is_blue() {
            if let Some(cmd) = cmd_part.split(" = ").nth(1) {
                assert!(cmd_part.split(" = ").count() == 2);
                
                if (cmd.starts_with("Mul") ||
                    cmd.starts_with("Div") ||
                    cmd.starts_with("Mod") ||
                    cmd.starts_with("And") ||
                    cmd.starts_with("Or") ||
                    cmd.starts_with("Xor") ||
                    cmd.starts_with("Shl") ||
                    cmd.starts_with("Sar")) {
                    self.taint = Taint::Red;
                } else if cmd.starts_with("Add") {
                    let mut ngp = self.preds.iter().filter(|&pred| {
                        if let Some(ref p) = *pred { ! p.is_green() } else { true }
                    });
                    
                    if ngp.nth(1).is_some() { // at least two blue predecessors
                        self.taint = Taint::Red;
                    }
                } else if cmd.starts_with("Cmp") {
                    // because we are blue at least one pred is blue
                    // if the other one is blue, too, everything is fine and we are green
                    // if the other one is green nothing is fine and we go red
                    let all_blue = self.preds.iter().all(|pred| {
                        if let Some(ref p) = *pred { p.is_blue() } else { true }
                    });
                    
                    if all_blue {
                        self.taint = Taint::Green
                    } else { // we know that at least one pred is blue because self.is_blue() above
                        self.taint = Taint::Red
                    }
                } else {
                    if let Some(cap) = RE_SUB_CMD.captures(cmd) {
                        let mut ngp = self.preds.iter().filter(|&pred| {
                            if let Some(ref p) = *pred { ! p.is_green() } else { true }
                        });
                        let ngp0 = ngp.next();
                        
                        // we allow (blue - green) but not (green - blue) or (blue - blue)
                        if ngp.next().is_some() {
                            // do not allow (blue - blue)
                            self.taint = Taint::Red;
                        } else {
                            match ngp0 {
                                Some(&Some(ref p)) => {
                                    let subtrahend = cap.at(1).unwrap();
                                    
                                    // this one is a predecessor, so it should have a var set
                                    assert!(p.var.is_some());
                                    
                                    if (p.var.as_ref().unwrap() == subtrahend) {
                                        self.taint = Taint::Red
                                    }
                                },
                                Some(&None) => {
                                    // here we could have the following commands
                                    // t3 = Sub undef t2 | | | t3 <- undef       [BLUE]
                                    // t3 = Sub undef t2 | | | t3 <- undef, t2   [BLUE]
                                    // t3 = Sub t2 undef | | | t3 <- undef       [RED]
                                    // t3 = Sub t2 undef | | | t3 <- undef, t2   [RED]
                                    // where t2 is always green if it carries taint
                                    // and undef wasn't defined before (is None here)
                                    // which means that undef carries blue taint by default
                                    
                                    // TODO
                                    panic!("Not implemented");
                                },
                                None => {} // (green - green), all good
                            }
                        }
                    } // end if re matches
                }
            }
        } // end if self.is_blue
    }

    fn calc_sink(&mut self, loc_part: &str, cmd_part: &str) {
        lazy_static! {
            static ref RE_IF_CMD: Regex = Regex::new(r"^IF ([\w_]+) ").unwrap();
            static ref RE_TERNARY_CMD: Regex = Regex::new(r"[\w_]+ = ([\w_]+) \? [\w_]+ : [\w_]+").unwrap();
        }
        
        // Is this a sink? Let's see...
        // note the LOAD/STORE with red taint is already handled in analyze_taint_flow
        if ! self.is_green() {
            if loc_part.contains(" _Exit ") {
                // we must not allow returning tainted exit values
                for pred in self.preds.iter() {
                    if let Some(ref p) = *pred {
                        self.sink_reasons.push(p.clone())
                    }
                }
            } else {
                let match_ = RE_IF_CMD.captures(cmd_part).or_else(|| RE_TERNARY_CMD.captures(cmd_part));
                if let Some(cap) = match_ {
                    // we can safely allow blue taint to reach a condition because
                    // it is either 0 (null) in all variants or a valid pointer (-> true)
                    for pred in self.preds.iter() {
                        if let Some(ref p) = *pred {
                            // this one is a predecessor, so it should have a var set
                            assert!(p.var.is_some());
                            
                            if p.is_red() && (p.var.as_ref().unwrap() == cap.at(1).unwrap()) {
                                self.sink_reasons.push(p.clone())
                            }
                        }
                    }
                }
            }
        }
    }

    fn inherit_taint(&mut self) {
        self.taint = if self.is_source() { Taint::Blue } else { Taint::Green };

        for pred in self.preds.iter() {
            if let Some(ref p) = *pred {
                if p.is_red() {
                    self.taint = Taint::Red;
                    break // once we are red we cannot go back anyway
                } else if p.is_blue() {
                    self.taint = Taint::Blue
                }
            }
        }
    }

    /// A TgNode is a source of taint if it does not have any predecessors
    /// or sink reasons different from None
    pub fn is_source(&self) -> bool {
        // sink reasons are not Options, so there must not be any sink_reasons
        self.sink_reasons.is_empty() && self.preds.iter().all(|p| p.is_none())
    }

    pub fn is_sink(&self) -> bool {
        ! self.sink_reasons.is_empty()
    }

    pub fn is_red(&self) -> bool {
        self.taint == Taint::Red
    }

    pub fn is_blue(&self) -> bool {
        self.taint == Taint::Blue
    }

    pub fn is_green(&self) -> bool {
        self.taint == Taint::Green
    }
}

impl PartialEq for TgNode {
    fn eq(&self, other: &TgNode) -> bool {
        self.idx == other.idx
    }
}

impl Hash for TgNode {
    fn hash<H>(&self, state: &mut H) where H: Hasher {
        state.write_usize(self.idx);
        state.finish();
    }
}

impl Eq for TgNode {}
