use std::collections::HashMap;
use std::rc::Rc;
use std::cmp::PartialEq;
use std::cmp::Eq;
use std::hash::Hash;
use std::hash::Hasher;
use super::regex::Regex;
use ansi_term::Colour;
use ansi_term::ANSIString;

use super::meta::TgMetaNode;

#[derive(PartialEq)]
pub enum Taint {
    Red,
    Blue,
    Green
}

impl Taint {
    pub fn paint<'a>(&self, s : &'a str) -> ANSIString<'a> {
        self.color().paint(s)
    }

    pub fn color(&self) -> Colour {
        match *self {
            Taint::Red => Colour::Red,
            Taint::Blue => Colour::Blue,
            Taint::Green => Colour::Green
        }
    }

    pub fn abbrv(&self) -> &str {
        match *self {
            Taint::Red => "R",
            Taint::Blue => "B",
            Taint::Green => "G"
        }
    }
}

pub struct TgEdge {
    pub dest : Option<Rc<TgNode>>,
    
    /// the variable over which dest was reached
    pub via : String
}

impl TgEdge {
    fn new(via: String, dest: Option<Rc<TgNode>>) -> TgEdge {
        TgEdge { via: via, dest: dest }
    }
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
    pub preds: Vec<TgEdge>,
    pub sink_reasons: Vec<Rc<TgNode>>,
    pub taint: Taint
}

pub type TgNodeMap = HashMap<String, Rc<TgNode>>;

impl TgNode {
    pub fn new(loc_part: &str,
               cmd_part: &str,
               tnt_flow: &str,
               idx: usize,
               graph: &TgNodeMap) -> (Option<String>, Rc<TgNode>) {
        let mut node = TgNode {
            idx: idx,
            preds: vec![],
            sink_reasons: vec![],
            taint: Taint::Green
        };

        // connect to predecessors + find some sink_reasons
        let var = node.analyze_taint_flow(tnt_flow, graph);
        
        // calculate the taint
        node.calc_taint(cmd_part);

        node.calc_sink(loc_part, cmd_part);
        
        (var, Rc::new(node))
    }

    /// Analyze the taint flow
    ///
    /// Returns the variable that is defined in this node if any
    fn analyze_taint_flow(&mut self,
                          tnt_flow: &str,
                          graph: &TgNodeMap) -> Option<String> {
        lazy_static! {
            static ref RE_TNT_FLOW: Regex = Regex::new(r"^(.+?) <-?(\*?)- (.+?)$").unwrap();
        }

        let mut var = None;
        
        for pred in tnt_flow.split("; ") {
            if let Some(cap) = RE_TNT_FLOW.captures(pred) {
                if cap.at(2).unwrap().is_empty() {
                    // e.g. t54_1741 <- t42_1773, t29_4179
                    match var {
                        Some(ref s) => assert!(s == cap.at(1).unwrap()),
                        None => var = Some(cap.at(1).unwrap().to_string())
                    }
                    
                    for f in cap.at(3).unwrap().split(", ") {
                        self.preds.push(TgEdge::new(f.to_string(), graph.get(f).map(|n| n.clone())));
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
                    self.preds.push(TgEdge::new(f.to_string(), graph.get(f).map(|n| n.clone())));
                }
            }
        }

        var
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
                    let mut ngp = self.preds.iter().filter(|&&TgEdge{ ref dest, .. }| {
                        dest.as_ref().map_or(true, |p| ! p.is_green())
                    });
                    
                    if ngp.nth(1).is_some() { // at least two blue predecessors
                        self.taint = Taint::Red;
                    }
                } else if cmd.starts_with("Cmp") {
                    // because we are blue at least one pred is blue
                    // if the other one is blue, too, everything is fine and we are green
                    // if the other one is green nothing is fine and we go red
                    let mut blue_preds = self.preds.iter().filter(|&&TgEdge{ ref dest, .. }| {
                        dest.as_ref().map_or(true, |p| p.is_blue())
                    });

                    if blue_preds.nth(1).is_some() { // the other one is blue, too
                        self.taint = Taint::Green
                    } else { // we know that at least one pred is blue because self.is_blue() above
                        self.taint = Taint::Red
                    }
                } else {
                    if let Some(cap) = RE_SUB_CMD.captures(cmd) {
                        let mut ngp = self.preds.iter().filter(|&&TgEdge{ ref dest, .. }| {
                            dest.as_ref().map_or(true, |p| ! p.is_green())
                        });
                        let ngp0 = ngp.next();

                        // TODO this might be optimizable
                        // we allow (blue - green) but not (green - blue) or (blue - blue)
                        if ngp.next().is_some() {
                            // do not allow (blue - blue)
                            self.taint = Taint::Red;
                        } else if let Some(&TgEdge { ref via, .. }) = ngp0 {
                            let subtrahend = cap.at(1).unwrap();
                            if (via == subtrahend) {
                                self.taint = Taint::Red
                            }
                        }
                    } // end if re matches
                }
            }
        } // end if self.is_blue
    }

    #[allow(unused_parens)]
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
                for pred in self.preds.iter().filter_map(|&TgEdge{ref dest, ..}| dest.as_ref()) {
                    self.sink_reasons.push(pred.clone())
                }
            } else {
                if let Some(cap) = RE_IF_CMD.captures(cmd_part).or_else(|| RE_TERNARY_CMD.captures(cmd_part)) {
                    let cond = cap.at(1).unwrap();
                    
                    // we can safely allow blue taint to reach a condition because
                    // it is either 0 (null) in all variants or a valid pointer (-> true)
                    for pred in (self.preds.iter()
                                 .filter(|&&TgEdge{ref via,..}| via == cond)
                                 .filter_map(|&TgEdge{ref dest,..}| dest.as_ref())
                                 .filter(|p| p.is_red())) {
                        self.sink_reasons.push(pred.clone())
                    }
                }
            }
        }
    }

    fn inherit_taint(&mut self) {
        self.taint = if self.is_source() { Taint::Blue } else { Taint::Green };

        for pred in self.preds.iter().filter_map(|&TgEdge{ref dest,..}| dest.as_ref()) {
            if pred.is_red() {
                self.taint = Taint::Red;
                break // once we are red we cannot go back anyway
            } else if pred.is_blue() {
                self.taint = Taint::Blue
            }
        }
    }

    /// A TgNode is a source of taint if it does not have any predecessors
    /// or sink reasons different from None
    pub fn is_source(&self) -> bool {
        // sink reasons are not Options, so there must not be any sink_reasons
        self.sink_reasons.is_empty() && self.preds.iter().all(|p| p.dest.is_none())
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

    pub fn print(&self, meta: &TgMetaNode, colored: bool) {
        let tnt_str = self.taint.abbrv();
        if colored {
            let clr: Colour = self.taint.color();
            let meta_str = meta.to_string();
            if self.is_sink() {
                println!("{} {}", tnt_str, clr.bold().paint(meta_str.as_str()));
            } else {
                println!("{} {}", tnt_str, clr.paint(meta_str.as_str()));
            }
        } else {
            println!("{} {}", tnt_str, meta);
        }
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
