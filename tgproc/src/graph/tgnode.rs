extern crate regex;

use std::collections::HashMap;
use std::rc::Rc;
use self::regex::Regex;

#[derive(PartialEq)]
pub enum Taint {
    Red,
    Blue,
    Green
}

/**
 * As there might be very many tg nodes floating around it is very important
 * to keep the memory footprint minimal w/o loosing information. Because of that
 * a TgNode only contains the absolutely necessary information needed for the
 * graph search. For convenience one a TgNode is usually wrapped in a TgMetaNode
 * that stores additional information about the node.
 * If performance is necessary this construct allows us to easily loose all
 * irrelevant information to keep the memory footprint small.
 */
pub struct TgNode {
    pub idx: usize, // the index of the line in the taintgrind log
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

impl TgNode {
    pub fn new(tnt_flow: &str,
               idx: usize,
               graph: &HashMap<String, Rc<TgNode>>) -> (Option<String>, Rc<TgNode>) {
        let mut node = TgNode { idx: idx, preds: vec![], sink_reasons: vec![], taint: Taint::Green };

        let mut var: Option<String> = None;

        lazy_static! {
            static ref RE_TNT_FLOW: Regex = Regex::new(r"^(.+?) <-?(\*?)- (.+?)$").unwrap();
        }
        
        for pred in tnt_flow.split("; ") {
            match RE_TNT_FLOW.captures(pred) {
                Some(cap) =>
                    if cap.at(2).unwrap().is_empty() {
                        // e.g. t54_1741 <- t42_1773, t29_4179
                        {
                            // set variable
                            let vvv = &mut var;
                            match *vvv {
                                Some(ref s) => assert!(s == cap.at(1).unwrap()),
                                None => *vvv = Some(cap.at(1).unwrap().to_string())
                            }
                        }

                        for f in cap.at(3).unwrap().split(", ") {
                            node.preds.push(graph.get(f).map(|n| n.clone()));
                        }
                    } else {
                        // e.g. t78_744 <*- t72_268 (for dereferencing)
                        // or t78_744 <-*- t72_268 (for storing)
                        // we MUST not dereference or store a red value,
                        // however this does not count as taintflow
                        for f in cap.at(3).unwrap().split(", ") {
                            match graph.get(f) {
                                Some(n) =>
                                    if n.is_red() {
                                        node.sink_reasons.push(n.clone());
                                    },
                                None => {}
                            }
                        }
                    },
                None => // e.g. t54_1741
                    for f in pred.split(", ") {
                        node.preds.push(graph.get(f).map(|n| n.clone()));
                    }
            }
        }

        // inherit taint
        
        
        (var, Rc::new(node))
    }

    pub fn is_sink(&self) -> bool {
        true
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

