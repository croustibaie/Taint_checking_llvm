extern crate regex;

mod simple;

use self::regex::Regex;

use super::tgnode::TgNode;

pub struct TgMetaNode {
    pub line: String,
        
    pub addr: String,
    pub file: String,
    pub lineno: Option<usize>,
    
    pub func: String
}

pub trait TgMetaDb {
    fn new() -> Self;
    
    fn insert_node(&mut self, node: &TgNode, line : String, loc_part: &str) {
        self.insert(node.idx, line, loc_part)
    }
    
    fn insert(&mut self, idx: usize, line : String, loc_part: &str) {
        lazy_static! {
            // e.g. 0x40080D: main (two-taints.c:10)
            static ref RE_LOC1: Regex = Regex::new(r"(0x\w+): (.+?) \((.+):(\d+)\)").unwrap();

            // e.g. 0x40080D: main (in /tmp/a.out)
            static ref RE_LOC2: Regex = Regex::new(r"(0x\w+): (.+?) \(in (.+)\)").unwrap();
        }

        let tgmeta = if let Some(cap) = RE_LOC1.captures(loc_part) {
            TgMetaNode {
                line: line,
                addr: cap.at(1).unwrap().to_string(),
                file: cap.at(2).unwrap().to_string(),
                func: cap.at(3).unwrap().to_string(),
                lineno: Some(cap.at(4).unwrap().parse::<usize>().unwrap())
            }
        } else if let Some(cap) = RE_LOC2.captures(loc_part) {
            TgMetaNode {
                line: line,
                addr: cap.at(1).unwrap().to_string(),
                file: cap.at(2).unwrap().to_string(),
                func: cap.at(3).unwrap().to_string(),
                lineno: None
            }
        } else {
            panic!("Could not parse loc part: {}", loc_part);
        };

        self.insert_meta(idx, tgmeta);
    }

    fn insert_meta(&mut self, idx: usize, meta: TgMetaNode);
    
    fn get(&self, idx: usize) -> Option<&TgMetaNode>;
    fn get_node(&self, node: &TgNode) -> Option<&TgMetaNode> {
        self.get(node.idx)
    }
}

pub type SimpleMetaDB = simple::MetaDB;
