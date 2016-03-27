use std::collections::HashMap;
use std::rc::Rc;

pub struct TgNode {
    pub idx: usize,
    pub var: &'static str
}

impl TgNode {
    pub fn new(line: &str, idx: usize, graph: &HashMap<&str, Rc<TgNode>>) -> Rc<TgNode> {
        Rc::new(TgNode { idx: idx, var: "" })
    }

    pub fn is_def(&self) -> bool {
        true
    }

    pub fn is_sink(&self) -> bool {
        true
    }
}

