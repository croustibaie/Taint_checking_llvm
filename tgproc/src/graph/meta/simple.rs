use std::collections::HashMap;

use super::TgMetaDb;
use super::TgMetaNode;

pub struct MetaDB(HashMap<usize, TgMetaNode>);

impl TgMetaDb for MetaDB {
    fn new() -> MetaDB {
        MetaDB(HashMap::new())
    }
    
    fn insert(&mut self, idx: usize, meta: TgMetaNode) {
        let MetaDB(ref mut map) = *self;
        map.insert(idx, meta);
    }
    
    fn get_mut_by_idx(&mut self, idx: usize) -> Option<&mut TgMetaNode> {
        let MetaDB(ref mut map) = *self;
        map.get_mut(&idx)
    }

    fn get_by_idx(&self, idx: usize) -> Option<&TgMetaNode> {
        let MetaDB(ref map) = *self;
        map.get(&idx)
    }
}
