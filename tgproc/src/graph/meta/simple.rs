use std::collections::HashMap;

use super::TgMetaDb;
use super::TgMetaNode;

pub struct MetaDB(HashMap<usize, TgMetaNode>);

impl TgMetaDb for MetaDB {
    fn new() -> MetaDB {
        MetaDB(HashMap::new())
    }
    
    fn insert_meta(&mut self, idx: usize, meta: TgMetaNode) {
        let MetaDB(ref mut map) = *self;
        map.insert(idx, meta);
    }
    
    fn get(&self, idx: usize) -> Option<&TgMetaNode> {
        let MetaDB(ref map) = *self;
        map.get(&idx)
    }
}
