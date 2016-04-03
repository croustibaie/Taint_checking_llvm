extern crate regex;
extern crate walkdir;

mod simple;

use std::u64;
use std::result::Result;
use std::num::ParseIntError;
use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;
use std::env;
use std::io::BufReader;
use std::io::BufRead;
use std::fs::File;
use std::process::Command;
use std::fmt;
use std::fmt::Display;
use std::fmt::Formatter;
use self::regex::Regex;
use self::walkdir::WalkDir;
use self::walkdir::WalkDirIterator;

use super::tgnode::TgNode;

pub struct DebugInfoDb(HashMap<String, HashMap<u64, (String, usize)>>);

impl DebugInfoDb {
    pub fn new() -> DebugInfoDb {
        DebugInfoDb(HashMap::new())
    }
    
    fn addr2srcloc(&mut self, binary: &str, addr: u64) -> &(String, usize) {
        let DebugInfoDb(ref mut bin_map) = *self;
        
        if ! bin_map.contains_key(binary) {
            bin_map.insert(binary.to_string(), HashMap::new());
        }

        let mut addr_map = bin_map.get_mut(binary).unwrap();

        if ! addr_map.contains_key(&addr) {
            let output = Command::new("addr2line")
                .arg("-e")
                .arg(binary)
                .arg(format!("0x{:x}", addr))
                .output()
                .unwrap_or_else(|e| { panic!("failed to execute process: {}", e) });

            let output_str = String::from_utf8(output.stdout).unwrap();
            let mut out_split = output_str.split(":");
            let file = out_split.next().unwrap().to_string();
            let lineno = out_split.next().unwrap().trim().parse::<usize>().unwrap();
            addr_map.insert(addr, (file, lineno));
        }

        addr_map.get(&addr).unwrap()
    }
}

pub struct SrcLoc {
    addr: u64,
    pub file: String,
    pub lineno: Option<usize>,
    pub src_line: Option<String>
}

impl SrcLoc {
    pub fn new_u64(addr: u64, file: String, lineno: Option<usize>) -> SrcLoc {
        SrcLoc {
            addr: addr,
            file: file,
            lineno: lineno,
            src_line: None
        }
    }

    pub fn new(addr: &str, file: String, lineno: Option<usize>) -> Result<SrcLoc, ParseIntError> {
        u64::from_str_radix(&addr[2..], 16).map(|a| SrcLoc::new_u64(a, file, lineno))
    }

    pub fn complete_info(&mut self, debug_db: &mut DebugInfoDb) {
        if self.lineno.is_none() {
            let (ref file, lineno) = *debug_db.addr2srcloc(&self.file, self.addr);
            self.file = file.clone();
            self.lineno = Some(lineno);
        }

        let mut src_line = None;
        let mut file = None;

        {
            let filepath = Path::new(&self.file);
            if ! filepath.exists() {
                let basename = filepath.file_name().unwrap();
                
                let walker = WalkDir::new(".").into_iter().filter_entry(|entry| {
                    entry.path().to_str().map(|s| s.ends_with(&self.file)).unwrap_or(false) &&
                    entry.file_name() == basename
                });
                
                for entry in walker.filter_map(|e| e.ok()) {
                    if let Some(line) = self.load_src_line_from(entry.path()) {
                        src_line = Some(line);
                        file = Some(entry.path().to_str().unwrap().to_string());
                        break;
                    }
                }
            } else {
                src_line = self.load_src_line_from(filepath);
            }
        }

        if src_line.is_some() {
            self.src_line = src_line;
        }
        if let Some(f) = file {
            self.file = f;
        }
    }

    fn load_src_line_from(&self, path: &Path) -> Option<String> {
        if let Some(lineno) = self.lineno {
            if let Ok(f) = File::open(path) {
                let reader = BufReader::new(&f);
                if let Some(Ok(line)) = reader.lines().nth(lineno-1) {
                    return Some(line.trim().to_string())
                }
            }
        }
        None
    }
}

pub struct TgMetaNode {
    pub line: String,
    pub loc: SrcLoc,
    pub func: String
}

impl Display for TgMetaNode {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let line = if let Some(ref l) = self.loc.src_line { l.as_str() } else { "[file not found]" };

        let path = Path::new(&self.loc.file);
        let mut relpath = path.to_path_buf();
        
        if path.is_absolute() {
            // create a path relative to the current directory
            if let Ok(mut basepath) = env::current_dir() {
                relpath = PathBuf::new();

                while !path.starts_with(&basepath) {
                    relpath.push("..");
                    if !basepath.pop() {
                        // ok we somehow did not manage, let's break that off
                        relpath = PathBuf::new();
                        break;
                    }
                }

                if let Ok(suffix) = path.strip_prefix(&basepath) {
                    relpath.push(suffix);
                } else {
                    relpath = path.to_path_buf();
                }
            }
        }

        write!(f, "{:>29}:{:04}: {:>20}:  {}", relpath.display(), self.loc.lineno.unwrap(), self.func, line)
    }
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
                loc: SrcLoc::new(cap.at(1).unwrap(),
                                 cap.at(3).unwrap().to_string(),
                                 Some(cap.at(4).unwrap().parse::<usize>().unwrap())).unwrap(),
                func: cap.at(2).unwrap().to_string(),
                
            }
        } else if let Some(cap) = RE_LOC2.captures(loc_part) {
            TgMetaNode {
                line: line,
                loc: SrcLoc::new(cap.at(1).unwrap(),
                                 cap.at(3).unwrap().to_string(),
                                 None).unwrap(),
                func: cap.at(2).unwrap().to_string(),
            }
        } else {
            panic!("Could not parse loc part: {}", loc_part);
        };

        self.insert_meta(idx, tgmeta);
    }

    fn insert_meta(&mut self, idx: usize, meta: TgMetaNode);
    
    fn get_mut_by_idx(&mut self, idx: usize) -> Option<&mut TgMetaNode>;
    fn get_mut(&mut self, node: &TgNode) -> Option<&mut TgMetaNode> {
        self.get_mut_by_idx(node.idx)
    }
}

pub type SimpleMetaDB = simple::MetaDB;
