use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::io;

use atomic_counter::{AtomicCounter, RelaxedCounter};
use lazy_static::lazy_static;
use libipld::cbor::DagCborCodec;
use libipld::ipld::Ipld;
use libipld::json::DagJsonCodec;
use libipld_core::cid::{CidGeneric, Codec as CidCodec};
use libipld_core::codec::Codec;
use libipld_core::multihash::{Code, MultihashDigest};
use regex::Regex;
use thiserror::Error;

type Cid = CidGeneric<CidCodec, Code>;

lazy_static! {
    static ref ID_COUNTER: RelaxedCounter = RelaxedCounter::new(0);
}

fn generate_id() -> String {
    format!("dagbuilder-generated-id-{}", ID_COUNTER.inc())
}

#[derive(Clone, Copy, Debug)]
pub enum IpldCodec {
    Raw = 0x55,
    DagCbor = 0x71,
    DagJson = 0x0129,
}

impl From<IpldCodec> for u64 {
    /// Return the codec as integer value.
    fn from(codec: IpldCodec) -> Self {
        codec as _
    }
}

impl TryFrom<u64> for IpldCodec {
    type Error = String;

    /// Return the `IpldCodec` based on the integer value. Error if no matching code exists.
    fn try_from(raw: u64) -> Result<Self, Self::Error> {
        match raw {
            0x55 => Ok(IpldCodec::Raw),
            0x71 => Ok(IpldCodec::DagCbor),
            0x0129 => Ok(IpldCodec::DagJson),
            _ => Err("Cannot convert code to codec.".to_string()),
        }
    }
}

impl From<IpldCodec> for Box<dyn Codec> {
    fn from(codec: IpldCodec) -> Self {
        match codec {
            IpldCodec::Raw => panic!("TODO vmx 2020-04-24: Implement Raw Codec"),
            IpldCodec::DagCbor => Box::new(DagCborCodec),
            IpldCodec::DagJson => Box::new(DagJsonCodec),
        }
    }
}

// The number of spaces used to indent the children
const INDENTATION: u8 = 2;

#[derive(Error, Debug)]
pub enum DagbuilderError {
    #[error("cannot open file")]
    FileError(#[from] io::Error),
}

#[derive(Debug)]
pub struct RawData {
    pub data: String,
    pub meta: String,
}

#[derive(Debug)]
pub struct TreeItem {
    // The depth of the item within the tree
    pub depth: u64,
    // The actual data that be store
    pub data: Ipld,
    // Meta information on how to encode/hash the data
    pub meta: Meta,
    // The raw, unparsed data and meta data
    pub raw: RawData,
}

#[derive(Debug, Eq, PartialEq)]
pub enum MetaType {
    HEX,
    JSON,
    UTF8,
}

impl TryFrom<&str> for MetaType {
    type Error = String;

    fn try_from(meta_type: &str) -> Result<Self, Self::Error> {
        match meta_type {
            "hex" => Ok(Self::HEX),
            "json" => Ok(Self::JSON),
            "utf8" => Ok(Self::UTF8),
            _ => Err(format!("Unknown meta type `{}`", meta_type)),
        }
    }
}

#[derive(Debug)]
pub struct Meta {
    pub type_: MetaType,
    pub id: String,
    pub linkname: Option<String>,
}

/// The string needs to be formatted as:
/// [key1:value1,key2:value2,...]
impl TryFrom<&str> for Meta {
    type Error = String;

    fn try_from(meta_raw: &str) -> Result<Self, Self::Error> {
        // Remove leading and trailing brackets, split it into the individual key-value pairs and
        // put it into a hashmap.
        let meta = meta_raw[1..meta_raw.len() - 1].split(',').fold(
            BTreeMap::new(),
            |mut acc, key_value| {
                let splitted: Vec<&str> = key_value.splitn(2, ':').collect();
                let (key, value) = (splitted[0].trim(), splitted[1].trim());
                acc.insert(key, value);
                acc
            },
        );

        let type_ = MetaType::try_from(*meta.get("type").ok_or("Missing `type`.")?)?;
        // If no ID is given, generate one
        let id = meta.get("id").map_or_else(generate_id, ToString::to_string);
        let linkname = meta.get("linkname").map(ToString::to_string);
        Ok(Meta {
            type_,
            id,
            linkname,
        })
    }
}

/// Gets a node off the tree and resolves links.
/// It returns the processed node
fn pop_and_link(tree: &mut Vec<TreeItem>) -> Result<TreeItem, String> {
    let node = tree.pop().unwrap();

    // The current last item is the parent of this node. Add a link
    let parent = tree.last_mut().unwrap();

    // Links can only be added to JSON encoded nodes
    if parent.meta.type_ != MetaType::JSON {
        return Err("Only `type:json` nodes may have children".to_string());
    }

    // Add the link with the `linkname` to the `id` of the object. That `id` will
    // later be replaced with its hash. If ther's no `linkname` given, use the
    // `id`.
    let linkname: &str = match node.meta.linkname {
        Some(ref ln) => ln,
        None => &node.meta.id,
    };
    //let link = CidOrId::Id(node.meta.id.clone());
    let hasher = Box::<dyn MultihashDigest<_>>::from(Code::Identity);
    let multihash = hasher.digest(node.meta.id.as_bytes());
    // TODO vmx 2020-05-05: Make it work with `IpldCodec` instead of `CidCodec`
    let link = Cid::new_v1(CidCodec::DagCBOR, multihash);
    // TODO vmx 2020-04-09: Support linknames that contain paths
    //create_object_from_link_name(linkname, link);

    match &mut (*parent).data {
        Ipld::Map(ref mut map) => map.insert(linkname.to_string(), Ipld::Link(link)),
        _ => return Err("`data` needs to be an IPLD map".to_string()),
    };

    Ok(node)
}

/// Returns parsed items
///
/// A DAGs, sinks (children) need to be processed first. Hence this call may buffer up several
/// items. This means that it sometimes return no items and sometimes several
fn process_line(line: &str, tree: &mut Vec<TreeItem>) -> Result<Option<Vec<TreeItem>>, String> {
    // The depth of the previously processed line
    let prev_depth = if tree.is_empty() {
        None
    } else {
        Some(tree[tree.len() - 1].depth)
    };
    // Split between indentation and the rest
    let re = Regex::new(r"^( *)(.+)").unwrap();
    let captures = re.captures(line).unwrap();
    let depth = captures[1].len() as u64 / INDENTATION as u64;
    // TODO vmx 2020-04-07: do more robust parsing
    let splitted: Vec<&str> = captures[2].splitn(2, ' ').collect();
    let (meta_raw, data_raw) = (splitted[0].to_string(), splitted[1].to_string());

    // TODO vmx 2020-04-08: Make this a proper error
    let meta = Meta::try_from(&meta_raw[..]).unwrap();

    let data = match meta.type_ {
        MetaType::HEX => Ipld::Bytes(hex::decode(&data_raw[..]).unwrap()),
        MetaType::JSON => DagJsonCodec::decode(&data_raw[..].as_bytes()).unwrap(),
        MetaType::UTF8 => Ipld::String(data_raw.clone()),
    };

    let mut result = Vec::new();
    // Write and add links independent of whether it's a sibling or a child
    if let Some(prev_depth_value) = prev_depth {
        if prev_depth_value > depth {
            for _ in 0..(prev_depth_value - depth) {
                let node = pop_and_link(tree)?;
                result.push(node)
            }
        }
    }

    tree.push(TreeItem {
        depth,
        data,
        meta,
        raw: RawData {
            data: data_raw,
            meta: meta_raw,
        },
    });

    Ok(Some(result))
}

/// Returns a flat array of parsed nodes wich have their links added
///
/// Takes as input a string containing a DAG described in a custom format
pub fn flatten_dag(contents: &str) -> Result<Vec<TreeItem>, DagbuilderError> {
    let mut tree = Vec::new();

    // The final list of nodes with links resolved
    let mut result = Vec::new();

    for line in contents.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(nodes) = process_line(line, &mut tree).unwrap() {
            result.extend(nodes)
        }
    }

    // There might be still some data in the tree, flush it back to front
    while tree.len() > 1 {
        let node = pop_and_link(&mut tree).unwrap();
        result.push(node)
    }

    // And finally add the root node
    let root = tree.pop().unwrap();
    result.push(root);

    Ok(result)
}
