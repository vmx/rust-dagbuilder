use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::fmt;
use std::fs;
use std::io;

use atomic_counter::{AtomicCounter, RelaxedCounter};
use clap::{App, Arg};
use lazy_static::lazy_static;
use libipld::cbor::DagCborCodec;
use libipld::ipld::Ipld;
use libipld::json::DagJsonCodec;
use libipld_core::cid::{CidGeneric, Codec as CidCodec};
use libipld_core::codec::Codec;
use libipld_core::multibase::Base;
use libipld_core::multihash::{Code, MultihashDigest};
use regex::Regex;
use serde_json::Value as JsonValue;
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

#[derive(Error, Debug)]
pub enum BlockError {
    #[error("Cannot decode block.")]
    DecodeError,
    #[error("Cannot encode block.")]
    EncodeError,
    #[error("Cannot find codec implementation.")]
    CodecNotFound,
    #[error("Cannot find hash algorithm implementation.")]
    HashAlgNotFound,
}

#[derive(Debug, Clone)]
struct MyNode {
    hello: String,
    is: bool,
}

impl From<MyNode> for Ipld {
    fn from(my_node: MyNode) -> Self {
        let mut map = BTreeMap::new();
        map.insert("hello".to_string(), Ipld::String(my_node.hello));
        map.insert("is".to_string(), Ipld::Bool(my_node.is));
        Ipld::Map(map)
    }
}

pub type Block = BlockGeneric<IpldCodec, Code>;

/// A `Block` is an IPLD object together with a CID. The data can be encoded and decoded.
///
/// All operations are cached. This means that encoding, decoding and CID calculation happens
/// at most once. All subsequent calls will use a cached version.
pub struct BlockGeneric<C, H>
where
    C: Copy + TryFrom<u64> + Into<u64>,
    H: Copy + TryFrom<u64> + Into<u64>,
    <C as TryFrom<u64>>::Error: fmt::Debug,
    <H as TryFrom<u64>>::Error: fmt::Debug,
{
    cid: Option<CidGeneric<C, H>>,
    raw: Option<Vec<u8>>,
    node: Option<Ipld>,
    codec: C,
    hash_alg: H,
}

impl<C, H> BlockGeneric<C, H>
where
    C: Copy + TryFrom<u64> + Into<u64> + fmt::Debug,
    H: Copy + TryFrom<u64> + Into<u64>,
    Box<dyn Codec>: From<C>,
    Box<dyn MultihashDigest<H>>: From<H>,
    <C as TryFrom<u64>>::Error: fmt::Debug,
    <H as TryFrom<u64>>::Error: fmt::Debug,
{
    /// Create a new `Block` from the given CID and raw binary data.
    ///
    /// It needs a registry that contains codec and hash algorithms implementations in order to
    /// be able to decode the data into IPLD.
    pub fn new(cid: CidGeneric<C, H>, raw: Vec<u8>) -> Result<Self, BlockError>
    where
        <C as TryFrom<u64>>::Error: fmt::Debug,
        <H as TryFrom<u64>>::Error: fmt::Debug,
    {
        let codec = cid.codec();
        let hash_alg = cid.hash().algorithm();
        Ok(Self {
            cid: Some(cid),
            raw: Some(raw),
            node: None,
            codec,
            hash_alg,
        })
    }

    /// Create a new `Block` from the given IPLD object, codec and hash algorithm.
    ///
    /// No computation is done, the CID creation and the encoding will only be performed when the
    /// corresponding methods are called.
    pub fn encoder(node: Ipld, codec: C, hash_alg: H) -> Self {
        Self {
            cid: None,
            raw: None,
            node: Some(node),
            codec,
            hash_alg,
        }
    }

    /// Create a new `Block` from encoded data, codec and hash algorithm.
    ///
    /// No computation is done, the CID creation and the decoding will only be performed when the
    /// corresponding methods are called.
    pub fn decoder(raw: Vec<u8>, codec: C, hash_alg: H) -> Self {
        Self {
            cid: None,
            raw: Some(raw),
            node: None,
            codec,
            hash_alg,
        }
    }

    /// Decode the `Block` into an IPLD object.
    ///
    /// The actual decoding is only performed if the object doesn't have a copy of the IPLD
    /// object yet. If that method was called before, it returns the cached result.
    pub fn decode(&mut self) -> Result<Ipld, BlockError> {
        if let Some(node) = &self.node {
            Ok(node.clone())
        } else if let Some(raw) = &self.raw {
            let decoded = Box::<dyn Codec>::from(self.codec).decode(&raw).unwrap();
            self.node = Some(decoded.clone());
            Ok(decoded)
        } else {
            Err(BlockError::DecodeError)
        }
    }

    /// Encode the `Block` into raw binary data.
    ///
    /// The actual encoding is only performed if the object doesn't have a copy of the encoded
    /// raw binary data yet. If that method was called before, it returns the cached result.
    pub fn encode(&mut self) -> Result<Vec<u8>, BlockError> {
        if let Some(raw) = &self.raw {
            Ok(raw.clone())
        } else if let Some(node) = &self.node {
            let encoded = Box::<dyn Codec>::from(self.codec)
                .encode(&node)
                .unwrap()
                .to_vec();
            self.raw = Some(encoded.clone());
            Ok(encoded)
        } else {
            Err(BlockError::EncodeError)
        }
    }

    /// Calculate the CID of the `Block`.
    ///
    /// The CID is calculated from the encoded data. If it wasn't encoded before, that
    /// operation will be performed. If the encoded data is already available, from a previous
    /// call of `encode()` or because the `Block` was instantiated via `encoder()`, then it
    /// isn't re-encoded.
    pub fn cid(&mut self) -> Result<CidGeneric<C, H>, BlockError>
    where
        <C as TryFrom<u64>>::Error: fmt::Debug,
        <H as TryFrom<u64>>::Error: fmt::Debug,
    {
        if let Some(cid) = &self.cid {
            Ok(cid.clone())
        } else {
            // TODO vmx 2020-01-31: should probably be `encodeUnsafe()`
            let hash = Box::<dyn MultihashDigest<H>>::from(self.hash_alg).digest(&self.encode()?);
            let cid = CidGeneric::new_v1(self.codec, hash);
            Ok(cid)
        }
    }
}

impl<C, H> fmt::Debug for BlockGeneric<C, H>
where
    C: Copy + TryFrom<u64> + Into<u64> + fmt::Debug,
    H: Copy + TryFrom<u64> + Into<u64> + fmt::Debug,
    H: Into<Box<dyn MultihashDigest<H>>>,
    <C as TryFrom<u64>>::Error: fmt::Debug,
    <H as TryFrom<u64>>::Error: fmt::Debug,
{
    fn fmt(&self, ff: &mut fmt::Formatter) -> fmt::Result {
        write!(ff, "Block {{ cid: {:?}, raw: {:?} }}", self.cid, self.raw)
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
struct RawData {
    data: String,
    meta: String,
}

#[derive(Debug)]
struct TreeItem {
    // The depth of the item within the tree
    depth: u64,
    // The actual data that be store
    data: Ipld,
    // Meta information on how to encode/hash the data
    meta: Meta,
    // The raw, unparsed data and meta data
    raw: RawData,
}

#[derive(Debug, Eq, PartialEq)]
enum MetaType {
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
struct Meta {
    type_: MetaType,
    id: String,
    linkname: Option<String>,
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
fn flatten_dag(contents: &str) -> Result<Vec<TreeItem>, DagbuilderError> {
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

/// Make links actually proper links. Replace IDs with their CIDs once they are serialized
fn replace_ids_with_cids(json: &mut JsonValue, id_to_cid: &BTreeMap<String, String>) {
    for (key, mut value) in json.as_object_mut().unwrap().iter_mut() {
        if key == "/" {
            match id_to_cid.get(value.as_str().unwrap()) {
                Some(cid) => {
                    *value = JsonValue::from(cid.clone());
                }
                None => panic!("Cannot resolve link with id {}", value),
            }
        } else if value.is_array() {
            for mut item in value.as_array_mut().unwrap().iter_mut() {
                replace_ids_with_cids(&mut item, id_to_cid)
            }
        } else if value.is_object() {
            replace_ids_with_cids(&mut value, id_to_cid)
        }
    }
}

/// Get the CID of the node ata and store it
fn create_block(
    meta: Meta,
    data: &[u8],
    _include_id: bool,
    id_to_cid: &mut BTreeMap<String, String>,
) -> Block {
    let hash_alg = Code::Sha2_256;
    let mut block = match meta.type_ {
        MetaType::JSON => {
            // DagJSON cannot be used here to parse the data as it doesn't contain CIDs as link
            // value, but IDs which will be resolved to CIDs in a later step.
            let mut json = serde_json::from_slice(data).unwrap();
            // After this call, the JSON will be proper DagJSON
            replace_ids_with_cids(&mut json, id_to_cid);
            let dag_json = serde_json::to_vec(&json).unwrap();

            let node = Block::decoder(dag_json, IpldCodec::DagJson, hash_alg)
                .decode()
                .unwrap();
            Block::encoder(node, IpldCodec::DagCbor, hash_alg)
        }
        MetaType::HEX => {
            let bytes = hex::decode(data).unwrap();
            Block::decoder(bytes, IpldCodec::Raw, hash_alg)
        }
        MetaType::UTF8 => {
            // Store the UTF-8 string bytes as they are
            Block::decoder(data.to_vec(), IpldCodec::Raw, hash_alg)
        }
    };
    let cid = block
        .cid()
        .unwrap()
        .to_string_of_base(Base::Base64)
        .unwrap();
    if id_to_cid.insert(meta.id.clone(), cid).is_some() {
        panic!(r#"IDs must be unique "{:?}" was not."#, meta.id)
    }
    block
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = App::new("dagbuilder")
        .version("0.1")
        .about("Load a DAG described in a file into IPLD")
        .arg(
            Arg::with_name("include-id")
                .short("i")
                .long("include-id")
                .help("Add the id speficied in the DAG file to the node (if the node is JSON)"),
        )
        .arg(Arg::with_name("FILE").help("input file").required(true))
        .get_matches();

    let filename = matches.value_of("FILE").unwrap();
    let include_id = matches.is_present("include-id");

    let contents = String::from_utf8(fs::read(filename).unwrap()).unwrap();

    // Mapping between IDs and their CIDs onces serialized
    let mut id_to_cid: BTreeMap<String, String> = BTreeMap::new();

    let flattened = flatten_dag(&contents).unwrap();
    for item in flattened {
        let mut block = create_block(
            item.meta,
            item.raw.data.as_bytes(),
            include_id,
            &mut id_to_cid,
        );
        println!(
            "{}",
            block
                .cid()
                .unwrap()
                .to_string_of_base(Base::Base32Lower)
                .unwrap()
        );
    }

    Ok(())
}
