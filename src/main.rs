use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::fmt;

use thiserror::Error;

//use clap::{App, Arg};
use libipld::cbor::DagCborCodec;
use libipld::ipld::Ipld;
use libipld_base::cid::CidGeneric;
use libipld_base::codec::Codec;
use libipld_base::multihash::{Code, MultihashDigest};

#[derive(Clone, Copy, Debug)]
enum IpldCodec {
    DagCbor = 0x71,
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
            0x71 => Ok(IpldCodec::DagCbor),
            _ => Err("Cannot convert code to codec.".to_string()),
        }
    }
}

impl From<IpldCodec> for Box<dyn Codec> {
    fn from(codec: IpldCodec) -> Self {
        match codec {
            IpldCodec::DagCbor => Box::new(DagCborCodec),
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

type Block = BlockGeneric<IpldCodec, Code>;

/// A `Block` is an IPLD object together with a CID. The data can be encoded and decoded.
///
/// All operations are cached. This means that encoding, decoding and CID calculation happens
/// at most once. All subsequent calls will use a cached version.
pub struct BlockGeneric<C, H>
where
    C: Copy + TryFrom<u64> + Into<u64>,
    H: Copy + TryFrom<u64> + Into<u64>,
{
    cid: Option<CidGeneric<C, H>>,
    raw: Option<Vec<u8>>,
    node: Option<Ipld>,
    codec: C,
    hash_alg: H,
}

impl<C, H> BlockGeneric<C, H>
where
    C: Copy + TryFrom<u64> + Into<u64>,
    H: Copy + TryFrom<u64> + Into<u64>,
    Box<dyn Codec>: From<C>,
    Box<dyn MultihashDigest<H>>: From<H>,
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
{
    fn fmt(&self, ff: &mut fmt::Formatter) -> fmt::Result {
        write!(ff, "Block {{ cid: {:?}, raw: {:?} }}", self.cid, self.raw)
    }
}

fn cid_node(node: MyNode) {
    println!("cidnode: node: {:?}", node);

    let mut block_from_encoder =
        Block::encoder(Ipld::from(node), IpldCodec::DagCbor, Code::Sha2_256);
    println!("block from encoder: {:02x?}", block_from_encoder);

    let mut block_from_decoder = Block::decoder(
        block_from_encoder.encode().unwrap(),
        IpldCodec::DagCbor,
        Code::Sha2_256,
    );
    println!("block from decoder: {:02x?}", block_from_decoder);

    let mut block_from_new = Block::new(
        block_from_decoder.cid().unwrap(),
        block_from_decoder.encode().unwrap(),
    )
    .unwrap();
    println!("block from new: {:02x?}", block_from_new);

    let decoded = block_from_new.decode();
    println!("decoded: {:?}", decoded);
}

fn main() {
    //let matches = App::new("dagbuilder")
    //    .version("0.1")
    //    .about("Load a DAG described in a file into IPLD")
    //    .arg(
    //        Arg::with_name("include-id")
    //            .short("i")
    //            .long("include-id")
    //            .help("Add the id speficied in the DAG file to the node (if the node is JSON)"),
    //    )
    //    .arg(Arg::with_name("FILE").help("input file").required(true))
    //    .get_matches();
    //
    //let file = matches.value_of("FILE").unwrap();
    //println!("input file: {}", file);
    //let include_id = matches.is_present("include-id");
    //println!("include id: {:?}", include_id);

    let my_node = MyNode {
        hello: "world!".to_string(),
        is: true,
    };

    cid_node(my_node);
}
