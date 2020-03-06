use std::collections::BTreeMap;
use std::fmt;

use thiserror::Error;

//use clap::{App, Arg};
use libipld::cbor::{CborError, DagCborCodec};
use libipld::ipld::Ipld;
use libipld::Cid;
use libipld_base::cid;
use libipld_base::codec::Codec;
use libipld_base::multihash::{self, MultihashDigest, Sha2_256};

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

/// A registry for IPLD Codecs.
pub trait Registry {
    /// Get a codec implementation by Multicodec
    fn get_codec<'a>(multicodec: cid::Codec) -> Option<&'a dyn Codec<Error = CborError>>;
    /// Get a hash algorithm implementation by Multicodec
    fn get_hash_alg<'a>(multicodec: multihash::Code) -> Option<&'a dyn MultihashDigest>;
}

struct DefaultRegistry {}
impl Registry for DefaultRegistry {
    //fn get_codec(multicodec: cid::Codec) -> Option<Box<dyn Codec<Error=CborError>>> {
    fn get_codec<'a>(multicodec: cid::Codec) -> Option<&'a dyn Codec<Error = CborError>> {
        match multicodec {
            cid::Codec::DagCBOR => Some(&DagCborCodec),
            _ => {
                println!("codec not supported");
                None
            }
        }
    }
    fn get_hash_alg<'a>(multicodec: multihash::Code) -> Option<&'a dyn MultihashDigest> {
        //match multicodec {
        //    multihash::Hash::SHA2256 => Some(&Sha2_256),
        //    _ => {
        //        println!("hash not supported");
        //        None
        //    }
        //}
        Some(&Sha2_256)
    }
}

/// A `Block` is an IPLD object together with a CID. The data can be encoded and decoded.
///
/// All operations are cached. This means that encoding, decoding and CID calculation happens
/// at most once. All subsequent calls will use a cached version.
pub struct Block<'a> {
    cid: Option<Cid>,
    raw: Option<Vec<u8>>,
    node: Option<Ipld>,
    codec: &'a dyn Codec<Error = CborError>,
    hash_alg: &'a dyn MultihashDigest,
}

impl<'a> Block<'a> {
    /// Create a new `Block` from the given CID and raw binary data.
    ///
    /// It needs a registry that contains codec and hash algorithms implementations in order to
    /// be able to decode the data into IPLD.
    pub fn new<R>(cid: Cid, raw: Vec<u8>) -> Result<Self, BlockError>
    where
        R: Registry,
    {
        let codec_code = cid.codec();
        let codec = R::get_codec(codec_code).ok_or(BlockError::CodecNotFound)?;

        let hash_alg_code = cid.hash().algorithm();
        let hash_alg = R::get_hash_alg(hash_alg_code).ok_or(BlockError::HashAlgNotFound)?;

        Ok(Block {
            cid: Some(cid),
            raw: Some(raw),
            node: None,
            codec,
            hash_alg: hash_alg,
        })
    }

    /// Create a new `Block` from the given IPLD object, codec and hash algorithm.
    ///
    /// No computation is done, the CID creation and the encoding will only be performed when the
    /// corresponding methods are called.
    pub fn encoder(
        node: Ipld,
        codec: &'a dyn Codec<Error = CborError>,
        hash_alg: &'a dyn MultihashDigest,
    ) -> Self {
        Block {
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
    pub fn decoder(
        raw: Vec<u8>,
        codec: &'a dyn Codec<Error = CborError>,
        hash_alg: &'a dyn MultihashDigest,
    ) -> Self {
        Block {
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
            let decoded = self.codec.decode(&raw).unwrap();
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
            let encoded = self.codec.encode(&node).unwrap().to_vec();
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
    pub fn cid(&mut self) -> Result<Cid, BlockError> {
        if let Some(cid) = &self.cid {
            Ok(cid.clone())
        } else {
            // TODO vmx 2020-01-31: should probably be `encodeUnsafe()`
            let hash = self.hash_alg.digest(&self.encode()?);
            let cid = Cid::new_v1(self.codec.codec(), hash);
            Ok(cid)
        }
    }
}

impl<'a> fmt::Debug for Block<'a> {
    fn fmt(&self, ff: &mut fmt::Formatter) -> fmt::Result {
        write!(ff, "Block {{ cid: {:?}, raw: {:?} }}", self.cid, self.raw)
    }
}

fn cid_node(node: MyNode) {
    println!("cidnode: node: {:?}", node);

    let mut block_from_encoder = Block::encoder(Ipld::from(node), &DagCborCodec, &Sha2_256);
    println!("block from encoder: {:02x?}", block_from_encoder);

    let mut block_from_decoder = Block::decoder(
        block_from_encoder.encode().unwrap(),
        &DagCborCodec,
        &Sha2_256,
    );
    println!("block from decoder: {:02x?}", block_from_decoder);

    let mut block_from_new = Block::new::<DefaultRegistry>(
        block_from_decoder.cid().unwrap(),
        block_from_decoder.encode().unwrap(),
    ).unwrap();
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
