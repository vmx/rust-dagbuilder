use std::collections::BTreeMap;
use std::fmt;

use futures::executor::block_on;

//use clap::{App, Arg};
use libipld::cbor::{CborError, DagCborCodec};
use libipld::hash::{Hash, HashDyn, Sha2_256};
use libipld::ipld::Ipld;
use libipld::Cid;
use libipld_base::codec::{Codec, CodecDyn};
use libipld_base::error::BlockError;

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
    fn get_codec<'a>(multicodec: cid::Codec) -> Option<&'a dyn CodecDyn<Error = CborError>>;
    /// Get a hash algorithm implementation by Multicodec
    fn get_hash_alg<'a>(multicodec: multihash::Hash) -> Option<&'a dyn HashDyn>;
}

struct DefaultRegistry {}
impl Registry for DefaultRegistry {
    //fn get_codec(multicodec: cid::Codec) -> Option<Box<dyn Codec<Error=CborError>>> {
    fn get_codec<'a>(multicodec: cid::Codec) -> Option<&'a dyn CodecDyn<Error = CborError>> {
        match multicodec {
            cid::Codec::DagCBOR => Some(&DagCborCodec),
            _ => {
                println!("codec not supported");
                None
            }
        }
    }
    fn get_hash_alg<'a>(multicodec: multihash::Hash) -> Option<&'a dyn HashDyn> {
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

pub struct Block<'a> {
    cid: Option<Cid>,
    data: Option<Vec<u8>>,
    node: Option<Ipld>,
    codec: &'a dyn CodecDyn<Error = CborError>,
    hash_alg: &'a dyn HashDyn,
}

impl<'a> Block<'a> {
    pub fn new<R>(cid: Cid, data: Vec<u8>) -> Self
    where
        R: Registry,
    {
        // TODO vmx 2019-01-31: Get it from the CID instead of hard-coding it
        let codec = R::get_codec(cid::Codec::DagCBOR).unwrap();
        // TODO vmx 2019-01-31: Get it from the CID instead of hard-coding it
        let hash_alg = R::get_hash_alg(multihash::Hash::SHA2512).unwrap();
        Block {
            cid: Some(cid),
            data: Some(data),
            node: None,
            codec,
            hash_alg,
        }
    }

    pub fn encoder(
        node: Ipld,
        codec: &'a dyn CodecDyn<Error = CborError>,
        hash_alg: &'a dyn HashDyn,
    ) -> Self {
        Block {
            cid: None,
            data: None,
            node: Some(node),
            codec,
            hash_alg,
        }
    }

    pub fn decoder(
        data: Vec<u8>,
        codec: &'a dyn CodecDyn<Error = CborError>,
        hash_alg: &'a dyn HashDyn,
    ) -> Self {
        Block {
            cid: None,
            data: Some(data),
            node: None,
            codec,
            hash_alg,
        }
    }

    pub fn decode(&mut self) -> Ipld {
        if let Some(node) = &self.node {
            node.clone()
        } else if let Some(data) = &self.data {
            let decoded = block_on(self.codec.decode(&data)).unwrap();
            self.node = Some(decoded.clone());
            decoded
        } else {
            panic!("no data found, cannot decode block")
        }
    }

    pub fn encode(&mut self) -> Vec<u8> {
        if let Some(data) = &self.data {
            data.clone()
        } else if let Some(node) = &self.node{
            let encoded = block_on(self.codec.encode(&node)).unwrap().to_vec();
            self.data = Some(encoded.clone());
            encoded
        } else {
            panic!("no data found, cannot decode block")
        }
    }

    pub fn cid(&mut self) -> Cid {
        if let Some(cid) = &self.cid {
            cid.clone()
        } else {
            // TODO vmx 2020-01-31: should probably be `encodeUnsafe()`
            let hash = self.hash_alg.digest(&self.encode());
            let cid = Cid::new_v1(self.codec.codec(), hash);
            cid
        }
    }
}

impl<'a> fmt::Debug for Block<'a> {
    fn fmt(&self, ff: &mut fmt::Formatter) -> fmt::Result {
        write!(ff, "Block {{ cid: {:?}, data: {:?} }}", self.cid, self.data)
    }
}

fn cid_node(node: MyNode) {
    println!("cidnode: node: {:?}", node);

    //let encoded = DagCborCodec::encode(&Ipld::from(node.clone())).await;
    //println!("encoded: {:02x?}", encoded);
    //

    //let encoded = Block::encoder::<DagCborCodec, Sha2_256>(&Ipld::from(node));
    //let encoded = Block::encoder::<DagCborCodec, Sha2_256>(&Ipld::from(node), DagCborCodec, Sha2_256);
    let mut encoded = Block::encoder(Ipld::from(node), &DagCborCodec, &Sha2_256);
    println!("encoded: {:02x?}", encoded);

    let mut decoded = Block::decoder(encoded.encode(), &DagCborCodec, &Sha2_256);
    println!("decodec: {:02x?}", decoded);

    //let block = Block::new(
    //    encoded.cid.clone(),
    //    encoded.data.clone(),
    //    &DefaultRegistry {},
    //);
    let block = Block::new::<DefaultRegistry>(decoded.cid(), decoded.encode());
    println!("block:   {:02x?}", block);
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

    //block_on(cid_node(my_node));
    cid_node(my_node);
}
