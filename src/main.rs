mod block;
mod flattendag;

use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::fs;

use clap::{App, Arg};
use libipld::cbor::DagCborCodec;
use libipld::json::DagJsonCodec;
use libipld_core::codec::Codec;
use libipld_core::multibase::Base;
use libipld_core::multihash::Code;
use serde_json::Value as JsonValue;

use crate::block::BlockGeneric;
use crate::flattendag::{flatten_dag, Meta, MetaType};

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

pub type Block = BlockGeneric<IpldCodec, Code>;

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
