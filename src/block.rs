use std::convert::TryFrom;
use std::fmt;

use libipld::ipld::Ipld;
use libipld_core::cid::CidGeneric;
use libipld_core::codec::Codec;
use libipld_core::multihash::MultihashDigest;
use thiserror::Error;

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
