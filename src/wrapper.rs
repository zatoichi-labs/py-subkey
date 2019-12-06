use primitives::{ed25519, sr25519, ecdsa, Pair, Public};
pub use primitives::crypto::SecretStringError as SeedError;

pub trait Crypto: Sized {
	type Pair: Pair<Public = Self::Public>;
	type Public: Public + AsRef<[u8]> + std::hash::Hash;

	fn pair_from_suri(suri: &str) -> Result<Self::Pair, SeedError> {
        let password = None; // TODO Handle passwords in suri
		Self::Pair::from_string(suri, password)
	}

    fn pair_from_seed_slice(seed: &[u8]) -> Result<Self::Pair, SeedError> {
        <Self::Pair as Pair>::from_seed_slice(seed)
    }

    fn raw_seed(pair: &Self::Pair) -> Vec<u8> {
        pair.to_raw_vec()
    }

	fn public_from_pair(pair: &Self::Pair) -> Self::Public {
		pair.public()
	}

    fn public_from_slice(public: &[u8]) -> Self::Public
    {
        Self::Public::from_slice(public)
    }

    fn sign(pair: &Self::Pair, message: &[u8]) -> <Self::Pair as Pair>::Signature
    {
        pair.sign(message)
    }

    fn signature_from_slice(signature: &[u8]) -> <Self::Pair as Pair>::Signature;

    fn verify(signature: <Self::Pair as Pair>::Signature, message: &[u8], pubkey: &Self::Public) -> bool
    {
        <Self::Pair as Pair>::verify(&signature, message, pubkey)
    }
}

pub struct Ecdsa;

impl Crypto for Ecdsa {
	type Pair = ecdsa::Pair;
	type Public = ecdsa::Public;

    fn signature_from_slice(signature: &[u8]) -> ecdsa::Signature {
        ecdsa::Signature::from_slice(signature)
    }
}

pub struct Sr25519;

impl Crypto for Sr25519 {
	type Pair = sr25519::Pair;
	type Public = sr25519::Public;

    fn signature_from_slice(signature: &[u8]) -> sr25519::Signature {
        sr25519::Signature::from_slice(signature)
    }
}

pub struct Ed25519;

impl Crypto for Ed25519 {
	type Pair = ed25519::Pair;
	type Public = ed25519::Public;

	fn pair_from_suri(suri: &str) -> Result<Self::Pair, SeedError> {
        let password = None; // TODO Handle passwords in suri
		Ok(ed25519::Pair::from_legacy_string(suri, password))
	}

    fn signature_from_slice(signature: &[u8]) -> ed25519::Signature {
        ed25519::Signature::from_slice(signature)
    }
}
