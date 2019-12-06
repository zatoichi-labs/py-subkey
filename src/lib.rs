use pyo3::prelude::*;
use pyo3::wrap_pyfunction;
use pyo3::exceptions::TypeError;

mod wrapper;
use wrapper::{Crypto, Ed25519, Sr25519, Ecdsa, SeedError};

const ECDSA_KEYTYPE: &str = "secp256k1";
const SR25519_KEYTYPE: &str = "sr25519";
const ED25519_KEYTYPE: &str = "ed25519";

const DEV_PHRASE: &str = "bottom drive obey lake curtain smoke basket hold race lonely fit walk";

fn unexpected_keytype_error(key_type: &str) -> PyErr {
    PyErr::new::<TypeError, _>(format!("Unexpected key type: {}", key_type))
}

fn bad_seed_error(error: SeedError) -> PyErr {
    PyErr::new::<TypeError, _>(format!("{:?}", error))
}

#[pyclass(module = "subkey")]
pub struct KeyringPair {
    key_type: String,
    seed: Vec<u8>,
    public: Vec<u8>,
}

#[pyfunction(module = "subkey")]
fn create_from_suri(suri: String, key_type: String) -> PyResult<KeyringPair> {
    // Use dev phrase (INSECURE) if none is given
    let suri = if &suri.as_str()[..2] == "//" {
        DEV_PHRASE.to_string() + &suri
    } else {
        suri
    };
    Ok(match key_type.as_str() {
        ECDSA_KEYTYPE => {
            let pair = <Ecdsa as Crypto>::pair_from_suri(&suri)
                .map_err(|e| bad_seed_error(e))?;
            let mut public = vec![0u8; 64];
            public.copy_from_slice(<Ecdsa as Crypto>::public_from_pair(&pair).as_ref());
            KeyringPair {
                key_type,
                seed: <Ecdsa as Crypto>::raw_seed(&pair),
                public,
            }
        },
        SR25519_KEYTYPE => {
            let pair = <Sr25519 as Crypto>::pair_from_suri(&suri)
                .map_err(|e| bad_seed_error(e))?;
            let mut public = vec![0u8; 32];
            public.copy_from_slice(<Sr25519 as Crypto>::public_from_pair(&pair).as_ref());
            KeyringPair {
                key_type,
                seed: <Sr25519 as Crypto>::raw_seed(&pair),
                public,
            }
        },
        ED25519_KEYTYPE => {
            let pair = <Ed25519 as Crypto>::pair_from_suri(&suri)
                .map_err(|e| bad_seed_error(e))?;
            let mut public = vec![0u8; 32];
            public.copy_from_slice(<Ed25519 as Crypto>::public_from_pair(&pair).as_ref());
            KeyringPair {
                key_type,
                seed: <Ed25519 as Crypto>::raw_seed(&pair),
                public,
            }
        },
        _ => return Err(unexpected_keytype_error(&key_type)),
    })
}

#[pyfunction(module = "subkey")]
pub fn verify(key_type: &str, signature: &[u8], message: &[u8], public: &[u8]) -> PyResult<bool> {
    Ok(match key_type {
        ECDSA_KEYTYPE => {
            let public = <Ecdsa as Crypto>::public_from_slice(public);
            let signature = <Ecdsa as Crypto>::signature_from_slice(signature);
            <Ecdsa as Crypto>::verify(signature, message, &public)
        },
        SR25519_KEYTYPE => {
            let public = <Sr25519 as Crypto>::public_from_slice(public);
            let signature = <Sr25519 as Crypto>::signature_from_slice(signature);
            <Sr25519 as Crypto>::verify(signature, message, &public)
        },
        ED25519_KEYTYPE => {
            let public = <Ed25519 as Crypto>::public_from_slice(public);
            let signature = <Ed25519 as Crypto>::signature_from_slice(signature);
            <Ed25519 as Crypto>::verify(signature, message, &public)
        },
        _ => return Err(unexpected_keytype_error(&key_type)),
    })
}

#[pymethods]
impl KeyringPair {
    #[new]
    pub fn new(obj: &PyRawObject, suri: String, key_type: String) -> PyResult<()> {
        obj.init(create_from_suri(suri, key_type)?);
        Ok(())
    }

    #[getter]
    pub fn key_type(&self) -> &str {
        self.key_type.as_str()
    }

    #[getter]
    pub fn public(&self) -> &[u8] {
        self.public.as_ref()
    }

    pub fn sign(&self, message: &[u8]) -> PyResult<Vec<u8>> {
        Ok(match self.key_type.as_str() {
            ECDSA_KEYTYPE => {
                let pair = <Ecdsa as Crypto>::pair_from_seed_slice(&self.seed)
                    .map_err(|e| bad_seed_error(e))?;
                let signature = <Ecdsa as Crypto>::sign(&pair, message);
                let mut result = vec![0u8; 65];
                result.copy_from_slice(signature.as_ref());
                result
            },
            SR25519_KEYTYPE => {
                let pair = <Sr25519 as Crypto>::pair_from_seed_slice(&self.seed)
                    .map_err(|e| bad_seed_error(e))?;
                let signature = <Sr25519 as Crypto>::sign(&pair, message);
                let mut result = vec![0u8; 64];
                result.copy_from_slice(signature.as_ref());
                result
            },
            ED25519_KEYTYPE => {
                let pair = <Ed25519 as Crypto>::pair_from_seed_slice(&self.seed)
                    .map_err(|e| bad_seed_error(e))?;
                let signature = <Ed25519 as Crypto>::sign(&pair, message);
                let mut result = vec![0u8; 64];
                result.copy_from_slice(signature.as_ref());
                result
            },
            _ => return Err(unexpected_keytype_error(&self.key_type)),
        })
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> PyResult<bool> {
        return verify(&self.key_type, signature, message, &self.public)
    }
}

#[pyclass(module = "subkey")]
pub struct Keyring {
    default_key_type: String,
    pairs: Vec<KeyringPair>,
}

#[pymethods]
impl Keyring {
    #[new]
    pub fn new(obj: &PyRawObject, default_type: Option<String>) -> PyResult<()> {
        let default_key_type = if default_type.is_some() {
            let key_type = default_type.unwrap();
            if key_type != ECDSA_KEYTYPE
                && key_type != SR25519_KEYTYPE
                && key_type != ED25519_KEYTYPE
            {
                return Err(unexpected_keytype_error(&key_type));
            }
            key_type
        } else {
            ED25519_KEYTYPE.into()
        };
        obj.init(Keyring {
            default_key_type,
            pairs: vec![],
        });
        Ok(())
    }

    #[getter]
    pub fn default_key_type(&self) -> &str {
        self.default_key_type.as_str()
    }
    
    pub fn add_from_uri(&mut self, uri: String, key_type: Option<String>) -> PyResult<()> {
        let key_type = if key_type.is_some() {
            let key_type = key_type.unwrap();
            if key_type != ECDSA_KEYTYPE
                && key_type != SR25519_KEYTYPE
                && key_type != ED25519_KEYTYPE
            {
                return Err(unexpected_keytype_error(&key_type));
            }
            key_type
        } else {
            self.default_key_type.clone()
        };
        let pair = create_from_suri(uri, key_type)?;
        self.pairs.push(pair);
        Ok(())
    }
}

#[pymodule]
fn subkey(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<KeyringPair>()?;
    m.add_class::<Keyring>()?;
    m.add_wrapped(wrap_pyfunction!(create_from_suri))?;
    m.add_wrapped(wrap_pyfunction!(verify))?;

    Ok(())
}