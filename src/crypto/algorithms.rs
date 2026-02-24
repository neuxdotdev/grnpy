use crate::error::{Error, Result};
use jsonwebtoken::Algorithm;
use rand::{self, RngExt};                 // rand 0.10 untuk HMAC
use rand08::rngs::OsRng;                  // rand 0.8 untuk RSA (kompatibel dengan rsa)
use rsa::{
    pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey},
    RsaPrivateKey, RsaPublicKey,
};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JwtAlgorithm {
    Hs256,
    Hs384,
    Hs512,
    Rs256,
    Rs384,
    Rs512,
}

impl JwtAlgorithm {
    pub fn to_algorithm(&self) -> Algorithm {
        match self {
            JwtAlgorithm::Hs256 => Algorithm::HS256,
            JwtAlgorithm::Hs384 => Algorithm::HS384,
            JwtAlgorithm::Hs512 => Algorithm::HS512,
            JwtAlgorithm::Rs256 => Algorithm::RS256,
            JwtAlgorithm::Rs384 => Algorithm::RS384,
            JwtAlgorithm::Rs512 => Algorithm::RS512,
        }
    }

    pub fn is_hmac(&self) -> bool {
        matches!(self, JwtAlgorithm::Hs256 | JwtAlgorithm::Hs384 | JwtAlgorithm::Hs512)
    }

    pub fn is_rsa(&self) -> bool {
        matches!(self, JwtAlgorithm::Rs256 | JwtAlgorithm::Rs384 | JwtAlgorithm::Rs512)
    }

    pub fn min_key_bits(&self) -> usize {
        match self {
            JwtAlgorithm::Hs256 => 256,
            JwtAlgorithm::Hs384 => 384,
            JwtAlgorithm::Hs512 => 512,
            JwtAlgorithm::Rs256 => 2048,
            JwtAlgorithm::Rs384 => 3072,
            JwtAlgorithm::Rs512 => 4096,
        }
    }
}

#[derive(Clone)]
pub enum JwtKey {
    Hmac(Vec<u8>),
    Rsa {
        private: Arc<RsaPrivateKey>,
        public: Arc<RsaPublicKey>,
    },
}

impl JwtKey {
    pub fn generate(alg: JwtAlgorithm) -> Result<Self> {
        match alg {
            alg if alg.is_hmac() => {
                let bits = alg.min_key_bits();
                let mut secret = vec![0u8; bits / 8];
                rand::rng().fill(&mut secret);      // rand 0.10
                Ok(JwtKey::Hmac(secret))
            }
            alg if alg.is_rsa() => {
                let bits = alg.min_key_bits();
                let mut rng = OsRng;                // rand 0.8 (OsRng)
                let private = RsaPrivateKey::new(&mut rng, bits)
                    .map_err(|e| Error::Crypto(format!("RSA key generation failed: {}", e)))?;
                let public = RsaPublicKey::from(&private);
                Ok(JwtKey::Rsa {
                    private: Arc::new(private),
                    public: Arc::new(public),
                })
            }
            _ => Err(Error::Internal { msg: "unsupported algorithm".into() }),
        }
    }

    pub fn from_hmac_secret(secret: Vec<u8>) -> Self {
        JwtKey::Hmac(secret)
    }

    pub fn from_rsa_private(private: RsaPrivateKey) -> Result<Self> {
        let public = RsaPublicKey::from(&private);
        Ok(JwtKey::Rsa {
            private: Arc::new(private),
            public: Arc::new(public),
        })
    }

    pub fn signing_key(&self) -> Result<jsonwebtoken::EncodingKey> {
        match self {
            JwtKey::Hmac(secret) => Ok(jsonwebtoken::EncodingKey::from_secret(secret)),
            JwtKey::Rsa { private, .. } => {
                let der = private
                    .to_pkcs1_der()
                    .map_err(|e| Error::Crypto(format!("Failed to encode RSA private key: {}", e)))?;
                Ok(jsonwebtoken::EncodingKey::from_rsa_der(der.as_bytes()))
            }
        }
    }

    pub fn verification_key(&self) -> Result<jsonwebtoken::DecodingKey> {
        match self {
            JwtKey::Hmac(secret) => Ok(jsonwebtoken::DecodingKey::from_secret(secret)),
            JwtKey::Rsa { public, .. } => {
                let der = public
                    .to_pkcs1_der()
                    .map_err(|e| Error::Crypto(format!("Failed to encode RSA public key: {}", e)))?;
                Ok(jsonwebtoken::DecodingKey::from_rsa_der(der.as_bytes()))
            }
        }
    }
}