use crate::crypto::algorithms::{JwtAlgorithm, JwtKey};
use crate::error::{Error, Result};
use crate::internal::validation;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::collections::HashMap;
use uuid::Uuid;
const DEFAULT_EXPIRES_IN: i64 = 3600;
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub iss: String,
    pub iat: i64,
    pub exp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    pub jti: String,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}
pub struct JwtBuilder {
    count: usize,
    algorithm: JwtAlgorithm,
    expires_in: i64,
    include_roles: bool,
    include_scope: bool,
    subject: Option<String>,
    issuer: Option<String>,
    key: Option<JwtKey>,
    extra_claims: HashMap<String, serde_json::Value>,
}
impl JwtBuilder {
    pub fn new() -> Self {
        Self {
            count: 1,
            algorithm: JwtAlgorithm::Hs256,
            expires_in: DEFAULT_EXPIRES_IN,
            include_roles: false,
            include_scope: false,
            subject: None,
            issuer: None,
            key: None,
            extra_claims: HashMap::new(),
        }
    }
    pub fn count(mut self, count: usize) -> Result<Self> {
        validation::check_range(count, 1, 10, "count")?;
        self.count = count;
        Ok(self)
    }
    pub fn algorithm(mut self, alg: JwtAlgorithm) -> Self {
        self.algorithm = alg;
        self
    }
    pub fn expires_in(mut self, seconds: i64) -> Result<Self> {
        if seconds <= 0 {
            return Err(Error::Validation("expires_in must be positive".into()));
        }
        self.expires_in = seconds;
        Ok(self)
    }
    pub fn include_roles(mut self, include: bool) -> Self {
        self.include_roles = include;
        self
    }
    pub fn include_scope(mut self, include: bool) -> Self {
        self.include_scope = include;
        self
    }
    pub fn subject(mut self, sub: impl Into<String>) -> Self {
        self.subject = Some(sub.into());
        self
    }
    pub fn issuer(mut self, iss: impl Into<String>) -> Self {
        self.issuer = Some(iss.into());
        self
    }
    pub fn key(mut self, key: JwtKey) -> Self {
        self.key = Some(key);
        self
    }
    pub fn add_claim(mut self, key: &str, value: serde_json::Value) -> Self {
        self.extra_claims.insert(key.to_string(), value);
        self
    }
    pub fn generate(self) -> Result<Vec<String>> {
        validation::check_range(self.count, 1, 10, "count")?;
        let mut tokens = Vec::with_capacity(self.count);
        for _ in 0..self.count {
            tokens.push(self.generate_single()?);
        }
        Ok(tokens)
    }
    fn generate_single(&self) -> Result<String> {
        let now = Utc::now();
        let iat = now.timestamp();
        let exp = (now + Duration::seconds(self.expires_in)).timestamp();
        let jti = Uuid::new_v4().to_string();
        let sub = self.subject.clone().unwrap_or_else(|| Uuid::new_v4().to_string());
        let iss = self.issuer.clone().unwrap_or_else(|| "librgrn".to_string());
        let roles = if self.include_roles {
            Some(vec!["user".to_string(), "admin".to_string()])
        } else {
            None
        };
        let scope = if self.include_scope {
            Some("read write".to_string())
        } else {
            None
        };
        let claims = Claims {
            sub,
            iss,
            iat,
            exp,
            roles,
            scope,
            jti,
            extra: self.extra_claims.clone(),
        };
        let key = match &self.key {
            Some(k) => k.clone(),
            None => JwtKey::generate(self.algorithm)?,
        };
        let header = jsonwebtoken::Header::new(self.algorithm.to_algorithm());
        let encoding_key = key.signing_key()?;
        jsonwebtoken::encode(&header, &claims, &encoding_key)
            .map_err(|e| Error::Jwt(format!("Failed to encode JWT: {}", e)))
    }
    pub fn verify(&self, token: &str) -> Result<Claims> {
        let key = self.key.as_ref().ok_or_else(|| Error::Jwt("No key provided for verification".into()))?;
        let mut validation = jsonwebtoken::Validation::new(self.algorithm.to_algorithm());
        validation.validate_exp = true;
        validation.required_spec_claims = HashSet::from_iter(vec!["exp".to_string()]);
        let decoding_key = key.verification_key()?;
        let token_data = jsonwebtoken::decode::<Claims>(token, &decoding_key, &validation)
            .map_err(|e| Error::Jwt(format!("Verification failed: {}", e)))?;
        Ok(token_data.claims)
    }
}
impl Default for JwtBuilder {
    fn default() -> Self {
        Self::new()
    }
}
pub fn generate_default() -> Result<String> {
    JwtBuilder::new().generate().map(|mut v| v.pop().unwrap())
}
pub fn generate_multiple(count: usize) -> Result<Vec<String>> {
    JwtBuilder::new().count(count)?.generate()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_generate_default() {
        let token = generate_default().unwrap();
        assert!(!token.is_empty());
    }
    #[test]
    fn test_generate_with_roles() {
        let builder = JwtBuilder::new()
            .include_roles(true)
            .include_scope(true)
            .expires_in(7200)
            .unwrap();
        let tokens = builder.generate().unwrap();
        assert_eq!(tokens.len(), 1);
    }
    #[test]
    fn test_verify() {
        let key = JwtKey::generate(JwtAlgorithm::Hs256).unwrap();
        let builder = JwtBuilder::new()
            .key(key.clone())
            .subject("testuser")
            .issuer("testissuer");
        let token = builder.generate().unwrap().pop().unwrap();
        // Buat builder baru untuk verifikasi dengan key yang sama
        let verifier = JwtBuilder::new().key(key);
        let verified = verifier.verify(&token).unwrap();
        assert_eq!(verified.sub, "testuser");
        assert_eq!(verified.iss, "testissuer");
    }
}