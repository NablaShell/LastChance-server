// src/identity/mod.rs
use crate::storage::SafeFSOps;
use anyhow::{anyhow, Result};
use bip39::Mnemonic;
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

pub const IDENTITY_FILE_NAME: &str = "identity.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub nickname: String,
    pub seed_phrase: String,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
    pub ed25519_public_key: Vec<u8>,
    pub ed25519_private_key: Vec<u8>,
    pub hash: String,
    pub created_at: i64,
    pub updated_at: i64,
}

pub struct IdentityManager {
    storage_path: String,
    safe_fs: Option<SafeFSOps>,
    cached_id: Option<Identity>,
}

impl IdentityManager {
    pub fn new(storage_path: String) -> Self {
        Self {
            storage_path,
            safe_fs: None,
            cached_id: None,
        }
    }

    fn init_safe_fs(&mut self) -> Result<()> {
        if self.safe_fs.is_none() {
            self.safe_fs = Some(SafeFSOps::new(&self.storage_path)?);
        }
        Ok(())
    }

    pub fn generate_new_identity(&mut self, nickname: &str) -> Result<Identity> {
        let mut entropy = [0u8; 32];
        OsRng.fill_bytes(&mut entropy);

        let mnemonic = Mnemonic::from_entropy(&entropy)
            .map_err(|e| anyhow!("failed to generate mnemonic: {}", e))?;
        let seed_phrase = mnemonic.to_string();

        let seed = mnemonic.to_seed("");
        let (x_pub, x_priv, ed_pub, ed_priv, hash) = derive_keys_from_seed(&seed)?;

        let nickname = if nickname.is_empty() {
            format!("user_{}", &hash[..8])
        } else {
            nickname.to_string()
        };

        let now = chrono::Utc::now().timestamp();

        let identity = Identity {
            nickname,
            seed_phrase,
            public_key: x_pub,
            private_key: x_priv,
            ed25519_public_key: ed_pub,
            ed25519_private_key: ed_priv,
            hash,
            created_at: now,
            updated_at: now,
        };

        self.cached_id = Some(identity.clone());
        Ok(identity)
    }

    pub fn load_or_create(&mut self, nickname: &str) -> Result<Identity> {
        self.init_safe_fs()?;

        let safe_fs = self.safe_fs.as_ref().unwrap();
        match safe_fs.safe_stat(IDENTITY_FILE_NAME) {
            Ok(_) => self.load(),
            Err(_) => {
                let identity = self.generate_new_identity(nickname)?;
                self.save(&identity)?;
                Ok(identity)
            }
        }
    }

    pub fn save(&mut self, identity: &Identity) -> Result<()> {
        self.init_safe_fs()?;

        let data = serde_json::to_string_pretty(identity)
            .map_err(|e| anyhow!("failed to marshal identity: {}", e))?;

        let safe_fs = self.safe_fs.as_ref().unwrap();
        safe_fs.safe_write_file(IDENTITY_FILE_NAME, data.as_bytes(), 0o600)?;

        self.cached_id = Some(identity.clone());
        Ok(())
    }

    pub fn load(&mut self) -> Result<Identity> {
        self.init_safe_fs()?;

        let safe_fs = self.safe_fs.as_ref().unwrap();
        let data = safe_fs.safe_read_file(IDENTITY_FILE_NAME)?;

        let identity: Identity = serde_json::from_slice(&data)
            .map_err(|e| anyhow!("failed to unmarshal identity: {}", e))?;

        self.cached_id = Some(identity.clone());
        Ok(identity)
    }

    pub fn current(&self) -> Option<&Identity> {
        self.cached_id.as_ref()
    }

    pub fn update_nickname(&mut self, nickname: &str) -> Result<()> {
        if self.cached_id.is_none() {
            self.load_or_create(nickname)?;
        }

        if let Some(identity) = self.cached_id.as_mut() {
            identity.nickname = nickname.to_string();
            identity.updated_at = chrono::Utc::now().timestamp();
            let identity_clone = identity.clone();
            self.save(&identity_clone)?;
        }

        Ok(())
    }
}

fn derive_keys_from_seed(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, String)> {
    // X25519 via HKDF
    let hkdf_x = Hkdf::<Sha256>::new(None, seed);
    let mut x_priv_raw = [0u8; 32];
    hkdf_x
        .expand(b"X25519_E2EE_Key_v1", &mut x_priv_raw)
        .map_err(|e| anyhow!("hkdf x25519: {}", e))?;

    let private_key = StaticSecret::from(x_priv_raw);
    let public_key = PublicKey::from(&private_key);

    let x25519_priv = private_key.to_bytes().to_vec();
    let x25519_pub = public_key.as_bytes().to_vec();

    // Ed25519 via HKDF
    let hkdf_e = Hkdf::<Sha256>::new(None, seed);
    let mut ed_seed = [0u8; 32];
    hkdf_e
        .expand(b"Ed25519_Auth_Key_v1", &mut ed_seed)
        .map_err(|e| anyhow!("hkdf ed25519: {}", e))?;

    let signing_key = SigningKey::from_bytes(&ed_seed);
    let verifying_key = signing_key.verifying_key();

    let ed25519_pub = verifying_key.as_bytes().to_vec();
    let ed25519_priv = signing_key.to_bytes().to_vec();

    // Hash = SHA256(Ed25519PublicKey)
    let mut hasher = Sha256::new();
    hasher.update(&ed25519_pub);
    let hash_result = hasher.finalize();
    let hash = hex::encode(hash_result);

    Ok((x25519_pub, x25519_priv, ed25519_pub, ed25519_priv, hash))
}

impl Identity {
    pub fn get_public_key_hex(&self) -> String {
        hex::encode(&self.public_key)
    }

    pub fn get_ed25519_public_key_hex(&self) -> String {
        hex::encode(&self.ed25519_public_key)
    }

    pub fn sign_auth(&self, timestamp: i64) -> Result<String> {
        if self.ed25519_private_key.len() != 32 {
            return Err(anyhow!(
                "ed25519 private key invalid size: {}",
                self.ed25519_private_key.len()
            ));
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&self.ed25519_private_key);
        let signing_key = SigningKey::from_bytes(&key_bytes);

        use ed25519_dalek::Signer;
        let message = format!("{}{}", timestamp, self.hash);
        let signature = signing_key.sign(message.as_bytes());

        Ok(hex::encode(signature.to_bytes()))
    }
}
