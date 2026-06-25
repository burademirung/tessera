//! Self-signed runtime bundle. Regorus cannot consume OPA .tar.gz bundles, so we
//! ship our own manifest + detached Ed25519 signature and verify in the Worker
//! BEFORE loading into the engine (verifier-and-consumer-agree, fail closed).

use super::engine::{AuthzError, RegorusEngine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Deserialize)]
struct Manifest {
    version: String,
    revision: String,
    policies: BTreeMap<String, String>,
    data: serde_json::Value,
    hashes: BTreeMap<String, String>,
    data_hash: String,
}

pub struct SignedBundle {
    sig: Vec<u8>,
    manifest: Manifest,
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

impl SignedBundle {
    pub fn parse(bundle: &[u8], sig: &[u8]) -> Result<Self, AuthzError> {
        let manifest: Manifest =
            serde_json::from_slice(bundle).map_err(|e| AuthzError::Data(e.to_string()))?;
        Ok(Self {
            sig: sig.to_vec(),
            manifest,
        })
    }

    /// Recompute every hash and verify the detached Ed25519 signature.
    /// Rejects on ANY mismatch (fail closed).
    pub fn verify(&self, public_key: &[u8; 32]) -> Result<(), AuthzError> {
        if self.manifest.version != "1" {
            return Err(AuthzError::Data("unsupported bundle version".into()));
        }
        // 1. Every policy source must hash to its declared hash.
        for (name, src) in &self.manifest.policies {
            let want = self
                .manifest
                .hashes
                .get(name)
                .ok_or_else(|| AuthzError::Data(format!("missing hash for {name}")))?;
            if &sha256_hex(src.as_bytes()) != want {
                return Err(AuthzError::Data(format!("policy hash mismatch: {name}")));
            }
        }
        // 2. data_hash must match canonical (sorted, compact) data JSON.
        let data_canon = to_canonical_bytes(&self.manifest.data)?;
        if sha256_hex(&data_canon) != self.manifest.data_hash {
            return Err(AuthzError::Data("data_hash mismatch".into()));
        }
        // 3. Signature over sha256(canonical {revision, hashes, data_hash}).
        let signing_payload = to_canonical_bytes(&serde_json::json!({
            "revision": self.manifest.revision,
            "hashes": self.manifest.hashes,
            "data_hash": self.manifest.data_hash,
        }))?;
        let digest = Sha256::digest(&signing_payload);

        let vk =
            VerifyingKey::from_bytes(public_key).map_err(|e| AuthzError::Data(e.to_string()))?;
        let sig = Signature::from_slice(&self.sig).map_err(|e| AuthzError::Data(e.to_string()))?;
        vk.verify(&digest, &sig)
            .map_err(|_| AuthzError::Data("signature verification failed".into()))?;
        Ok(())
    }

    /// Build the engine. Caller MUST have called `verify` first.
    pub fn into_engine(self) -> Result<RegorusEngine, AuthzError> {
        let data_json = serde_json::to_string(&self.manifest.data)
            .map_err(|e| AuthzError::Data(e.to_string()))?;
        let policies: Vec<(&str, &str)> = self
            .manifest
            .policies
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        RegorusEngine::from_sources(&policies, &data_json)
    }

    pub fn revision(&self) -> &str {
        &self.manifest.revision
    }
}

/// Serialize a value to the same canonical compact-sorted JSON the Python signer
/// produces (`json.dumps(sort_keys=True, separators=(",", ":"))`): keys sorted
/// recursively, no whitespace. serde_json already emits no spaces; we only need
/// to sort object keys recursively.
fn to_canonical_bytes(v: &serde_json::Value) -> Result<Vec<u8>, AuthzError> {
    serde_json::to_vec(&canonicalize(v)).map_err(|e| AuthzError::Data(e.to_string()))
}

fn canonicalize(v: &serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(map) => {
            let mut sorted = serde_json::Map::new();
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for k in keys {
                sorted.insert(k.clone(), canonicalize(&map[k]));
            }
            serde_json::Value::Object(sorted)
        }
        serde_json::Value::Array(a) => {
            serde_json::Value::Array(a.iter().map(canonicalize).collect())
        }
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUNDLE: &[u8] = include_bytes!("../../tests/fixtures/bundle.json");
    const SIG: &[u8] = include_bytes!("../../tests/fixtures/bundle.sig");
    const PUBKEY_HEX: &str = include_str!("../../tests/fixtures/pubkey.hex");

    fn pubkey() -> [u8; 32] {
        let raw = hex_decode(PUBKEY_HEX.trim());
        let mut k = [0u8; 32];
        k.copy_from_slice(&raw);
        k
    }

    #[test]
    fn verifies_a_well_signed_bundle() {
        let b = SignedBundle::parse(BUNDLE, SIG).expect("parse");
        b.verify(&pubkey()).expect("verify ok");
        assert_eq!(b.revision(), "2026-06-24.1");
    }

    #[test]
    fn rejects_tampered_data() {
        let mut tampered = BUNDLE.to_vec();
        // Flip a byte inside the manifest -> hashes/signature must no longer match.
        let pos = tampered.len() / 2;
        tampered[pos] ^= 0x01;
        let parsed = SignedBundle::parse(&tampered, SIG);
        // Either parse fails (broken JSON) or verify fails — never accepted.
        let accepted = parsed.is_ok() && parsed.unwrap().verify(&pubkey()).is_ok();
        assert!(!accepted, "tampered bundle must be rejected");
    }

    #[test]
    fn rejects_wrong_signature() {
        let b = SignedBundle::parse(BUNDLE, SIG).expect("parse");
        let wrong = [0u8; 32];
        assert!(b.verify(&wrong).is_err(), "wrong key must fail verify");
    }

    #[test]
    fn verified_bundle_builds_a_working_engine() {
        let b = SignedBundle::parse(BUNDLE, SIG).expect("parse");
        b.verify(&pubkey()).expect("verify ok");
        let engine = b.into_engine().expect("engine");
        let input = r#"{"subject":{"id":"u1","roles":["reader"],"tenant":"t1","mfa":false},
            "resource":{"type":"user","id":"r1","tenant":"t1"},"action":"read",
            "environment":{"now_epoch":1782259200,"device_posture":"byod"}}"#;
        assert!(matches!(
            engine.decide_json(input),
            super::super::AuthzDecision::Allow
        ));
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
