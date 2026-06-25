//! Authorization seam (Phase 4). The edge Worker is the PEP; this module is the
//! bridge to the PE (Regorus). The Worker passes the four-category `input` and the
//! loaded `data`; no policy logic lives here or in the Worker — only in Rego.
//!
//! `seam` holds the STABLE Phase-2 contract (trait + types); do not change it.
mod seam;
pub use seam::{AuthzDecision, AuthzInput, DenyAllEngine, PolicyEngine};

mod engine;
pub use engine::{AuthzError, RegorusEngine, ALLOW_QUERY};

mod bundle;
pub use bundle::SignedBundle;

#[cfg(test)]
mod conformance;
