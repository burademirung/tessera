//! Pure helpers shared across modules. Host-testable (no WASM).

use base64ct::{Base64UrlUnpadded, Encoding};

/// Base64url (no padding) encode — the JOSE encoding for all token parts.
pub fn b64url_encode(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

/// Base64url (no padding) decode.
pub fn b64url_decode(s: &str) -> Result<Vec<u8>, String> {
    Base64UrlUnpadded::decode_vec(s).map_err(|e| format!("base64url decode: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_base64url_without_padding() {
        let input = b"hello\x00\x01\x02world";
        let encoded = b64url_encode(input);
        assert!(!encoded.contains('='), "must be unpadded");
        assert!(
            !encoded.contains('+') && !encoded.contains('/'),
            "must be url-safe"
        );
        assert_eq!(b64url_decode(&encoded).unwrap(), input);
    }

    #[test]
    fn rejects_invalid_base64url() {
        assert!(b64url_decode("not valid !!!").is_err());
    }
}
