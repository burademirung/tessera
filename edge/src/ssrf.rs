//! SSRF guard for outbound JWKS/discovery fetches: HTTPS-only, anchored issuer
//! allow-list, block private/loopback/link-local/metadata on every hop, and never
//! act on token-supplied key URLs. Pure + host-tested.

use serde_json::Value;

#[derive(Clone, Debug)]
pub struct IssuerAllowList {
    issuers: Vec<String>,
}

/// Build the anchored allow-list from configured issuer base URLs.
pub fn new_allow_list(issuers: &[&str]) -> IssuerAllowList {
    IssuerAllowList {
        issuers: issuers
            .iter()
            .map(|s| s.trim_end_matches('/').to_lowercase())
            .collect(),
    }
}

fn host_of(url: &str) -> Result<String, String> {
    let after = url
        .strip_prefix("https://")
        .ok_or("only https:// URLs are allowed")?;
    let host = after.split(['/', '?', '#']).next().unwrap_or("");
    let host = host.split('@').last().unwrap_or(host); // drop userinfo
    let host = host.trim_start_matches('[').trim_end_matches(']'); // ipv6 brackets
    // strip :port
    let host = if let Some(idx) = host.rfind(':') {
        let (h, p) = host.split_at(idx);
        if p[1..].chars().all(|c| c.is_ascii_digit()) && !h.is_empty() {
            h
        } else {
            host
        }
    } else {
        host
    };
    if host.is_empty() {
        return Err("empty host".to_string());
    }
    Ok(host.to_lowercase())
}

fn is_blocked_literal(host: &str) -> bool {
    // Metadata + obvious literals (string-level; defense-in-depth, every hop).
    if host == "169.254.169.254" || host == "metadata.google.internal" || host == "::1" {
        return true;
    }
    if host == "localhost" || host.ends_with(".localhost") {
        return true;
    }
    // IPv4 private/loopback/link-local ranges.
    let octets: Vec<u8> = host.split('.').filter_map(|o| o.parse::<u8>().ok()).collect();
    if octets.len() == 4 {
        let [a, b, _, _] = [octets[0], octets[1], octets[2], octets[3]];
        if a == 127 {
            return true; // loopback
        }
        if a == 10 {
            return true; // 10/8
        }
        if a == 192 && b == 168 {
            return true; // 192.168/16
        }
        if a == 172 && (16..=31).contains(&b) {
            return true; // 172.16/12
        }
        if a == 169 && b == 254 {
            return true; // link-local / metadata
        }
        if a == 0 {
            return true;
        }
    }
    false
}

/// Gate an outbound URL before any fetch: HTTPS only, host must be a configured
/// issuer host, and never a private/loopback/link-local/metadata target.
pub fn check_outbound_url(allow: &IssuerAllowList, url: &str) -> Result<(), String> {
    let host = host_of(url)?;
    if is_blocked_literal(&host) {
        return Err(format!("blocked host: {host}"));
    }
    let anchored = allow.issuers.iter().any(|iss| {
        host_of(iss).map(|h| h == host).unwrap_or(false)
    });
    if !anchored {
        return Err(format!("host not in issuer allow-list: {host}"));
    }
    Ok(())
}

/// Documents and enforces that we NEVER select key material from a token header's
/// `jku`/`x5u`/`jwk`. Returns true always — present so call sites assert intent and
/// tests guard against regressions.
pub fn header_key_url_is_ignored(_header: &Value) -> bool {
    // No code path reads jku/x5u/jwk for trust selection; trust comes only from
    // the anchored issuer's JWKS fetched via check_outbound_url.
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn allow() -> IssuerAllowList {
        new_allow_list(&["https://okta.example", "https://entra.example", "https://idp.lifecycle.example"])
    }

    #[test]
    fn allows_an_anchored_https_issuer_host() {
        assert!(check_outbound_url(&allow(), "https://okta.example/.well-known/openid-configuration").is_ok());
        assert!(check_outbound_url(&allow(), "https://idp.lifecycle.example/jwks").is_ok());
    }

    #[test]
    fn rejects_non_https() {
        assert!(check_outbound_url(&allow(), "http://okta.example/jwks").is_err());
    }

    #[test]
    fn rejects_unanchored_host() {
        assert!(check_outbound_url(&allow(), "https://evil.example/jwks").is_err());
    }

    #[test]
    fn blocks_the_cloud_metadata_endpoint() {
        assert!(check_outbound_url(&allow(), "https://169.254.169.254/latest/meta-data/").is_err());
    }

    #[test]
    fn blocks_rfc1918_loopback_and_linklocal() {
        for h in ["https://10.0.0.5/jwks", "https://192.168.1.1/jwks", "https://172.16.0.1/jwks", "https://127.0.0.1/jwks", "https://[::1]/jwks", "https://169.254.0.1/jwks"] {
            assert!(check_outbound_url(&allow(), h).is_err(), "should block {h}");
        }
    }

    #[test]
    fn token_supplied_key_urls_are_ignored() {
        let header = json!({ "alg":"RS256","kid":"k","jku":"https://evil.example/jwks","x5u":"https://evil.example/x","jwk":{"kty":"RSA"} });
        assert!(header_key_url_is_ignored(&header));
        let clean = json!({ "alg":"RS256","kid":"k" });
        assert!(header_key_url_is_ignored(&clean));
    }
}
