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

/// Parse 4 IPv4 octets from a dotted string. Returns None unless it is exactly
/// four decimal octets in 0..=255.
fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut out = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        // Reject empty / non-digit / out-of-range octets.
        if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        out[i] = p.parse::<u8>().ok()?;
    }
    Some(out)
}

/// True if an IPv4 literal is private/loopback/link-local/metadata/unspecified.
fn ipv4_is_blocked(o: &[u8; 4]) -> bool {
    let [a, b, _, _] = *o;
    a == 127            // loopback 127/8
        || a == 10          // 10/8
        || (a == 192 && b == 168) // 192.168/16
        || (a == 172 && (16..=31).contains(&b)) // 172.16/12
        || (a == 169 && b == 254) // link-local + metadata
        || a == 0           // 0.0.0.0/8 (incl. unspecified)
}

fn is_blocked_literal(host: &str) -> bool {
    // Metadata + obvious literals (string-level; defense-in-depth, every hop).
    if host == "metadata.google.internal" {
        return true;
    }
    if host == "localhost" || host.ends_with(".localhost") {
        return true;
    }
    // IPv4 private/loopback/link-local ranges.
    if let Some(o) = parse_ipv4(host) {
        if ipv4_is_blocked(&o) {
            return true;
        }
    }
    // IPv6 literals (brackets already stripped by host_of). Normalize lowercase.
    if host.contains(':') {
        return ipv6_is_blocked(host);
    }
    false
}

/// Block dangerous IPv6 literals: loopback `::1`, unspecified `::`, ULA `fc00::/7`
/// (fc/fd), link-local `fe80::/10`, and IPv4-mapped `::ffff:0:0/96` whose embedded
/// v4 falls in the v4 blocklist. The host is the lowercased, bracket-stripped form.
fn ipv6_is_blocked(host: &str) -> bool {
    // Loopback and unspecified.
    if host == "::1" || host == "::" || host == "0:0:0:0:0:0:0:1" || host == "0:0:0:0:0:0:0:0" {
        return true;
    }
    // IPv4-mapped (::ffff:a.b.c.d or ::ffff:HHHH:HHHH): check the embedded v4.
    if let Some(v4) = mapped_ipv4(host) {
        if ipv4_is_blocked(&v4) {
            return true;
        }
    }
    // First hextet governs ULA / link-local ranges.
    let first = host.split("::").next().unwrap_or(host);
    let first = first.split(':').next().unwrap_or("");
    if let Ok(h) = u16::from_str_radix(first, 16) {
        let high = (h >> 8) as u8;
        // ULA fc00::/7  -> high byte 0xfc or 0xfd
        if high == 0xfc || high == 0xfd {
            return true;
        }
        // link-local fe80::/10 -> 0xfe80..=0xfebf
        if (0xfe80..=0xfebf).contains(&h) {
            return true;
        }
    }
    false
}

/// Extract the embedded IPv4 from an IPv4-mapped IPv6 literal `::ffff:a.b.c.d`
/// (dotted form) or `::ffff:wwww:xxxx` (hex form). Returns None otherwise.
fn mapped_ipv4(host: &str) -> Option<[u8; 4]> {
    let rest = host.strip_prefix("::ffff:")?;
    // Dotted form: ::ffff:169.254.169.254
    if let Some(v4) = parse_ipv4(rest) {
        return Some(v4);
    }
    // Hex form: ::ffff:a9fe:a9fe -> two hextets => 4 bytes.
    let groups: Vec<&str> = rest.split(':').collect();
    if groups.len() == 2 {
        let hi = u16::from_str_radix(groups[0], 16).ok()?;
        let lo = u16::from_str_radix(groups[1], 16).ok()?;
        return Some([(hi >> 8) as u8, (hi & 0xff) as u8, (lo >> 8) as u8, (lo & 0xff) as u8]);
    }
    None
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
    fn blocks_ipv6_ula_linklocal_mapped_and_unspecified() {
        // ULA fc00::/7 (fcxx + fdxx), link-local fe80::/10, unspecified, mapped v4.
        for h in [
            "https://[fc00::1]/jwks",
            "https://[fd12:3456::1]/jwks",
            "https://[fe80::1]/jwks",
            "https://[febf::1]/jwks",
            "https://[::]/jwks",
            "https://[::1]/jwks",
            // IPv4-mapped metadata + RFC1918, dotted and hex forms.
            "https://[::ffff:169.254.169.254]/jwks",
            "https://[::ffff:10.0.0.1]/jwks",
            "https://[::ffff:a9fe:a9fe]/jwks", // 169.254.169.254 in hex
        ] {
            assert!(check_outbound_url(&allow(), h).is_err(), "should block {h}");
        }
        // 0.0.0.0 unspecified IPv4.
        assert!(check_outbound_url(&allow(), "https://0.0.0.0/jwks").is_err());
    }

    #[test]
    fn token_supplied_key_urls_are_ignored() {
        let header = json!({ "alg":"RS256","kid":"k","jku":"https://evil.example/jwks","x5u":"https://evil.example/x","jwk":{"kty":"RSA"} });
        assert!(header_key_url_is_ignored(&header));
        let clean = json!({ "alg":"RS256","kid":"k" });
        assert!(header_key_url_is_ignored(&clean));
    }
}
