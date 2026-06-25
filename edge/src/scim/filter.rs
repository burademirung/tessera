//! Strict SCIM filter parser (RFC 7644 §3.4.2.2), restricted to the subset both
//! Okta and Entra actually send: `eq`, `pr` (present), `and`. The AST compiles to
//! a PARAMETERIZED SQL WHERE clause (placeholders + binds) — injection-safe.

use crate::scim::error::{ScimError, ScimErrorType};

#[derive(Debug, Clone, PartialEq)]
pub enum FilterExpr {
    Eq { attr: String, value: String },
    Present { attr: String },
    And(Box<FilterExpr>, Box<FilterExpr>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct SqlFilter {
    pub where_clause: String,
    pub binds: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Str(String),
    Eq,
    Pr,
    And,
    LParen,
    RParen,
}

/// Hard caps so a hostile filter cannot exhaust memory or blow the parser stack
/// (brief 10 §3: SCIM filter injection + pagination/DoS). Real IdP filters are tiny.
const MAX_FILTER_LEN: usize = 2048;
const MAX_FILTER_DEPTH: usize = 16;

fn lex(input: &str) -> Result<Vec<Tok>, ScimError> {
    if input.len() > MAX_FILTER_LEN {
        return Err(invalid("filter too long"));
    }
    let mut toks = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        match c {
            '(' => {
                toks.push(Tok::LParen);
                i += 1;
            }
            ')' => {
                toks.push(Tok::RParen);
                i += 1;
            }
            '"' => {
                let mut s = String::new();
                i += 1;
                while i < chars.len() && chars[i] != '"' {
                    // No escape processing: reject backslashes outright (defensive).
                    if chars[i] == '\\' {
                        return Err(invalid("escape sequences not allowed in filter strings"));
                    }
                    s.push(chars[i]);
                    i += 1;
                }
                if i >= chars.len() {
                    return Err(invalid("unterminated string literal"));
                }
                i += 1; // closing quote
                toks.push(Tok::Str(s));
            }
            c if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == ':' => {
                let mut s = String::new();
                while i < chars.len()
                    && (chars[i].is_ascii_alphanumeric()
                        || chars[i] == '.'
                        || chars[i] == '_'
                        || chars[i] == ':')
                {
                    s.push(chars[i]);
                    i += 1;
                }
                match s.to_lowercase().as_str() {
                    "eq" => toks.push(Tok::Eq),
                    "pr" => toks.push(Tok::Pr),
                    "and" => toks.push(Tok::And),
                    _ => toks.push(Tok::Ident(s)),
                }
            }
            _ => return Err(invalid(format!("unexpected character {c:?} in filter"))),
        }
    }
    Ok(toks)
}

fn invalid(detail: impl Into<String>) -> ScimError {
    ScimError::bad_request(ScimErrorType::InvalidFilter, detail)
}

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
    depth: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }
    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        self.pos += 1;
        t
    }
    // expr := term ( "and" term )*
    fn parse_expr(&mut self) -> Result<FilterExpr, ScimError> {
        // Depth guard: bound recursion so a hostile nested filter can't blow the
        // stack (DoS). Decremented on the way out.
        self.depth += 1;
        if self.depth > MAX_FILTER_DEPTH {
            return Err(invalid("filter nesting too deep"));
        }
        let mut left = self.parse_term()?;
        while matches!(self.peek(), Some(Tok::And)) {
            self.next();
            let right = self.parse_term()?;
            left = FilterExpr::And(Box::new(left), Box::new(right));
        }
        self.depth -= 1;
        Ok(left)
    }
    // term := "(" expr ")" | comparison
    fn parse_term(&mut self) -> Result<FilterExpr, ScimError> {
        if matches!(self.peek(), Some(Tok::LParen)) {
            self.next();
            let e = self.parse_expr()?;
            match self.next() {
                Some(Tok::RParen) => Ok(e),
                _ => Err(invalid("expected ')'")),
            }
        } else {
            self.parse_comparison()
        }
    }
    // comparison := ident ( "eq" string | "pr" )
    fn parse_comparison(&mut self) -> Result<FilterExpr, ScimError> {
        let attr = match self.next() {
            Some(Tok::Ident(s)) => s,
            _ => return Err(invalid("expected attribute name")),
        };
        match self.next() {
            Some(Tok::Eq) => match self.next() {
                Some(Tok::Str(v)) => Ok(FilterExpr::Eq { attr, value: v }),
                _ => Err(invalid("eq requires a quoted value")),
            },
            Some(Tok::Pr) => Ok(FilterExpr::Present { attr }),
            _ => Err(invalid("unsupported operator (only eq, pr, and are allowed)")),
        }
    }
}

pub fn parse_filter(input: &str) -> Result<FilterExpr, ScimError> {
    let toks = lex(input)?;
    if toks.is_empty() {
        return Err(invalid("empty filter"));
    }
    let mut p = Parser { toks, pos: 0, depth: 0 };
    let expr = p.parse_expr()?;
    if p.pos != p.toks.len() {
        return Err(invalid("trailing tokens in filter"));
    }
    Ok(expr)
}

/// Map an allow-listed SCIM attribute (case-insensitive) to a column name.
fn column_for<'a>(attr: &str, allow: &'a [(&'a str, &'a str)]) -> Result<&'a str, ScimError> {
    allow
        .iter()
        .find(|(scim, _)| scim.eq_ignore_ascii_case(attr))
        .map(|(_, col)| *col)
        .ok_or_else(|| invalid(format!("filtering on attribute {attr:?} is not supported")))
}

pub fn compile(expr: &FilterExpr, allow: &[(&str, &str)]) -> Result<SqlFilter, ScimError> {
    match expr {
        FilterExpr::Eq { attr, value } => {
            let col = column_for(attr, allow)?;
            Ok(SqlFilter {
                where_clause: format!("{col} = ?"),
                binds: vec![value.clone()],
            })
        }
        FilterExpr::Present { attr } => {
            let col = column_for(attr, allow)?;
            Ok(SqlFilter {
                where_clause: format!("({col} IS NOT NULL AND {col} != '')"),
                binds: vec![],
            })
        }
        FilterExpr::And(a, b) => {
            let la = compile(a, allow)?;
            let lb = compile(b, allow)?;
            let mut binds = la.binds;
            binds.extend(lb.binds);
            Ok(SqlFilter {
                where_clause: format!("({} AND {})", la.where_clause, lb.where_clause),
                binds,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALLOW: &[(&str, &str)] = &[
        ("userName", "user_name"),
        ("externalId", "external_id"),
        ("active", "active"),
        ("displayName", "display_name"),
    ];

    #[test]
    fn parses_eq() {
        // Verbatim Okta/Entra shape: userName eq "bjensen@example.com"
        let e = parse_filter("userName eq \"bjensen@example.com\"").unwrap();
        assert_eq!(
            e,
            FilterExpr::Eq { attr: "userName".into(), value: "bjensen@example.com".into() }
        );
    }

    #[test]
    fn parses_and_of_eq_and_pr() {
        let e = parse_filter("userName eq \"x\" and active pr").unwrap();
        match e {
            FilterExpr::And(_, _) => {}
            _ => panic!("expected And"),
        }
    }

    #[test]
    fn compiles_to_parameterized_sql() {
        let e = parse_filter("userName eq \"x\"").unwrap();
        let sql = compile(&e, ALLOW).unwrap();
        assert_eq!(sql.where_clause, "user_name = ?");
        assert_eq!(sql.binds, vec!["x".to_string()]);
    }

    #[test]
    fn compiles_and() {
        let e = parse_filter("userName eq \"x\" and externalId eq \"y\"").unwrap();
        let sql = compile(&e, ALLOW).unwrap();
        assert_eq!(sql.where_clause, "(user_name = ? AND external_id = ?)");
        assert_eq!(sql.binds, vec!["x".to_string(), "y".to_string()]);
    }

    #[test]
    fn injection_payload_is_a_bound_value_not_sql() {
        // The malicious string lands ONLY in binds, never in the SQL text.
        let e = parse_filter("userName eq \"x'; DROP TABLE users;--\"").unwrap();
        let sql = compile(&e, ALLOW).unwrap();
        assert_eq!(sql.where_clause, "user_name = ?");
        assert_eq!(sql.binds[0], "x'; DROP TABLE users;--");
        assert!(!sql.where_clause.contains("DROP"));
    }

    #[test]
    fn rejects_unsupported_operator() {
        let err = parse_filter("userName co \"x\"").unwrap_err();
        assert_eq!(err.status, 400);
        assert_eq!(err.scim_type, Some(ScimErrorType::InvalidFilter));
    }

    #[test]
    fn rejects_unknown_attribute_at_compile() {
        let e = parse_filter("password eq \"x\"").unwrap();
        let err = compile(&e, ALLOW).unwrap_err();
        assert_eq!(err.scim_type, Some(ScimErrorType::InvalidFilter));
    }

    #[test]
    fn rejects_escapes_and_unterminated_strings() {
        assert!(parse_filter("userName eq \"x\\y\"").is_err());
        assert!(parse_filter("userName eq \"x").is_err());
    }

    #[test]
    fn rejects_overlong_and_overdeep_filters() {
        // Length guard.
        let long = format!("userName eq \"{}\"", "a".repeat(MAX_FILTER_LEN));
        assert!(parse_filter(&long).is_err());
        // Depth guard: deeply nested parentheses.
        let deep = format!(
            "{}userName eq \"x\"{}",
            "(".repeat(MAX_FILTER_DEPTH + 2),
            ")".repeat(MAX_FILTER_DEPTH + 2)
        );
        let err = parse_filter(&deep).unwrap_err();
        assert_eq!(err.scim_type, Some(ScimErrorType::InvalidFilter));
    }
}
