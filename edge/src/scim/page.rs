//! SCIM pagination (RFC 7644 §3.4.2.4). startIndex is 1-based; counts are integers.

use crate::scim::error::{ScimError, ScimErrorType};

#[derive(Debug, Clone, PartialEq)]
pub struct Page {
    pub start_index: usize,
    pub count: usize,
}

const DEFAULT_COUNT: usize = 100;
const MAX_COUNT: usize = 500;

pub fn parse_page(
    start_index: Option<&str>,
    count: Option<&str>,
) -> Result<Page, ScimError> {
    let start_index = match start_index {
        None => 1,
        Some(s) => {
            let n: i64 = s.parse().map_err(|_| {
                ScimError::bad_request(ScimErrorType::InvalidValue, "startIndex must be an integer")
            })?;
            if n < 1 {
                1
            } else {
                n as usize
            }
        }
    };
    let count = match count {
        None => DEFAULT_COUNT,
        Some(s) => {
            let n: i64 = s.parse().map_err(|_| {
                ScimError::bad_request(ScimErrorType::InvalidValue, "count must be an integer")
            })?;
            if n < 0 {
                0
            } else {
                (n as usize).min(MAX_COUNT)
            }
        }
    };
    Ok(Page { start_index, count })
}

/// Returns (sql_fragment, limit, offset). Caller appends a stable `ORDER BY id`
/// BEFORE this fragment.
pub fn to_sql(page: &Page) -> (String, i64, i64) {
    let offset = (page.start_index - 1) as i64;
    (
        "ORDER BY id ASC LIMIT ? OFFSET ?".to_string(),
        page.count as i64,
        offset,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_one_based_start_and_default_count() {
        let p = parse_page(None, None).unwrap();
        assert_eq!(p.start_index, 1);
        assert_eq!(p.count, DEFAULT_COUNT);
    }

    #[test]
    fn start_index_below_one_clamps_to_one() {
        assert_eq!(parse_page(Some("0"), None).unwrap().start_index, 1);
        assert_eq!(parse_page(Some("-5"), None).unwrap().start_index, 1);
    }

    #[test]
    fn offset_is_start_index_minus_one() {
        let p = parse_page(Some("11"), Some("10")).unwrap();
        let (frag, limit, offset) = to_sql(&p);
        assert!(frag.contains("ORDER BY id ASC"));
        assert_eq!(limit, 10);
        assert_eq!(offset, 10); // startIndex 11 → offset 10
    }

    #[test]
    fn count_is_clamped_to_max() {
        assert_eq!(parse_page(None, Some("99999")).unwrap().count, MAX_COUNT);
    }

    #[test]
    fn non_integer_is_invalid_value() {
        let err = parse_page(Some("abc"), None).unwrap_err();
        assert_eq!(err.scim_type, Some(ScimErrorType::InvalidValue));
    }
}
