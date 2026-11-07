use axum::http::{HeaderMap, HeaderName, header::CONNECTION};

use crate::header_policy::reserved_headers::HOP_BY_HOP_HEADERS;

pub fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let connection_listed: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|token| HeaderName::from_bytes(token.trim().as_bytes()).ok())
        .collect();

    for name in connection_listed {
        headers.remove(name);
    }
    for name in HOP_BY_HOP_HEADERS {
        headers.remove(name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn removes_all_standard_hop_by_hop_headers() {
        let mut headers = HeaderMap::new();
        for name in HOP_BY_HOP_HEADERS {
            headers.insert(HeaderName::from_static(name), HeaderValue::from_static("1"));
        }
        headers.insert("accept", HeaderValue::from_static("*/*"));
        strip_hop_by_hop(&mut headers);
        assert_eq!(headers.len(), 1);
        assert!(headers.contains_key("accept"));
    }

    #[test]
    fn removes_headers_named_by_connection() {
        let mut headers = HeaderMap::new();
        headers.insert("connection", HeaderValue::from_static("close, X-Foo"));
        headers.insert("x-foo", HeaderValue::from_static("1"));
        headers.insert("x-bar", HeaderValue::from_static("2"));
        strip_hop_by_hop(&mut headers);
        assert!(!headers.contains_key("x-foo"));
        assert!(!headers.contains_key("connection"));
        assert!(headers.contains_key("x-bar"));
    }

    #[test]
    fn handles_multiple_connection_values_and_garbage() {
        let mut headers = HeaderMap::new();
        headers.append("connection", HeaderValue::from_static("x-a"));
        headers.append("connection", HeaderValue::from_static(" , bad name, x-b"));
        headers.insert("x-a", HeaderValue::from_static("1"));
        headers.insert("x-b", HeaderValue::from_static("1"));
        headers.insert("x-c", HeaderValue::from_static("1"));
        strip_hop_by_hop(&mut headers);
        assert_eq!(headers.len(), 1);
        assert!(headers.contains_key("x-c"));
    }

    #[test]
    fn leaves_other_headers_untouched() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("text/plain"));
        strip_hop_by_hop(&mut headers);
        assert_eq!(headers.len(), 1);
    }
}
