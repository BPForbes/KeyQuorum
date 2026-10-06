use super::{map_request, Refused, MAX_REQUEST_BODY};

fn map(
    method: &str,
    content_type: Option<&str>,
) -> Result<crate::relay::RelayHttpRequest, Refused> {
    map_request(
        method,
        "https://relay.test/inbox?after=3",
        None,
        content_type,
        Vec::new(),
    )
}

#[test]
fn only_the_methods_the_router_serves_are_mapped() {
    for method in ["GET", "POST", "PUT", "DELETE"] {
        assert_eq!(map(method, None).expect("mapped").method, method);
    }
    for method in ["PATCH", "HEAD", "OPTIONS", "get", ""] {
        assert_eq!(map(method, None).err(), Some(Refused(405)), "{method}");
    }
}

#[test]
fn content_types_become_the_routers_literals() {
    let json = map("POST", Some("Application/JSON; charset=utf-8")).expect("mapped");
    assert_eq!(json.content_type, Some("application/json"));
    let other = map("POST", Some("text/plain")).expect("mapped");
    assert_eq!(other.content_type, Some("application/octet-stream"));
    assert_eq!(map("POST", None).expect("mapped").content_type, None);
}

#[test]
fn an_oversized_body_or_a_bad_url_is_refused_before_routing() {
    let big = vec![0u8; MAX_REQUEST_BODY + 1];
    assert_eq!(
        map_request("POST", "https://relay.test/inbox", None, None, big).err(),
        Some(Refused(413))
    );
    let at_cap = vec![0u8; MAX_REQUEST_BODY];
    assert!(map_request("POST", "https://relay.test/inbox", None, None, at_cap).is_ok());
    assert_eq!(
        map_request("GET", "not a url", None, None, Vec::new()).err(),
        Some(Refused(400))
    );
}

#[test]
fn an_empty_bearer_is_no_bearer_and_the_query_survives() {
    let request = map_request(
        "GET",
        "https://relay.test/inbox?after=3",
        Some(String::new()),
        None,
        Vec::new(),
    )
    .expect("mapped");
    assert!(request.bearer.is_none());
    assert_eq!(request.url.query(), Some("after=3"));
}
