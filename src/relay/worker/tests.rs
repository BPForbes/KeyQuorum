use super::{map_request, Refused, MAX_LARGE_REQUEST_BODY, MAX_REQUEST_BODY};

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
        true,
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
        map_request("POST", "https://relay.test/keycheck", None, None, big, true).err(),
        Some(Refused(413))
    );
    let at_cap = vec![0u8; MAX_REQUEST_BODY];
    assert!(map_request(
        "POST",
        "https://relay.test/keycheck",
        None,
        None,
        at_cap,
        true
    )
    .is_ok());
    assert_eq!(
        map_request("GET", "not a url", None, None, Vec::new(), true).err(),
        Some(Refused(400))
    );
}

#[test]
fn only_a_raw_inbox_push_may_carry_a_body_as_large_as_a_large_letter() {
    let large = || vec![0u8; MAX_REQUEST_BODY + 1];
    for content_type in [None, Some("application/octet-stream"), Some("text/plain")] {
        assert!(
            map_request(
                "POST",
                "https://relay.test/inbox",
                None,
                content_type,
                large(),
                true
            )
            .is_ok(),
            "a raw inbox push takes a large letter"
        );
        assert!(map_request(
            "POST",
            "https://relay.test/inbox/",
            None,
            content_type,
            vec![0u8; MAX_LARGE_REQUEST_BODY],
            true
        )
        .is_ok());
        assert_eq!(
            map_request(
                "POST",
                "https://relay.test/inbox",
                None,
                content_type,
                vec![0u8; MAX_LARGE_REQUEST_BODY + 1],
                true
            )
            .err(),
            Some(Refused(413))
        );
    }
    // JSON (trees, an expiry) stays small, so a large letter cannot ride in it.
    assert_eq!(
        map_request(
            "POST",
            "https://relay.test/inbox",
            None,
            Some("application/json"),
            large(),
            true
        )
        .err(),
        Some(Refused(413))
    );
    // Every other route, and every other method, keeps the small cap.
    for (method, url) in [
        ("POST", "https://relay.test/devices/packages"),
        ("PUT", "https://relay.test/inbox"),
        ("PUT", "https://relay.test/trees"),
        ("POST", "https://relay.test/keycheck"),
        ("POST", "https://relay.test/inbox/other"),
    ] {
        assert_eq!(
            map_request(method, url, None, None, large(), true).err(),
            Some(Refused(413)),
            "{method} {url}"
        );
    }
}

#[test]
fn an_empty_bearer_is_no_bearer_and_the_query_survives() {
    let request = map_request(
        "GET",
        "https://relay.test/inbox?after=3",
        Some(String::new()),
        None,
        Vec::new(),
        true,
    )
    .expect("mapped");
    assert!(request.bearer.is_none());
    assert_eq!(request.url.query(), Some("after=3"));
}

#[test]
fn without_a_bucket_every_body_keeps_the_small_cap() {
    let large = vec![0u8; MAX_REQUEST_BODY + 1];
    assert_eq!(
        map_request("POST", "https://relay.test/inbox", None, None, large, false).err(),
        Some(Refused(413))
    );
}
