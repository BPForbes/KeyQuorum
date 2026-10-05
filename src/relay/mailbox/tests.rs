use super::*;

fn rows(sizes: &[usize]) -> Vec<(i64, usize)> {
    sizes
        .iter()
        .enumerate()
        .map(|(i, len)| (i as i64 + 1, *len))
        .collect()
}

fn bound(sizes: &[usize], page: i64) -> (Vec<(i64, usize)>, Option<i64>) {
    bound_page(rows(sizes), page, |r| r.0, |r| r.1)
}

#[test]
fn a_short_page_has_no_next_page() {
    let (kept, next) = bound(&[10, 10], 5);
    assert_eq!(kept.len(), 2);
    assert_eq!(next, None);
}

#[test]
fn the_extra_row_fetched_to_detect_a_next_page_is_dropped() {
    let (kept, next) = bound(&[10, 10, 10], 2);
    assert_eq!(kept.len(), 2);
    assert_eq!(next, Some(2));
}

#[test]
fn a_page_stops_before_the_byte_budget_and_points_at_the_last_letter_kept() {
    let third = MAX_INBOX_PAGE_BYTES / 3 + 1;
    let (kept, next) = bound(&[third, third, third, third], 100);
    assert_eq!(kept.len(), 2);
    assert_eq!(next, Some(2));
}

#[test]
fn a_page_at_exactly_the_budget_is_kept_whole() {
    let (kept, next) = bound(&[MAX_INBOX_PAGE_BYTES / 2, MAX_INBOX_PAGE_BYTES / 2], 100);
    assert_eq!(kept.len(), 2);
    assert_eq!(next, None);
}

#[test]
fn the_first_letter_is_always_returned_even_over_the_budget() {
    let (kept, next) = bound(&[MAX_INBOX_PAGE_BYTES + 1, 10], 100);
    assert_eq!(kept.len(), 1);
    assert_eq!(next, Some(1));
}

#[test]
fn the_worst_legal_page_fits_the_client_response_limit_once_encoded() {
    // Base64 inflates by 4/3; JSON framing is small beside the letters.
    let encoded = MAX_INBOX_PAGE_BYTES / 3 * 4 + 1024 * 1024;
    assert!((encoded as u64) < crate::relay::client::MAX_RESPONSE_BYTES);
}
