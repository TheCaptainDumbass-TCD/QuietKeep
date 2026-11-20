//! Debian package version comparison, following the rules dpkg uses.

use std::cmp::Ordering;

fn order(c: Option<u8>) -> i32 {
    match c {
        None => 0,
        Some(b'~') => -1,
        Some(c) if c.is_ascii_digit() => 0,
        Some(c) if c.is_ascii_alphabetic() => i32::from(c),
        Some(c) => i32::from(c) + 256,
    }
}

fn verrevcmp(a: &[u8], b: &[u8]) -> Ordering {
    let (mut i, mut j) = (0, 0);
    let digit = |s: &[u8], k: usize| s.get(k).is_some_and(u8::is_ascii_digit);
    while i < a.len() || j < b.len() {
        while (i < a.len() && !digit(a, i)) || (j < b.len() && !digit(b, j)) {
            let (ac, bc) = (order(a.get(i).copied()), order(b.get(j).copied()));
            if ac != bc {
                return ac.cmp(&bc);
            }
            i += 1;
            j += 1;
        }
        while a.get(i) == Some(&b'0') {
            i += 1;
        }
        while b.get(j) == Some(&b'0') {
            j += 1;
        }
        let mut first_diff = Ordering::Equal;
        while digit(a, i) && digit(b, j) {
            if first_diff == Ordering::Equal {
                first_diff = a[i].cmp(&b[j]);
            }
            i += 1;
            j += 1;
        }
        if digit(a, i) {
            return Ordering::Greater;
        }
        if digit(b, j) {
            return Ordering::Less;
        }
        if first_diff != Ordering::Equal {
            return first_diff;
        }
    }
    Ordering::Equal
}

fn split(v: &str) -> (u64, &str, &str) {
    let v = v.trim();
    let (epoch, rest) = match v.split_once(':') {
        Some((e, r)) if !e.is_empty() && e.bytes().all(|b| b.is_ascii_digit()) => (e.parse().unwrap_or(u64::MAX), r),
        _ => (0, v),
    };
    match rest.rsplit_once('-') {
        Some((up, rev)) => (epoch, up, rev),
        None => (epoch, rest, ""),
    }
}

/// Compares two Debian package versions such as `1:8.9p1-3ubuntu0.16`.
pub fn compare(a: &str, b: &str) -> Ordering {
    let (ea, ua, ra) = split(a);
    let (eb, ub, rb) = split(b);
    ea.cmp(&eb)
        .then_with(|| verrevcmp(ua.as_bytes(), ub.as_bytes()))
        .then_with(|| verrevcmp(ra.as_bytes(), rb.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::compare;
    use std::cmp::Ordering::{Equal, Greater, Less};

    #[test]
    fn follows_dpkg_ordering() {
        let cases = [
            ("1.0", "1.0-1", Less),
            ("1.0~rc1", "1.0", Less),
            ("1.0~rc1-1", "1.0-1", Less),
            ("1:0.1", "2.0", Greater),
            ("1.0a", "1.0", Greater),
            ("1.0+b1", "1.0", Greater),
            ("1.0", "1.0", Equal),
            ("1.01", "1.1", Equal),
            ("0:1.0", "1.0", Equal),
            ("6.8.0-1060.63~22.04.1", "6.8.0-1061.64~22.04.1", Less),
            ("1.9.9-1ubuntu2.6", "1.9.9-1ubuntu2.10", Less),
            ("2.35-0ubuntu3.15", "2.35-0ubuntu3.4", Greater),
            ("1:8.9p1-3ubuntu0.16", "1:8.9p1-3ubuntu0.10", Greater),
            ("1:8.9p1-3ubuntu0.16", "8.9p1-3ubuntu0.99", Greater),
            ("6.12.57-1", "6.12.6-1", Greater),
            ("1.2.3-1~deb13u1", "1.2.3-1", Less),
            ("1.2.3-1+deb13u1", "1.2.3-1", Greater),
        ];
        for (a, b, want) in cases {
            assert_eq!(compare(a, b), want, "{a} vs {b}");
            assert_eq!(compare(b, a), want.reverse(), "{b} vs {a}");
        }
    }
}
