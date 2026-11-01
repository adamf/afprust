//! Small helpers.

/// Constant-time byte comparison.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        d |= x ^ y;
    }
    // Prevent the compiler from short-circuiting the loop result.
    unsafe { std::ptr::read_volatile(&d) == 0 }
}

/// Overwrite a buffer with zeros in a way the optimizer will not remove.
pub fn scrub(b: &mut [u8]) {
    for x in b.iter_mut() {
        // SAFETY: volatile write to owned memory.
        unsafe { std::ptr::write_volatile(x, 0) };
    }
}

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
