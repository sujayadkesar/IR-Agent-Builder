//! Process-wide collection-size budget.
//!
//! `max_collection_size_gb` is checked at artifact boundaries in `main`, but a
//! single artifact can balloon on its own — e.g. a `$Recycle.Bin/**/*` glob that
//! copies multiple GB inside one `patterns::collect` call. This global budget is
//! consulted by the file-copy loops so such an artifact is stopped mid-copy, not
//! only after it has already filled the disk.
//!
//! Default cap is unlimited; `main` sets it once at startup. Thread-safe so it
//! works under parallel collection.

use std::sync::atomic::{AtomicU64, Ordering};

static CAP: AtomicU64 = AtomicU64::new(u64::MAX);
static USED: AtomicU64 = AtomicU64::new(0);

/// Set the total byte cap (`u64::MAX` = unlimited).
pub fn set_cap(bytes: u64) {
    CAP.store(bytes, Ordering::Relaxed);
}

/// Account for `bytes` just collected; returns `true` if the cap is now reached.
pub fn add(bytes: u64) -> bool {
    let used = USED.fetch_add(bytes, Ordering::Relaxed).saturating_add(bytes);
    used >= CAP.load(Ordering::Relaxed)
}

/// Whether the cap has already been reached.
pub fn is_over() -> bool {
    USED.load(Ordering::Relaxed) >= CAP.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_trips_when_total_crosses() {
        // Note: globals are process-wide; this is the only test that touches them.
        set_cap(1000);
        assert!(!is_over());
        assert!(!add(400)); // 400 < 1000
        assert!(!add(400)); // 800 < 1000
        assert!(add(400)); // 1200 >= 1000 -> tripped
        assert!(is_over());
        // Unlimited cap never trips.
        set_cap(u64::MAX);
        assert!(!is_over());
    }
}
