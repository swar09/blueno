#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allowed { remaining: u64, limit: u64 },
    Throttled { retry_after_secs: u64, limit: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseGrant {
    pub granted: u64,
    pub retry_after_secs: u64,
}
