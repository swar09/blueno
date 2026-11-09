use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use tower::load::Load;
use uuid::Uuid;

#[derive(Debug)]
pub struct Backend {
    pub id: Uuid,
    pub addr: SocketAddr,
    pub in_flight: AtomicUsize,
    pub consecutive_transport_failures: AtomicUsize,
    pub is_available: AtomicBool,
}

pub struct BackendGuard {
    backend: Arc<Backend>,
}

impl Clone for BackendGuard {
    fn clone(&self) -> Self {
        self.backend.in_flight.fetch_add(1, Ordering::AcqRel);
        Self {
            backend: Arc::clone(&self.backend),
        }
    }
}

impl BackendGuard {
    pub fn backend(&self) -> &Arc<Backend> {
        &self.backend
    }
}

impl Drop for BackendGuard {
    fn drop(&mut self) {
        self.backend.in_flight.fetch_sub(1, Ordering::Release);
    }
}

impl Load for Backend {
    type Metric = usize;

    fn load(&self) -> Self::Metric {
        self.in_flight.load(Ordering::Acquire)
    }
}

impl Backend {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            id: Uuid::new_v4(),
            addr,
            in_flight: AtomicUsize::new(0),
            consecutive_transport_failures: AtomicUsize::new(0),
            is_available: AtomicBool::new(true),
        }
    }

    pub fn acquire(self: &Arc<Self>) -> BackendGuard {
        self.in_flight.fetch_add(1, Ordering::AcqRel);
        BackendGuard {
            backend: Arc::clone(self),
        }
    }

    pub fn mark_transport_failure(&self, threshold: usize) {
        let prev = self
            .consecutive_transport_failures
            .fetch_add(1, Ordering::AcqRel);
        if prev + 1 >= threshold {
            self.is_available.store(false, Ordering::Release);
        }
    }

    pub fn mark_transport_success(&self) {
        self.consecutive_transport_failures
            .store(0, Ordering::Release);
        self.is_available.store(true, Ordering::Release);
    }

    #[inline]
    pub fn is_healthy_and_open(&self) -> bool {
        self.is_available.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backend_in_flight_tracking() {
        let addr = "127.0.0.1:8080".parse().unwrap();
        let backend = Arc::new(Backend::new(addr));

        assert_eq!(backend.load(), 0);

        let guard1 = backend.acquire();
        assert_eq!(backend.load(), 1);

        {
            let guard2 = guard1.clone();
            assert_eq!(backend.load(), 2);
            drop(guard2);
        }
        assert_eq!(backend.load(), 1);

        drop(guard1);
        assert_eq!(backend.load(), 0);
    }

    #[test]
    fn test_backend_health_failure_circuit() {
        let addr = "127.0.0.1:8080".parse().unwrap();
        let backend = Backend::new(addr);

        assert!(backend.is_healthy_and_open());

        backend.mark_transport_failure(2);
        assert!(backend.is_healthy_and_open());

        backend.mark_transport_failure(2);
        assert!(!backend.is_healthy_and_open());

        backend.mark_transport_success();
        assert!(backend.is_healthy_and_open());
    }
}
