use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use crate::load_balancer::{Backend, LoadBalancerError, LoadBalancingStrategy};

#[derive(Default)]
pub struct RoundRobin {
    counter: AtomicUsize,
}

impl LoadBalancingStrategy for RoundRobin {
    fn select<'a>(
        &self,
        service_name: &str,
        backends: &'a [Arc<Backend>],
    ) -> Result<&'a Arc<Backend>, LoadBalancerError> {
        if backends.is_empty() {
            return Err(LoadBalancerError::EmptyBackendPool {
                service_name: service_name.to_string(),
            });
        }

        let healthy: Vec<&'a Arc<Backend>> = backends
            .iter()
            .filter(|b| b.is_healthy_and_open())
            .collect();

        if healthy.is_empty() {
            return Err(LoadBalancerError::NoHealthyBackends {
                service_name: service_name.to_string(),
            });
        }

        let idx = self.counter.fetch_add(1, Ordering::Relaxed) % healthy.len();
        Ok(healthy[idx])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_robin_cycles_through_healthy_backends() {
        let b1 = Arc::new(Backend::new("127.0.0.1:8001".parse().unwrap()));
        let b2 = Arc::new(Backend::new("127.0.0.1:8002".parse().unwrap()));

        let strategy = RoundRobin::default();
        let backends = vec![Arc::clone(&b1), Arc::clone(&b2)];

        let first = strategy.select("test", &backends).unwrap();
        let second = strategy.select("test", &backends).unwrap();
        let third = strategy.select("test", &backends).unwrap();

        assert_eq!(first.addr, b1.addr);
        assert_eq!(second.addr, b2.addr);
        assert_eq!(third.addr, b1.addr);
    }
}
