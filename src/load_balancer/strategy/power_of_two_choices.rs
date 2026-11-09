use std::sync::Arc;

use crate::load_balancer::{Backend, LoadBalancerError, LoadBalancingStrategy};
use tower::load::Load;

#[derive(Default)]
pub struct PowerOfTwoChoices;

impl LoadBalancingStrategy for PowerOfTwoChoices {
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

        if healthy.len() == 1 {
            return Ok(healthy[0]);
        }

        let idx1 = fastrand::usize(..healthy.len());
        let mut idx2 = fastrand::usize(..healthy.len());
        if idx1 == idx2 {
            idx2 = (idx1 + 1) % healthy.len();
        }

        let b1 = healthy[idx1];
        let b2 = healthy[idx2];

        if b1.load() <= b2.load() {
            Ok(b1)
        } else {
            Ok(b2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p2c_selects_least_loaded() {
        let b1 = Arc::new(Backend::new("127.0.0.1:8001".parse().unwrap()));
        let b2 = Arc::new(Backend::new("127.0.0.1:8002".parse().unwrap()));

        let _guard = b1.acquire(); // b1 has load 1, b2 has load 0

        let strategy = PowerOfTwoChoices;
        let backends = vec![Arc::clone(&b1), Arc::clone(&b2)];

        let chosen = strategy.select("test", &backends).unwrap();
        assert_eq!(chosen.load(), 0);
        assert_eq!(chosen.addr, b2.addr);
    }
}
