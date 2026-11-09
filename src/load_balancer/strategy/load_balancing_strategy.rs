use std::sync::Arc;

use crate::load_balancer::{Backend, LoadBalancerError};

pub trait LoadBalancingStrategy: Send + Sync {
    fn select<'a>(
        &self,
        service_name: &str,
        backends: &'a [Arc<Backend>],
    ) -> Result<&'a Arc<Backend>, LoadBalancerError>;
}
