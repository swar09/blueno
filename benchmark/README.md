# benchmark

benchmarking suite and load testing tools for blueno.

## results

single-instance sustained throughput on 32 concurrent workers over 4s:

- **throughput**: 130,043 req/s
- **latency p50**: 225µs
- **latency p90**: 345µs
- **latency p99**: 577µs
- **latency p99.9**: 10.2ms
- **total requests**: 520,281
- **errors**: 0 socket drops, 0 5xx

## running benchmarks

the cli runner auto-spawns internal mock services if no mock infra is running:

```bash
cargo run -p benchmark -- --concurrency 32 --duration-secs 4 --downstream-services 10
```

### options

- `--concurrency, -c <n>`: number of concurrent worker threads (default: 32)
- `--duration-secs, -d <secs>`: test duration in seconds (default: 4)
- `--downstream-services, -s <n>`: number of upstream services (default: 10)
- `--gateway-url, -g <url>`: target custom gateway instance if already running

### mock services infra

for testing against standalone mock upstream containers:

- **bun.js mock**: `bun run mock-server.ts`
- **docker compose**: `docker compose up -d`
