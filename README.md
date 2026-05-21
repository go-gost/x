# x

The implementation layer for the GOST proxy framework. Every interface defined in [core/](../core/) is implemented here — handlers, listeners, dialers, connectors, plus config parsing, registries, and all cross-cutting concerns.

## Package layout

| Directory | Purpose |
|-----------|---------|
| `handler/` | Protocol handlers (http, socks4/5, ss, ssh, tunnel, tun, dns, redirect, etc.) |
| `listener/` | Protocol listeners (tcp, tls, ws, http2/3, quic, kcp, icmp, tun, udp, etc.) |
| `dialer/` | Outbound dialers (tcp, tls, ws, http2/3, quic, grpc, ssh, wg, kcp, icmp, etc.) |
| `connector/` | Destination connectors (http, socks4/5, ss, ssh, relay, tunnel, direct, etc.) |
| `config/` | Config struct, YAML/JSON parsing, and service construction |
| `registry/` | Typed global registries for all component types |
| `service/` | Accept loop wiring listener + handler |
| `chain/` | Multi-hop forwarding chain and route implementation |
| `router/` | Route table router (destination-based routing) |
| `hop/` | Node group with load-balanced selection |
| `selector/` | Load-balancing strategies (round-robin, random, weighted, hash) |
| `auth/`, `bypass/`, `admission/` | Authentication, bypass rules, admission control |
| `resolver/`, `hosts/` | DNS resolution and host mapping |
| `limiter/` | Traffic, connection, and rate limiters |
| `recorder/`, `observer/` | Traffic recording and observability |
| `ingress/`, `sd/`, `routing/` | Ingress control, service discovery, routing rules |
| `logger/`, `metrics/`, `api/` | Logging, Prometheus metrics, Web API |
| `metadata/`, `ctx/` | Metadata key-value system and context propagation |
| `internal/` | Shared internals — not importable externally |

## Component pattern

Every handler, listener, dialer, and connector follows the same pattern: `init()` registers a constructor into a global registry, the constructor takes functional options, and `Init(metadata.Metadata)` extracts typed configuration from the metadata key-value map.

See [CLAUDE.md](CLAUDE.md) for detailed architecture and conventions.
