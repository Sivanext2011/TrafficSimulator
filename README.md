# Telecom Traffic Simulator

A containerized web-based telecom traffic simulator supporting multiple protocols with full session lifecycle management.

## Supported Protocols

| Protocol | Interface | Transport | Session Lifecycle |
|----------|-----------|-----------|-------------------|
| 5G CHF (Nchf_ConvergedCharging) | SBI | HTTP/2 + mTLS | Create → Update → Release |
| 5G PCF (Npcf_SMPolicyControl) | SBI | HTTP/2 + mTLS | Create → Update → Delete |
| Diameter Gy | Online Charging | TCP/SCTP + TLS | CCR-I → CCR-U → CCR-T |
| Diameter Sy | Spending Limit | TCP/SCTP + TLS | SLR → SLA |
| Diameter Ro | Online Charging App | TCP/SCTP + TLS | CCR-I → CCR-U → CCR-T |
| SCAPv2 | Service Capability | TCP + TLS | Session lifecycle |

## Features

- Web UI with real-time metrics dashboard
- TPS (transactions per second) rate control slider
- Certificate upload (mTLS support)
- Full session lifecycle automation
- Configurable subscriber parameters (MSISDN, IMSI, Rating Group, Slice ID, DNN)
- Live success/failure counters, latency graphs
- Docker containerized deployment

## Quick Start

```bash
docker-compose up --build
```

Access the UI at: http://localhost:8080

## Configuration

Upload certificates and configure endpoints via the web UI, or mount them as volumes:

```yaml
volumes:
  - ./certs:/app/certs
```

## Architecture

```
Browser (Web UI) → FastAPI Backend → Target NF (CHA/PCF/DRA)
                        ↕
               WebSocket (live metrics)
```
