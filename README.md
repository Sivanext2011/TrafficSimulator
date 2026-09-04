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

### Running locally (dev)

Docker (above) is the primary supported deployment. For quick local runs:

```bash
# Linux/macOS
./run.sh
# Windows (PowerShell)
.\run.ps1              # foreground
.\run.ps1 -Background  # detached
```

### Tests

```bash
pip install -r requirements.txt
pytest -q
```
CI runs `pytest` on every push/PR (`.github/workflows/ci.yml`).

### Diagnostics / operations APIs

| Endpoint | Purpose |
|----------|---------|
| `GET /api/diameter/status` | Per-peer connection/health (CER result, peer identity, reconnects, DWR/DWA, result-code breakdown) |
| `GET /api/diameter/messages?limit&peer` | Recent Diameter TX/RX messages (decoded AVP summary + hex) |
| `GET /api/logs/events?limit&level` | Last-N structured log events |
| `GET/POST /api/logs/level` | Read/set runtime log level |
| `GET /api/metrics` | Counters + latency p50/p95/p99 + result-code breakdown |
| `GET/POST/DELETE /api/profiles[/name]` | Named integration profiles (multi-environment) |


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
