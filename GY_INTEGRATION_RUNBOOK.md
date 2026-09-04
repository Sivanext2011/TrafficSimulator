# Gy Internal Charging — Integration Runbook (CBEV 23.10)

How the Telecom Traffic Simulator was made to run Gy online charging against the
CBEV cluster, the exact success criteria, and how to send usage (units) so real
deduction happens.

Peer: `10.163.238.25:3868` (TCP, non-TLS) — CHA Diameter Load Balancer
`eric-bss-cha-diameter-lb`.

---

## 1. What it took to get a successful Gy CCR (result progression)

Each fix advanced the Diameter result code; all are now in place.

| # | Problem | Result seen | Fix | Side |
|---|---------|-------------|-----|------|
| 0 | 1st CCR ok, rest "Failed to connect" | connect fail | — | — |
| 1 | New TCP connection per call (same Origin-Host) rejected as duplicate; socket wedged | WinError 64 | Reuse one persistent Diameter client; fail-fast + cleanup + reconnect | Simulator |
| 2 | CCR not proxiable, DLB answered itself | 3002 UNABLE_TO_DELIVER | Set Diameter **P-bit** on CCR | Simulator |
| 3 | DLB served no realm | 3003 REALM_NOT_SERVED | `beamctl diameter-interface set-own-realm ccaf.epc.mnc092.mcc466.3gppnetwork.org --appgroup-name=cha1` | Cluster |
| 4 | DLB→CHA-Access AccessPod peer stale | 3002 (no downstream peer) | `kubectl -n cbev rollout restart deployment eric-bss-cha-access` | Cluster |
| 5 | Service-Context-Id case mismatch | 5031 / "No matching service context" | Send **`32251@3GPP.org`** (uppercase GPP) — matches the Active service context | Simulator |
| 6 | GyData charging service not loaded in cha-core | per-MSCC 5031, 0 units | Provision GyData charging service + **Monetize Data Services license** | Cluster |

Steps 1,2,5 are simulator fixes (done). Steps 3,4 are cluster config (done).
Step 6's remaining piece is the **license** (in progress).

---

## 2. Working Gy CCR parameters (what the simulator sends)

- Command: **CCR (272)**, Auth-Application-Id **4**
- Destination-Realm: `ccaf.epc.mnc092.mcc466.3gppnetwork.org`
- Destination-Host: empty (realm routing)
- **Service-Context-Id: `32251@3GPP.org`**  ← exact case matters
- P-bit (Proxiable): set
- AVP order (per OnlineRo_Gy dictionary): Session-Id, Origin-Host, Origin-Realm,
  Destination-Realm, Auth-Application-Id, Service-Context-Id, CC-Request-Number,
  CC-Request-Type, [Destination-Host], Multiple-Services-Indicator=1,
  Subscription-Id (MSISDN E164 + IMSI), Event-Timestamp, MSCC, Service-Information
- PS-Information: Called-Station-Id (APN), 3GPP-SGSN-MCC-MNC, 3GPP-RAT-Type,
  3GPP-User-Location-Info
- Subscriber: MSISDN 975009991, IMSI 97500999111122

---

## 3. Success criteria (how the simulator judges success)

A CCR is only "successful" when BOTH:
- top-level Result-Code = 2001, AND
- every per-MSCC Result-Code = 2001 (granted units present).

A command-level 2001 with a per-MSCC 5031 (RATING_FAILED, 0 units) is treated as
**failed** — this is the "success but no deduction" case, which means rating did
not grant anything (e.g. GyData/license not ready).

---

## 4. How to SEND UNITS (trigger real deduction)

Deduction happens across the session lifecycle:
- **CCR-I (create)**: reserves an initial quota (Requested-Service-Unit). No usage yet.
- **CCR-U (update)**: reports **Used-Service-Unit** (actual consumed volume) → OCS
  debits the balance and grants the next quota. **This is where deduction occurs.**
- **CCR-T (terminate/release)**: reports final Used-Service-Unit → final debit, session ends.

### Option A — Manual tab (UI)
1. Open http://localhost:8080 → Gy tab (pre-filled).
2. **Manual → Create** (CCR-I): reserves quota, shows granted units.
3. **Manual → Update** (CCR-U): set Total/Uplink/Downlink volume (e.g. 1 MB) → sends
   Used-Service-Unit → deducts and re-grants.
4. Repeat Update to consume more.
5. **Manual → Release** (CCR-T): final used units → final deduction, session closed.

### Option B — API (matches what the UI sends)
```
# CCR-I
POST /api/manual/create
{ "protocol":"gy","fqdn":"10.163.238.25","port":3868,"secure":false,
  "diameter_host":"10.163.238.25","diameter_port":3868,
  "origin_host":"telecom-simulator.local","origin_realm":"simulator.realm",
  "destination_host":"","destination_realm":"ccaf.epc.mnc092.mcc466.3gppnetwork.org",
  "service_context_id":"32251@3GPP.org","auth_app_id":4,"rating_groups":[1000],
  "subscriber":{"msisdn":"975009991","imsi":"97500999111122","apn":"internet","mcc":"466","mnc":"92"} }
# -> returns session_id

# CCR-U (report used units -> deduction)
POST /api/manual/update
{ "session_id":"<from create>", "total_volume":1048576, "uplink_volume":314572, "downlink_volume":734003 }

# CCR-T (final used units -> final deduction, close)
POST /api/manual/release
{ "session_id":"<from create>", "total_volume":524288 }
```

### Option C — Continuous traffic (auto usage/deduction)
```
POST /api/traffic/start
{ "protocol":"gy","endpoint":{"protocol":"gy","fqdn":"10.163.238.25","port":3868,"secure":false},
  "subscriber":{"msisdn":"975009991","imsi":"97500999111122","apn":"internet","mcc":"466","mnc":"92"},
  "speed_mbps":10,"rating_groups":[1000],"session_duration_sec":300,"num_sessions":1,
  "diameter_host":"10.163.238.25","diameter_port":3868,
  "origin_host":"telecom-simulator.local","origin_realm":"simulator.realm",
  "destination_host":"","destination_realm":"ccaf.epc.mnc092.mcc466.3gppnetwork.org",
  "service_context_id":"32251@3GPP.org","auth_app_id":4 }
# The consumption engine periodically sends CCR-U with used units at the configured Mbps -> ongoing deduction.
POST /api/traffic/stop   # sends CCR-T
```

The Traffic tab drives CCR-U automatically based on the TPS/speed slider, so units
are consumed and deducted continuously until stopped.

---

## 5. Verifying deduction (once license is in place)

- CCA per-MSCC Result-Code = 2001 with GrantedUnits > 0 (create/update succeed).
- Balance enquiry before vs after: the data bucket (e.g. bucketSpec 6160006) `amount`
  decreases by the reported used volume.
- CHA-ALL trace (bamctl trace-management) shows GrantedUnits and BalanceResult populated.
- Simulator dashboard: successful count increments; sessions show granted units.

---

## 6. Remaining cluster prerequisite

GyData charging service must be loadable by cha-core. Blocked by the
**Monetize Data Services license** (`cbev23…ecmonetizedataservices…` currently
"no valid license key found"). Once a valid license key is installed and the
license shows valid=true, re-run a create/update — CCA returns 2001 with real
GrantedUnits and deduction occurs. No simulator changes needed.
