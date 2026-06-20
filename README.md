# SOC Log Pipeline Lab — Cribl Stream + Splunk Enterprise

Author: Madhumitha C | github.com/madhumithac588

---

## Architecture

Log Generator (Python) → Cribl Stream → Splunk Enterprise

- Python script simulates a 4-phase attack and sends logs to Cribl via HEC
- Cribl processes logs through a 5-stage pipeline before forwarding to Splunk
- Splunk indexes the enriched data and correlation alerts fire

---

## Project Structure
splunk-cribl-soc-lab/

├── scripts/

│   └── generate_logs.py       # 4-phase attack simulator

├── .env.example               # Environment variable template

└── .gitignore

---

## Cribl Pipeline — 5 Stages

| Stage | What it does |
|-------|-------------|
| Drop noise | Removes health checks and low-value events before indexing |
| Enrich | Adds risk_score and is_external_ip fields to every auth event |
| Mask PII | Redacts password fields from raw logs before they reach Splunk |
| Route | risk_score ≥ 7 goes to soc_high_risk index automatically |
| Audit metadata | Stamps pipeline_version and processed_at on every event |

---

## Splunk Knowledge Objects

**Field Extractions**
Regex-based extraction for three sourcetypes — soc_auth_log, soc_network_log, soc_endpoint_log

**CIM Field Aliases**
Raw fields mapped to Common Information Model standards (src, src_user, dest_port, bytes_out)

**SPL Macros**
- `soc_base_filter` — controls base index reference across all searches from one place
- `soc_brute_threshold(N)` — parameterized threshold for brute force detection

**Correlation Alerts**

| Alert | Threshold | MITRE |
|-------|-----------|-------|
| SOC - Brute Force Detected | 5+ failures from one IP in 5 min | T1110.001 |
| SOC - Credential Compromise | Failures followed by success, same IP | T1078 |
| SOC - Lateral Movement | Office app spawning PowerShell/cmd | T1059.001, T1566 |
| SOC - DNS Tunneling | 100+ DNS queries/min or long subdomains | T1071.004 |

All four scheduled via cron expression `*/5 * * * *`

---

## Attack Simulation — 4 Phases

| Phase | What it simulates | Event |
|-------|------------------|-------|
| 1 | Brute force from Tor exit node 185.220.101.47 | EventID 4625 |
| 2 | Successful login after credential compromise | EventID 4624 |
| 3 | WINWORD.EXE spawning PowerShell with base64 payload | Process creation |
| 4 | 120 rapid DNS queries to long subdomains — C2 tunneling | DNS log |

---

## Setup

### Prerequisites
- Docker Desktop installed and running
- Python 3.x
- pip install python-dotenv requests

### Steps

1. Clone the repo
```bash
git clone https://github.com/madhumithac588/splunk-cribl-soc-lab.git
cd splunk-cribl-soc-lab
```

2. Copy .env.example to .env and fill in your values
```bash
cp .env.example .env
```

3. Pull and run Splunk
```bash
docker run -d --name splunk-siem -p 8000:8000 -p 8088:8088 \
-e SPLUNK_START_ARGS=--accept-license \
-e SPLUNK_PASSWORD=your_password \
splunk/splunk:9.2.1
```

4. Pull and run Cribl
```bash
docker run -d --name cribl-stream -p 9000:9000 -p 9088:8088 \
-e CRIBL_ADMIN_USERNAME=admin \
-e CRIBL_ADMIN_PASSWORD=your_password \
cribl/cribl:latest
```

5. Run the attack simulator
```bash
python scripts/generate_logs.py
```

6. Open Splunk at http://localhost:8000 and search:
index=soc_logs | stats count by sourcetype

---

## Key SPL Queries

```spl
-- Full kill chain timeline
`soc_base_filter` (sourcetype=soc_auth_log OR sourcetype=soc_network_log OR sourcetype=soc_endpoint_log)
| eval phase=case(
    sourcetype="soc_auth_log" AND status="failure", "Phase 1 - Brute Force",
    sourcetype="soc_auth_log" AND status="success", "Phase 2 - Credential Compromise",
    sourcetype="soc_endpoint_log", "Phase 3 - Lateral Movement",
    sourcetype="soc_network_log", "Phase 4 - DNS Tunneling"
)
| stats count, values(user) as users BY phase, host
| sort phase

-- Brute force detection
index=soc_logs sourcetype=soc_auth_log status=failure
| bucket _time span=5m
| stats count as failed_attempts by _time, source_ip
| where failed_attempts > 5
```

---

