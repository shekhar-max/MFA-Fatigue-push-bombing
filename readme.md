# SOC Lab Experiment: Detecting Identity Bypass via MFA Fatigue (Push Bombing)

## 📌 Project Overview
This project simulates and detects a modern **MFA Fatigue (Push Bombing)** attack pattern within a custom home-lab environment. The goal is to replicate the techniques used by advanced threat groups (e.g., Lapsus$, Akira, RansomHub) who bypass Multi-Factor Authentication not through exploits, but by compromising primary credentials and bombarding users with secondary authentication requests until they yield out of frustration or distraction.

The scenario demonstrates how a Tier 2 SOC Analyst / Detection Engineer moves from **adversary simulation** to **log ingestion pipeline validation** and finally **behavioral correlation alert engineering**.

---

## 🏗️ Lab Architecture & Data Pipeline
The attack lifecycle tracks across isolated zones managed through a virtualized lab environment:

1. **Attacker Zone (Kali Linux):** Automates the primary credential authentication loops and floods the application endpoint with pending push requests.
2. **Applications Zone (Docker Target):** Hosts a lightweight microservice endpoint simulating an Identity Provider portal that outputs dedicated security logs.
3. **Log Aggregation Pipeline:** Configured a **Splunk Universal Forwarder** on the Docker host targeting application-layer filesystem logs (`/var/log/`) and shipping them over network port `9997`.
4. **SIEM Zone (Splunk Enterprise):** Ingests raw telemetry logs, executes dynamic key-value field extractions, and processes the correlation search queries.

---

## ⚡ Attack Execution Simulation
The adversary behavior is simulated via a Python script utilizing the `requests` library. The script assumes primary credential compromise (`username` and `password` are known) and automates a multi-phase authentication hijack.

### Phase 1: The Push Storm
The script programmatically triggers an intentional authentication loop with a minor offset delay, forcing the authentication broker to broadcast multiple out-of-band push requests to the target user's mobile endpoint.
* **Volume:** 15 consecutive MFA push requests.
* **Interval:** 2-second sleep duration between payloads to maximize user interface saturation.

### Phase 2: The Compromise Accept
After the storm phase completes, the script halts for 10 seconds to simulate user mental fatigue before submitting a final payload with an approved session action value, mimicking a user tapping "Approve" out of distraction or annoyance.

---

## 📝 Telemetry Log Mapping
The simulated application writes directly to a structured flat-file log (`mfa_security.log`). The ingestion schema generates clean boundaries capturing the threat actor's IP address alongside anomalous status flags:

```text
2026-09-18 09:47:30,575 - INFO - status=MFA_Prompt_Sent user=victim_user src_ip=192.168.40.2 msg='Push notification sent to user device'
2026-09-18 09:47:30,576 - INFO - 192.168.40.2 - - [18/Sep/2026 09:47:30] "POST /login HTTP/1.1" 202 -
2026-09-18 09:47:41,410 - INFO - status=MFA_Approved user=victim_user src_ip=192.168.40.2 msg='User approved the push notification'
2026-09-18 09:47:41,410 - INFO - 192.168.40.2 - - [18/Sep/2026 09:47:41] "POST /login HTTP/1.1" 200 -
```

---

## 🔍 Detection Engineering & Alert Logic
Standard signature alerts targeting simple "MFA Failure" statuses will not catch this technique since the ultimate authentication outcome is logged as a successful connection. Instead, this detection relies on a **behavioral threshold correlation search**.

### Splunk Search Language (SPL) Production Query

```spl
index=* sourcetype="mfa_auth_logs"
| rex field=_raw "status=(?<status>\S+)\s+user=(?<user>\S+)\s+src_ip=(?<src_ip>\S+)"
| bucket _time span=5m
| stats count(eval(status="MFA_Prompt_Sent")) as total_prompts,
        count(eval(status="MFA_Approved")) as approved_prompts
        by user, src_ip, _time
| where total_prompts >= 10 AND approved_prompts > 0
```

### 🧠 Performance & Optimization Breakdown
* **Dynamic Inline Parsing (`rex`):** Leverages Regex capture groups to dynamically extract `status`, `user`, and `src_ip` straight from raw text strings on the fly, eliminating the need for slow, predefined extraction indexes.
* **Temporal Binning (`bucket`):** Groups events into tight 5-minute intervals. This reduces memory pressure and aligns specifically with the rapid, volatile timeframe indicative of an active push bombing attack rather than normal day-to-day login drift.
* **Resource Preservation (`stats` over `transaction`):** The `transaction` command is computationally expensive in production enterprise tenants because it keeps open event states in memory. Using `stats` grouped by standard context keys calculates the evaluation matrix dramatically faster.
* **Anomaly Filtering (`where` logic):** A typical user workflow registers as 1 prompt and 1 approval. Enforcing a threshold constraint of `total_prompts >= 10` paired with an ultimate `approved_prompts > 0` strips away typical enterprise noise and exclusively bubbles up successful compromises.

---

## 🛡️ Level 2 Incident Response & Containment Playbook
When this correlation rule fires within a Tier 2 queue, the analyst should execute the following containment strategy:

1. **Identity Isolation:** Immediately invoke an API command via the Identity Provider (Azure AD/Entra ID, Okta, Duo) to **revoke all active OAuth refresh tokens** and active web sessions for the compromised user account.
2. **Context Validation:** Compare the `src_ip` tied to the threat actor's authentication traffic against historical user baseline network segments. Check for geographic anomalies or unexpected ISP changes.
3. **Device Quarantine:** If the IP tracks to an internal network segment, cross-reference host endpoints with EDR telemetry to isolate the originating endpoint.
4. **Credential Mitigation:** Force an administrative password reset across the directory service and require an out-of-band identity check before unlocking the user token.
