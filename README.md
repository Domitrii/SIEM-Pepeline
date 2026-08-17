# SIEM Pipeline: Detection Engineering Lab

**Author:** Dima

**Stack:** Filebeat → Elasticsearch → Kibana (Docker Compose)

**Type:** Personal cybersecurity portfolio project

---

## 1. Goal

Build a working, self-hosted SIEM (Security Information and Event Management) pipeline from scratch to demonstrate practical security monitoring and detection engineering skills — not just running a stack, but understanding how log data flows from a source, through parsing and enrichment, into a searchable index, and finally into an automated detection rule that fires on malicious activity.

Specifically, the lab set out to answer: *"Given a raw authentication log, can I detect a brute-force SSH attack in near-real-time, using nothing but open-source tooling I configured myself?"*

<img width="1303" height="59" alt="Screenshot 2026-08-17 at 13 13 32" src="https://github.com/user-attachments/assets/692e3646-cd23-4da0-a385-d296f2284aa1" />

---

## 2. Architecture

```
auth.log (synthetic) --> Filebeat --> Elasticsearch ingest pipeline --> Elasticsearch index --> Kibana: Discover, Alerting
```

Here are the tools I was using during this lab.

- **Filebeat** works as an explorer and delivers raw lines to Elasticsearch.
- **An Elasticsearch ingest pipeline** analyses every raw syslog line using grok patterns into structured fields such as "source_ip, user_name, log_host, process_name, event.outcome, and @timestamp"
- **Elasticsearch** is a daily indicator and storage of events. `siem-auth-logs-YYYY.MM.DD`
- **Kibana** includes tools for threat and traffic search and exploration (Discover) and an alerting engine (Index Threshold rule) that watches for brute-force patterns.

All of these services are running through a single Docker file - `docker-compose.yml`.
I disabled Elasticsearch security for the lab simplicity purpose.

---

## 3. Attack scenario

I was using rebuilded synthetic `auth.log`, to avoid any real IPs and usernames, this version was modeling a realistic brute-force-then-compromise pattern:

- Normal SSH logins and sudo activity from legitimate users
- A burst of 9 failed SSH logins from a single IP (`203.0.113.44`) against common usernames (`admin`, `root`, `oracle`,...)
- A **successful** login from that same IP immediately after — the brute-force paying off
- A new, suspicious account (`backdoor01`) created right after the compromise — a classic post-exploitation move
- A sensitive file access event (`cat /etc/shadow` via sudo)

A companion script, `generate_live_attack.sh`, was also built to simulate a **live** attack by appending fresh failed-login lines with real-time timestamps — necessary for testing an alert rule, since Kibana rules evaluate a rolling time window and can't "see" static historical data as current.

<img width="1470" height="956" alt="Screenshot 2026-08-17 at 12 37 32" src="https://github.com/user-attachments/assets/a96da909-9c7c-4a9a-a86f-d7e0be410c5f" />


---

## 4. Detection rule

An Elasticsearch **Index Threshold** rule was configured in Kibana:

| Setting | Value |
|---|---|
| Index | `siem-auth-logs-*` |
| Condition | `count()` |
| Grouped over | top 10 `source_ip.keyword` |
| Threshold | is above 5 |
| Time window | for the last 1 minute |
| Filter | `event.outcome: "failure"` |
| Action | Server log connector |

This means: *if any single source IP produces more than 5 failed logins within a 1-minute window, fire an alert.* This was validated live using `generate_live_attack.sh`, which drips in 12 failed attempts from one IP over ~24 seconds — comfortably over the threshold.


<img width="1470" height="956" alt="Screenshot 2026-08-17 at 12 58 57" src="https://github.com/user-attachments/assets/9ebecf46-33c3-4a43-af4c-88c412ef0945" />
<img width="1470" height="956" alt="Screenshot 2026-08-17 at 12 59 45" src="https://github.com/user-attachments/assets/092700b4-baaf-4f8d-9b6b-cd549aae2d05" />
<img width="675" height="72" alt="Screenshot 2026-08-17 at 13 02 49" src="https://github.com/user-attachments/assets/d03d2eae-d15f-4b27-9595-3b8c428863e4" />
<img width="1126" height="37" alt="Screenshot 2026-08-17 at 13 31 28" src="https://github.com/user-attachments/assets/349e4e0a-17af-4401-bccc-0fca7b118f81" />


---

## 5. Problems encountered and how they were resolved

This section is arguably the most valuable part of the lab — most of the real learning happened while debugging, not while following the happy path.

### 5.1 Container name conflicts across duplicate project folders
**Symptom:** `Error response from daemon: Conflict. The container name "/es01" is already in use`
**Cause:** Re-downloading the project created a second folder (`siem-pipeline 2`), and Docker container names are global regardless of which folder started them — an old container from an earlier run was still present.
**Fix:** `docker rm -f <container>` to force-remove stale containers, then standardized on working from a single project folder going forward.

### 5.2 Filebeat appeared to ingest nothing after a fresh start
**Symptom:** `_count` on the index repeatedly returned 0, even though the log file clearly had 24 lines.
**Cause:** Two layered issues:
1. Filebeat keeps an internal **registry** (a bookmark of exactly how far it's read into each file). A `restart` does not clear this — only fully recreating the container does. Since the container had briefly seen the file before, it believed it had already finished reading it.
2. Separately, Docker Desktop's bind-mount file sharing on macOS can have a timing lag where a freshly-mounted file appears incomplete or empty to the container for the first few seconds.

**Fix:** Force-remove and recreate the Filebeat container specifically (`docker rm -f filebeat01 && docker compose up -d filebeat`) after confirming via `docker exec filebeat01 cat <file> | wc -l` that the file was actually fully visible inside the container.

### 5.3 Every document rejected with HTTP 400 — reserved ECS field names
**Symptom:** Filebeat logs showed `"dropped":24` — every single event was being sent but rejected by Elasticsearch.
**Cause:** The custom grok pattern extracted fields named `host`, `process`, and `user`. These exact names are reserved as **object** fields in Elasticsearch's default ECS (Elastic Common Schema) index template (e.g. `host` is expected to be `{name: ..., ip: ...}`, not a plain string). Writing a flat string into a field the template requires to be an object causes a mapping conflict and the whole document is rejected. **Fix:** Renamed the colliding fields to non-reserved names: `host` → `log_host`, `process` → `process_name`, `pid` → `process_pid`, `user` → `user_name`.

**This was diagnosed by bypassing Filebeat entirely** and sending a single test document directly to the ingest pipeline via `curl POST .../_doc?pipeline=...` — this surfaces Elasticsearch's actual error message, which Filebeat's own logs never show in full.

### 5.4 Events still dropped after the field-name fix — data stream auto-setup
**Symptom:** Same `dropped` pattern persisted even after fixing the field names.
**Cause:** A completely separate issue: Filebeat, on startup, attempts to auto-register an Elasticsearch **data stream** matching its configured template name. No matching index template existed for this data stream naming pattern, so Elasticsearch rejected the setup step with `"no matching index template found for data stream [siem-auth-logs]"` — and Filebeat refused to send any events until this succeeded.
**Fix:** Set `setup.template.enabled: false` in `filebeat.yml`, since the pipeline was already being managed manually via the ingest pipeline API — Filebeat's own auto-setup wasn't needed and was actively blocking writes.

### 5.5 Kibana refused to save alert rules
**Symptom:** Rule creation failed / rules feature inaccessible.
**Cause:** Kibana's Alerting feature encrypts rule definitions at rest and requires a stable encryption key (`xpack.encryptedSavedObjects.encryptionKey`) to be configured — without one, the feature can't function.
**Fix:** Generated a 32-character key with `openssl rand -hex 16` and added it as an environment variable on the Kibana service in `docker-compose.yml`.

### 5.6 Data view disappeared after a stack reset
**Symptom:** Kibana's Discover page showed no saved data view after a `docker compose down -v`.
**Cause:** `down -v` removes Elasticsearch's data volume, which includes the `.kibana` index where Kibana stores its own saved objects (data views, dashboards, etc.) — a full volume wipe resets Kibana's configuration too, not just the log data.
**Fix:** Recreated the data view (`siem-auth-logs-*`, timestamp field `@timestamp`). Noted as an expected side effect of `-v` resets going forward, not a bug.

---

## 6. What I learned

- **ECS reserved field names are a real, non-obvious trap.** Any custom grok/parsing logic needs to actively avoid top-level names like `host`, `process`, `user`, `event`, `source`, and `agent` unless intentionally building the nested object structure ECS expects.
- **Beats registries persist across restarts, not just container recreation.** "Have I turned it off and on again" isn't enough when debugging ingestion — the internal read-position bookmark survives a restart and can silently mask a fix.
- **Error messages from an agent (Filebeat) are often incomplete.** The most efficient debugging move was bypassing the agent and talking to Elasticsearch directly via `curl`, which surfaces the real `mapper_parsing_exception` / `illegal_argument_exception` reason instead of a generic "status=400, dropping event."
- **Docker Desktop on macOS has real bind-mount timing quirks** that can masquerade as application-level bugs.
- **Kibana's advanced features (Alerting) have their own infrastructure prerequisites** (encryption keys) that aren't obvious from the UI alone.
- **`docker compose down -v` is a genuinely destructive operation** — it doesn't just reset "your data," it resets Kibana's own saved configuration too.

---

## 7. Current state

- ✅ Full pipeline operational: Filebeat → ingest pipeline → Elasticsearch → Kibana
- ✅ 24 synthetic auth events fully parsed into structured fields (`source_ip`, `user_name`, `event.outcome`, real `@timestamp`, etc.)
- ✅ Brute-force attack pattern (9 failed logins → 1 success → new account created) fully detectable via KQL in Discover
- ✅ Index Threshold alert rule live and validated against a simulated real-time attack (12 failed logins from a single IP in ~24 seconds)
- ⬜ Not yet done: a saved Kibana **dashboard** combining multiple visualizations (failed logins over time, top attacking IPs, sudo timeline)
- ⬜ Not yet done: alert action wired to something beyond the Server log connector (e.g. a webhook or email, for a more realistic response flow)

---

## 8. Possible next steps

- Build a saved dashboard for a single visual summary of the attack
- Add a second log source (e.g. nginx access logs) to demonstrate multi-source correlation
- Swap the Server log alert action for a webhook to show integration with an external system
- Add index lifecycle management (ILM) to demonstrate retention policy awareness, even in a local demo
