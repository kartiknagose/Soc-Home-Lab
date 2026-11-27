# Elastic Cloud SSH Brute Force Detection

A cloud-SIEM counterpart to the Wazuh lab in this repo: same scenario (SSH brute force), different stack — **Elastic Security on Elastic Cloud (Serverless)**, log shipping via **Elastic Agent**, detection with **KQL** instead of Wazuh's rule engine.

## Goal

Show, end to end, that I can stand up a cloud SIEM from scratch, ship real OS auth logs into it, generate an actual attack against my own lab, find it with a query, and turn that query into a standing detection rule — not just read about SIEM concepts.

## Architecture

| Component | Details |
|---|---|
| Attacker | Parrot OS, host-only network |
| Target | Ubuntu 22.04 VM (`labvm`), `/var/log/auth.log` |
| SIEM | Elastic Security (Elastic Cloud Serverless, Security project, GCP Mumbai region) |
| Shipping | Elastic Agent (Fleet-managed), **System** integration + custom **Filestream** integration on `/var/log/auth.log` |
| Attack tool | Hydra 9.5 (SSH password brute force, authorized self-attack only) |

## What I did

1. Created an Elastic Cloud Serverless **Security** project (no credit card required for the trial).
2. Enrolled an Elastic Agent on the Ubuntu VM via Fleet, with the **System** integration (covers `/var/log/auth.log`, `/var/log/syslog`) plus a custom **Custom Logs (Filestream)** integration pointed directly at `/var/log/auth.log`.
3. Confirmed log flow in **Discover** (`logs-system.auth-default` data stream populated, documents visible within minutes of enrollment).
4. From Parrot OS, ran Hydra against the VM's SSH service (own lab VM, authorized, host-only network — no route outside the lab).
5. Queried the failed attempts in Discover using KQL / ES|QL, filtering on `event.outcome: "failure"`.
6. Built a custom detection rule (see `detection-rule.ndjson`) that fires on repeated SSH auth failures, and verified it alerts against the Hydra-generated data.

## Query used (Discover)

```
FROM logs-system.auth-default
| WHERE event.outcome == "failure" AND system.auth.ssh.method == "password"
| KEEP @timestamp, user.name, source.ip, host.hostname, message
| SORT @timestamp DESC
```

## Detection rule

- **Type:** Custom query
- **Name:** SSH Brute Force - Repeated Auth Failures
- **Query:** `event.dataset: "system.auth" and event.outcome: "failure"`
- **Schedule:** runs every 5 minutes, 1-minute additional look-back
- **MITRE ATT&CK:** Credential Access (TA0006) → Brute Force (T1110)
- **Status:** live-verified — fired **46 alerts** against a Hydra SSH brute-force run from Parrot OS (see `screenshots/02-rule-execution-46-alerts.png` and `screenshots/03-alerts-trend-confirmed.png`)
- Rule definition: [`detection-rule.ndjson`](detection-rule.ndjson)

## Screenshots

- `00-agent-healthy.png` — Elastic Agent enrolled and healthy in Fleet
- `01-discover-failed-ssh-logins.png` — failed SSH logins visible in Discover, source IP attributed to the Parrot attacker box
- `02-rule-execution-46-alerts.png` — rule execution log showing a successful run that created 46 alerts
- `03-alerts-trend-confirmed.png` — Alerts tab confirming the 46 alerts, stacked by event category

## What I'd improve with more time

- Narrow the detection rule with a threshold (e.g. 5+ failures from the same source IP in 5 minutes) instead of alerting on every single failure, to cut noise.
- Add a second rule for the follow-on successful login after a run of failures (the actual compromise indicator), mirroring the Wazuh lab's rule 40112.
- Build a simple dashboard panel (failed vs. successful auth count over time) instead of relying only on Discover.
- Tag the rule to a MITRE ATT&CK technique (T1110 / T1110.001) directly in the rule's metadata.

## Scope and safety

Attack run entirely against a VM I own, on an isolated VirtualBox host-only network, authorized self-testing only. No production systems, real credentials, or external targets involved.
