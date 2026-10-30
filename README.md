# SOC Home Lab: Purple Team

A hands-on lab where I attack my own systems from Parrot OS and detect, triage and document each attack in Wazuh.

> Status: Phase 1 in progress. Writeups are added as each attack/detect pair is completed.

## Architecture

```
                 Host-only network 192.168.56.0/24
  +-----------+        +----------------+        +----------------+
  | Parrot    | -----> | Ubuntu VM       | -----> | Wazuh server    |
  | attacker  |        | (SSH, agent)    |        | (on host)       |
  +-----------+        +----------------+        +----------------+
```

*Replace this diagram with a screenshot or draw.io export in `architecture/`.*

## Tools

| Role | Tool |
|---|---|
| SIEM / XDR | Wazuh (manager, indexer, dashboard on host; agent on VM) |
| Attack simulation | nmap, hydra |
| Framework | MITRE ATT&CK |

## Attack and detection writeups

| # | Technique | ATT&CK | Detected | Writeup |
|---|---|---|---|---|
| 1 | SSH brute force | T1110, T1110.001 | ✅ Yes (rules 5710, 5712, 40112) | [writeup](attack-detect-writeups/01-ssh-brute-force-T1110.md) |
| 2 | Network service scan | T1046 | ⚠️ Partial (visibility gap documented) | [writeup](attack-detect-writeups/02-network-scan-T1046.md) |

## Repo layout

```
architecture/            diagrams
attack-detect-writeups/  one markdown file per attack
detection-rules/         custom Wazuh / Sigma rules
screenshots/             alert evidence
```

## Scope and safety

All attacks target only VMs I own, on an isolated host-only network. No real systems, credentials or IPs are included in this repository.

## Author

Kartik Nagose | Aspiring SOC Analyst
