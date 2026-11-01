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
| 3 | Local account persistence + privilege escalation | T1136.001, T1098.007 | ✅ Yes (rules 5901, 5902, custom rule 100100) | [writeup](attack-detect-writeups/03-local-account-persistence-T1136.md) |

## Repo layout

```
architecture/            diagrams
attack-detect-writeups/  one markdown file per attack
detection-rules/         custom Wazuh / Sigma rules
screenshots/             alert evidence
```

## Detection rules

| Rule ID | Description | MITRE | Used in |
|---|---|---|---|
| [100100](detection-rules/100100-sudo-group-privilege-escalation.xml) | User added to sudo group - privilege escalation | T1098.007 | [writeup #3](attack-detect-writeups/03-local-account-persistence-T1136.md) |

## Scope and safety

All attacks target only VMs I own, on an isolated host-only network. No real systems, credentials or IPs are included in this repository.

## Author

Kartik Nagose | Aspiring SOC Analyst
