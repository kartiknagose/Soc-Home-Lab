# SOC Home Lab: Purple Team

A hands-on detection lab where I attack my own systems from Parrot OS, then detect, triage and document each attack in **Wazuh** (SIEM/XDR), mapping every finding to **MITRE ATT&CK**.

**Result so far:** 3 attack-and-detect cycles completed, 1 custom detection rule written and deployed, 1 detection gap documented with a recommended fix.

## Architecture

![Lab architecture](architecture/lab-architecture.svg)

| Component | Details |
|---|---|
| Attacker | Parrot OS, `192.168.56.1` |
| Target | Ubuntu 22.04 VM (`labvm`, `192.168.56.101`) with Wazuh agent v4.14.8 |
| SIEM / XDR | Wazuh manager, indexer and dashboard v4.14.8 (on the Parrot host) |
| Network | Isolated VirtualBox host-only network `192.168.56.0/24` |
| Attack tools | Hydra 9.5, Nmap 7.95 |

## Attack and detection writeups

| # | Technique | ATT&CK | Outcome | Writeup |
|---|---|---|---|---|
| 1 | SSH brute force | T1110, T1110.001 | Detected. Rules 5710, 5712 and 40112 (level 12, success after failures) fired | [Read](attack-detect-writeups/01-ssh-brute-force-T1110.md) |
| 2 | Network service scan | T1046 | Partial. Only the `-sV` scan left log traces; SYN and NULL scans were invisible to a host agent (gap documented) | [Read](attack-detect-writeups/02-network-scan-T1046.md) |
| 3 | Local account persistence and privilege escalation | T1136.001, T1098 | Detected. Rules 5901, 5902 and custom rule 100100 (written by me to close a gap) | [Read](attack-detect-writeups/03-local-account-persistence-T1136.md) |

## Key findings

- **Same attack, different alerts.** A brute force against a non-existent user only reaches rule 5712 (level 10). Against a real account with a weak password it escalates to rule 40112 (level 12), because the compromise is confirmed.
- **No alert does not mean the agent failed.** A log-based agent cannot see SYN or NULL scans because they never write a log line. Detecting them needs a network IDS (Suricata or Snort).
- **Default coverage has holes.** Wazuh alerted on account creation but had no dedicated alert for `usermod -aG sudo`, the actual privilege escalation. I wrote rule 100100 to close it and verified it live.

## Detection rules

| Rule ID | Description | MITRE | Used in |
|---|---|---|---|
| [100100](detection-rules/100100-sudo-group-privilege-escalation.xml) | User added to sudo group (privilege escalation), level 12 | T1098 (T1098.007 is more precise but is not in the Wazuh 4.14.8 MITRE database) | [Writeup 3](attack-detect-writeups/03-local-account-persistence-T1136.md) |

## Skills demonstrated

SIEM alert triage, log analysis (`auth.log`), File Integrity Monitoring, detection engineering (custom Wazuh rules, `wazuh-logtest`), MITRE ATT&CK mapping, true/false positive analysis, incident-style reporting with response recommendations.

## Repository layout

```
architecture/            lab diagram
attack-detect-writeups/  one markdown file per attack
detection-rules/         custom Wazuh rules
screenshots/             alert evidence
```

## Next steps

- Add a network IDS (Suricata) to detect the port scans that the Wazuh agent cannot see (follow-up from writeup 2).
- Extend rule 100100 to cover the `wheel` group and use a regex for portability across distributions.

## Scope and safety

All attacks target virtual machines I own, on an isolated host-only network with no route to the internet or to other devices. Credentials shown in the writeups are throwaway lab credentials. No real systems, accounts or IP addresses are included.

## Author

**Kartik Nagose**, entry-level SOC analyst candidate
[LinkedIn](https://www.linkedin.com/in/kartik-nagose-852b543a4) | [GitHub](https://github.com/kartiknagose) | kartiknagose1@gmail.com
