# Local Account Creation & Privilege Escalation (T1136.001, T1098.007)

## Objective

Simulate the step an attacker takes *after* an initial compromise: create a
backdoor account for persistence, then escalate it to root-equivalent
access. Test what Wazuh detects out of the box using File Integrity
Monitoring (FIM) and log-based rules, find any coverage gap, and — unlike
the network-visibility gap in writeup #2 (which needed a new tool) — close
this gap myself by writing a custom Wazuh detection rule.

This continues the writeup #1 story: Hydra cracked `cisco`/`password` via
SSH brute force. A real attacker's next move is to stop depending on that
one cracked credential — so they create their own account.

## Lab setup and scope

- **Attacker (simulating a post-compromise actor):** shell access on the
  VM, as if already authenticated as `cisco` from writeup #1
- **Target:** Ubuntu 22.04 VM `labvm`, `192.168.56.101`, Wazuh agent v4.14.8
- **SIEM:** Wazuh manager/indexer/dashboard v4.14.8 on the Parrot host
- **Network:** isolated host-only network, no traffic left the laptop
- **FIM config change:** `/etc` set to `realtime="yes"` in the agent's
  `<syscheck>` block (default is a 12-hour scheduled scan — too slow for a
  live demo) so file changes under `/etc` are detected within seconds

## Attack steps

```bash
# 1. Create a backdoor account with a home directory and a login shell
sudo useradd -m -s /bin/bash svc-backup

# 2. Set its password
sudo passwd svc-backup

# 3. Escalate it to root-equivalent access
sudo usermod -aG sudo svc-backup
```

The account name (`svc-backup`) was deliberately chosen to look like a
legitimate service account — basic defense evasion so it doesn't stand out
in a user list.

## Telemetry observed

**Raw `auth.log` lines** (collected by the agent, same log source as
writeup #1):

```
useradd[4137]: new group: name=svc-backup, GID=1009
useradd[4137]: new user: name=svc-backup, UID=1009, GID=1009, home=/home/svc-backup, shell=/bin/bash, from=/dev/pts/1
passwd[4153]: pam_unix(passwd:chauthtok): password changed for svc-backup
usermod[4186]: add 'svc-backup' to group 'sudo'
usermod[4186]: add 'svc-backup' to shadow group 'sudo'
```

**FIM (syscheck) activity:** `useradd` and `usermod` don't edit `/etc/passwd`,
`/etc/shadow` and `/etc/group` in place — they write a temp file and
`rename()` it over the original (atomic write, so a crash mid-write can't
corrupt the file). Syscheck sees this as the old inode being **deleted**
and a new one being **added**, not a simple "modified" — so each command
produced a `File deleted` + `File added` + `Integrity checksum changed`
triplet rather than one clean "modified" event.

## Detection

| Rule ID | Level | Description | Trigger | MITRE |
|---|---|---|---|---|
| 5901 | 8 | New group added to the system | `useradd -m` auto-creates a matching group | T1136.001 |
| 5902 | 8 | New user added to the system | `useradd` creates the account | T1136.001 |
| 5555 | 3 | PAM: User changed password | `passwd svc-backup` | T1136.001 |
| 5402 | 3 | Successful sudo to ROOT executed | every command above needed `sudo` | — |
| 5501/5502 | 3 | PAM session opened/closed | sudo session wrapper around each command | — |
| 550 | 7 | Integrity checksum changed (FIM) | `/etc/passwd`, `/etc/shadow`, `/etc/group` content changes | — |
| 553 | 7 | File deleted (FIM) | atomic rename artifact (see above) | — |
| 554 | 5 | File added to the system (FIM) | atomic rename artifact (see above) | — |
| **100100 (custom)** | **12** | **User added to sudo group - privilege escalation** | `usermod -aG sudo svc-backup` | **T1098.007** |

Before rule 100100 was added, **the `usermod -aG sudo` step — the actual
privilege escalation — produced no semantic alert at all.** It only showed
up as generic FIM noise (rule 550, level 7) on `/etc/group`, identical in
shape to a routine config change. Verified live after deployment: the same
command fired rule 100100 at level 12.

## Triage verdict

**True positive, but the default severity ranking is misleading.** Account
creation (rules 5901/5902) tops out at level 8 ("medium" in most SOC
triage conventions), *lower* than the confirmed SSH compromise in writeup
#1 (rule 40112, level 12) — even though creating a persistent backdoor
account is arguably a bigger long-term risk than one cracked password,
since it survives a password rotation on the original account.

Worse: the single most dangerous action in this whole sequence —
escalating that backdoor account to root via the `sudo` group — had **zero
dedicated detection** in the default ruleset. An analyst triaging by
severity level alone, or alerting only on levels 10+, would have caught
the account creation but missed the privilege escalation entirely, buried
in routine-looking FIM noise.

## Response recommendation

- Immediately disable/remove the `svc-backup` account and audit `/etc/sudoers`
  and the `sudo` group membership for any other unauthorized entries.
- Rotate the `cisco` account password (already flagged in writeup #1) —
  this account creation only happened *because* that credential was weak.
- Restrict who can run `useradd`/`usermod`/`gpasswd` via `sudoers` — most
  users should never need these.
- Periodically audit `/etc/group` and `/etc/passwd` for accounts outside
  of an approved baseline, not just rely on real-time alerts.

## Detection engineering: closing the gap

Rather than just documenting the gap (as in writeup #2), I wrote and
deployed a custom Wazuh rule to close it — [`detection-rules/100100-sudo-group-privilege-escalation.xml`](../detection-rules/100100-sudo-group-privilege-escalation.xml).

Process:
1. Found the exact log line `usermod` writes (`grep` on `auth.log`) instead
   of guessing a regex.
2. Wrote a rule matching on the pre-decoded `program_name` field
   (`usermod`) plus the literal text `to group 'sudo'` — deliberately
   excluding the companion `to shadow group 'sudo'` line so one action
   doesn't double-alert.
3. Validated with `wazuh-logtest` against the real log line before
   touching the live ruleset.
4. Deployed to `/var/ossec/etc/rules/local_rules.xml` on the manager,
   restarted `wazuh-manager`, then re-triggered the attack
   (`gpasswd -d` to remove, `usermod -aG sudo` to re-add) and confirmed a
   live alert at level 12.

## Tuning/hardening notes

- **MITRE mapping correction:** the rule was first tagged `T1098.003`
  ("Additional Cloud Roles") — wrong, since that sub-technique is
  cloud-IAM-specific. Corrected to `T1098.007` ("Additional Local or
  Domain Groups"), which matches this exact scenario — adding an account
  to a privileged local group.
- **Wider takeaway:** a mature SOC can't assume a SIEM's default ruleset
  covers every critical system change just because *some* related activity
  (account creation) is covered. Coverage should be audited action-by-action
  against what a real attacker's playbook looks like, not assumed from a
  vendor's defaults.
- Possible follow-up: the current rule only matches the exact string
  `to group 'sudo'`. A more robust version would also catch `wheel` (the
  equivalent privileged group on RHEL-based systems) and use a regex
  instead of a literal match for portability across distros.
