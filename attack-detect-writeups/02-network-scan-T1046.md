# Network Service Scanning (T1046)

## Objective

Run an Nmap reconnaissance scan against the lab host and test whether a
log-based Wazuh agent can detect it. Compare a service-detection scan
against pure stealth scans to find out exactly what is and isn't visible
to an agent that only reads host logs.

## Lab setup and scope

- **Attacker:** Parrot OS host, `192.168.56.1` (host-only network)
- **Target:** Ubuntu 22.04 VM `labvm`, `192.168.56.101`, Wazuh agent v4.14.8
  (intentionally left on its original, older package versions — a stale
  target gives more realistic attack surface for a lab, and avoids extra
  RAM/disk use on a resource-constrained host)
- **SIEM:** Wazuh manager/indexer/dashboard v4.14.8 on the Parrot host
- **Network:** isolated host-only network, no traffic left the laptop
- **Tool:** Nmap 7.95

## Attack steps

Three scan types were run against the same target to isolate what triggers
a log entry and what doesn't:

```bash
# 1. Service/version detection scan — connects to each port and reads
#    the service banner to identify software and version
sudo nmap -sV -T4 192.168.56.101

# 2. Null scan — sends packets with no flags set, a stealth technique
sudo nmap -sN -T4 192.168.56.101

# 3. SYN scan — "half-open" scan, never completes the TCP handshake
sudo nmap -sS -T4 192.168.56.101
```

### Results

| Scan | Ports found | Duration | Wazuh alert? |
|---|---|---|---|
| `-sV` (service detection) | 21 ftp (vsftpd 2.0.8+), 22 ssh (OpenSSH 8.9p1), 23 telnet, 631 ipp | 189s | **Yes — 2 alerts** |
| `-sN` (null/stealth) | Same 4 ports, reported `open\|filtered` | 1.52s | **No alerts** |
| `-sS` (SYN/half-open) | Same 4 ports, reported `open` | 0.38s | **No alerts** |

## Telemetry observed

Only the `-sV` scan produced any host-side log activity, and only for the
two ports where it had to actually open a connection to read the service
banner:

| Rule ID | Level | Description | Trigger |
|---|---|---|---|
| 11401 | 3 | vsftpd: FTP session opened | Nmap connected to port 21 to grab the FTP banner |
| 5602 | 3 | telnetd: Remote host established a telnet connection | Nmap connected to port 23 to grab the Telnet banner |

The `-sN` and `-sS` scans produced **zero** matching log entries in the
same time window — confirmed by querying `agent.name:labvm` for the scan's
timestamp and finding no new events.

## Detection

**No rule exists for "port scan detected" in this setup, because nothing
generated the telemetry a rule would need.** The two alerts that did fire
(11401, 5602) are not scan-detection rules at all — they are ordinary
"a client connected to this service" log lines that `vsftpd` and `telnetd`
would write for *any* connection, scan or legitimate. Wazuh had no way to
tell the difference between Nmap grabbing a banner and a real user logging
into FTP or Telnet.

## Triage verdict

**True negative on scan detection, not a false negative on the agent's
part — this is a visibility gap by design.** A Wazuh agent reads host-level
logs (`auth.log`, application logs, etc.). Raw network packets — SYN
packets, null-flag packets — are never written to a log file, so there is
nothing for the agent to read. This isn't a misconfiguration; it's the
fundamental limit of host-based (log-based) detection versus
network-based detection.

The two alerts that did fire are low-value on their own (level 3, routine
connection events) but become meaningful only with context: an FTP/Telnet
connection from an unfamiliar source IP (`192.168.56.1`, the attacker) in
quick succession with no further FTP/Telnet activity afterward is a weak
indicator of a scan, not a confirmed one.

## Response recommendation

- Disable Telnet entirely — a cleartext, unauthenticated-by-default
  protocol open on this host is a finding on its own, independent of the
  scan. If remote shell access is needed, SSH already covers it.
- Review whether FTP (vsftpd 2.0.8, an old version) is required; if not,
  disable it to shrink the attack surface shown by this scan.
- For actual scan detection, host logs are not enough — see tuning notes
  below.

## Tuning/hardening notes

- **This is the clearest evidence so far for the gap flagged in writeup
  #1:** an agent-only Wazuh deployment cannot see reconnaissance activity
  at the network layer. Detecting a port scan requires inspecting traffic
  directly — a network IDS/IPS (Suricata or Snort) sitting on the network
  path, not just an endpoint agent. This is the next logical addition to
  this lab.
- A possible partial mitigation without adding new tooling: Wazuh's
  `active-response` can block an IP after repeated connection attempts in
  a short window, which would at least slow down a `-sV`-style scan (since
  it does leave log traces) — would not help against `-sN`/`-sS` at all.
- Practical takeaway for interviews: "no alert fired" during a port scan
  is not automatically a detection failure — the first question is always
  *what telemetry source could have seen this at all*, before asking why a
  rule didn't fire.
