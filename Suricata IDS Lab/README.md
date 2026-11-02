# Suricata IDS Lab — SSH Brute Force, Recon & Web Scanning

> **Environment:** Kali attacker VM (`192.168.64.128`) → Ubuntu sensor/target VM (`suricata-lab`, `192.168.64.131`) on VMware Workstation NAT
>
> Authorized academic / self-study lab only. Do not run Hydra, Nmap, or Nikto against systems you do not own or lack explicit permission to test.

Controlled detection lab: Suricata (ET Open + local rules) alerts on three attacker techniques, with evidence export, a NIST SP 800-61r3-shaped incident report, and a detection-evaluation section (positive tests, negative controls, false positives).

---

## 1. Summary

- Built a **two-VM IDS lab** (Kali → Ubuntu + Suricata + Apache). Sensor liveness confirmed via live alerts on `ens33` (external `testmynids.org` was unavailable on the lab day).
- Detected **SSH password guessing** (Hydra) via ET Open SIDs **2001219**, **2006546** + local SID **1000002**, corroborated with `/var/log/auth.log` (**27** Failed password, **5** Accepted — account `ubuntu` cracked).
- Ran **Nmap** recon (SYN + NSE) and documented which ET scan SIDs still fire vs are commented out upstream; filled the SYN-scan gap with local SID **1000001**. NSE UA fired local **1000003** + ET **2009358**.
- Detected **web scanning** (curl + Nikto 2.6.1) via payload/behavior SIDs **1000005–1000008** and ET **2002825**. Nikto UA SIDs (**1000004**, ET **2002677**) stayed at **0** because Nikto 2.6.1 spoofs a Chrome-on-Windows User-Agent — written up as a detection-engineering finding.
- Produced a structured **incident report** (`reports/incident-report.md`) with timeline, evidence placeholders, MITRE ATT&CK mapping, and detection-gap analysis.

---

## 2. Results matrix

| Scenario | Tool | Expected SID(s) | Result | Notes |
|----------|------|-----------------|--------|-------|
| Baseline | `testmynids.org` | 2100498 | **SKIPPED** | External site down / mis-resolved; sensor proven via DHCP alert on `ens33` |
| SSH brute | Hydra `-t 1 -W 2` | 2001219, 2006546, 1000002 | **PASS** | Login succeeded (`ubuntu`); `-t 4` rate-limited |
| Nmap SYN | `nmap -sS -p 1-200` | 1000001 | **PASS** | 0 ET SYN SIDs (gap; local fills it) |
| Nmap NSE | `nmap --script http-headers` | 2009358, 1000003 | **PASS** | |
| Nikto UA | `nikto -h …` | 2002677, 1000004 | **FAIL** | Chrome UA spoof; payloads still detected |
| curl UA / GET burst | curl loop | 1000005, 1000006, 2002825 | **PASS** | 1 / 4 / 1 hits |
| Traversal / XSS pattern | curl + Nikto | 1000007, 1000008 | **PASS** | 284 / 271 hits |

Negative controls: single SSH login + Mozilla curl — **PASS** (no new scan/brute SIDs); details in incident report §10.2.

---

## 3. Architecture

```
[ Kali Linux 192.168.64.128 ] ---- VMware NAT ----> [ Ubuntu suricata-lab 192.168.64.131 ]
   ATTACKER                                              Suricata (AF_PACKET ens33) + Apache :80 + OpenSSH :22
                                                         HOME_NET = [192.168.64.131/32]
```

**HOME_NET is the victim VM only** (`/32`), so Kali falls into `EXTERNAL_NET`. A `/24` that includes Kali silently disables every `$EXTERNAL_NET → $HOME_NET` rule.

---

## 4. Quick start

```bash
# On Ubuntu sensor
sudo cp rules/local.rules /etc/suricata/rules/local.rules
# suricata.yaml: HOME_NET = "[192.168.64.131/32]"; af-packet.interface = ens33; rule-files includes local.rules
sudo ethtool -K ens33 gro off lro off
sudo suricata-update
sudo suricata -T -c /etc/suricata/suricata.yaml
sudo systemctl restart suricata

# On Kali
hydra -L lab-users.txt -P lab-pass.txt -t 1 -W 2 -f ssh://192.168.64.131
sudo nmap -sS -p 1-200 192.168.64.131
sudo nmap -p 80 --script http-headers 192.168.64.131
nikto -h http://192.168.64.131 -maxtime 120s

# Collect
mkdir -p evidence
sudo jq -c 'select(.event_type=="alert" and .dest_port==22)' /var/log/suricata/eve.json > evidence/ssh-alerts.json
sudo grep -E 'Failed password|Invalid user|Accepted' /var/log/auth.log > evidence/ssh-auth.log
sha256sum evidence/* > evidence/SHA256SUMS
```

---

## 5. Repo layout

```
config/                 # sanitized suricata.yaml excerpts
rules/local.rules       # SIDs 1000001–1000008
scenarios/              # optional attack scripts
reports/incident-report.md
evidence/               # alerts, auth.log extract, screenshots/, SHA256SUMS
docs/scenario-runbook.md
docs/incident-report-template.md
scripts/extract-alerts.sh
README.md
```

---

## 6. Key lessons (short)

1. Network SSH rules see **connections**, not passwords — correlate with `/var/log/auth.log`.
2. Ubuntu 26.04 logs SSH as `sshd-session`; `journalctl -u ssh` can look empty.
3. Pure `nmap -sS` gets no ET alert today; local **1000001** covers the gap.
4. Do not trust User-Agent detection alone — modern Nikto spoofs Chrome.
5. Set the VM timezone to `Asia/Singapore` before capturing evidence.

Full write-up: [`reports/incident-report.md`](reports/incident-report.md).

---

## 7. Safety

Authorized home lab only. No external targets. Credentials used were lab-only weak passwords on a disposable Ubuntu guest.
