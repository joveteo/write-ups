# Suricata Lab: Scenario Runbook (Fri 23 Oct 2026, 1:00–5:00pm SGT)

**Lab topology (assumed):** Kali attacker VM → Ubuntu VM running Suricata (both on your 64GB laptop). Authorized home lab only.
**Already done:** Suricata setup, `testmynids` alert, Hydra SSH brute-force scenario (finish/confirm alerts tomorrow).
**GitHub:** No existing Suricata lab repo under `joveteo` (see `../GITHUB-NOTE.md`). Use the layout in `README-draft.md`.

Replace placeholders:
- `ATTACKER_IP`: Kali IP on the lab net
- `TARGET_IP`: Ubuntu victim / monitored host IP
- `IFACE`: Suricata capture interface (e.g. `enp0s3`, `ens33`)
- `HOME_NET`: **victim VM only**, e.g. `"[192.168.56.20/32]"`, so Kali falls into `EXTERNAL_NET` *(Perplexity recommendation; changed from the earlier /24 advice, because with a /24 Kali is also "home" and every `$EXTERNAL_NET -> $HOME_NET` rule stays silent)*
- `EVE`: typically `/var/log/suricata/eve.json`

**Source tags used in this file**
- **[VERIFIED-ET]**: checked against the live ET Open `emerging-scan.rules` / `emerging-policy.rules`, re-fetched 22 Oct 2026 ~11:45pm SGT.
- **[VERIFIED-TEST]**: fired (or did not fire) in a synthetic loopback replay on Grok Bot's box: Suricata 7.0.10, ET Open via `suricata-update` + `rules/local.rules`, traffic 127.0.0.10 → 127.0.0.20. Not your VMs, so re-confirm on the lab.
- **[PPLX]**: comes only from the Perplexity research pass (GPT-6.1 Sol Thinking, 22 Oct 2026); not independently verified.

---

## Timeline (stick to this)

| Block | Time | Goal |
|-------|------|------|
| A | 1:00–1:30 | Verify setup + local rules + confirm Hydra SSH alerts |
| B | 1:30–2:45 | Nmap recon, then web scan (curl + nikto) |
| (break) | 2:45–3:00 | Break |
| C | 3:00–4:15 | Draft incident report |
| D | 4:15–5:00 | README + GitHub push |

---

## Block A: 1:00–1:30, verify setup + Hydra

### A1. Suricata healthy + seeing the right NIC (Ubuntu)

```bash
sudo systemctl status suricata --no-pager
ps -ww -C suricata -o args=          # actual command line: which -i / --af-packet interface?  [PPLX]
ip -br address                       # which interface holds TARGET_IP?                          [PPLX]
sudo tcpdump -ni IFACE -c 20 host ATTACKER_IP   # packets from Kali really reach this NIC        [PPLX]
grep -nE 'HOME_NET|EXTERNAL_NET' /etc/suricata/suricata.yaml | head
grep -n -A12 '^af-packet' /etc/suricata/suricata.yaml
sudo suricatasc -c uptime
sudo suricatasc -c ruleset-stats     # rules_loaded / rules_failed

# live views
sudo tail -f /var/log/suricata/fast.log
sudo tail -f /var/log/suricata/eve.json | jq -c 'select(.event_type=="alert") | {t:.timestamp,sid:.alert.signature_id,msg:.alert.signature,src:.src_ip,dst:.dest_ip}'
```

Expected `suricata.yaml` bits:

```yaml
vars:
  address-groups:
    HOME_NET: "[192.168.56.20/32]"     # victim VM only [PPLX]
    EXTERNAL_NET: "!$HOME_NET"

af-packet:
  - interface: IFACE
    cluster-id: 99
    cluster-type: cluster_flow         # [PPLX] (also the Debian/Ubuntu default)
    defrag: yes
    tpacket-v3: yes                    # [PPLX]

unix-command:
  enabled: yes                         # needed for suricatasc reloads [PPLX]
```

**GRO/LRO (VM NICs):** checksum offload is generally fine on AF_PACKET *[PPLX]*, but GRO/LRO merge packets into "super-frames" and confuse stream reassembly. Check, then turn them off:

```bash
ethtool -k IFACE | grep -E 'generic-receive-offload|large-receive-offload'
sudo ethtool -K IFACE gro off lro off      # [PPLX]; not persistent across reboot
```

### A2. Install the local rules + reload (new)

```bash
sudo cp rules/local.rules /etc/suricata/rules/local.rules
# suricata.yaml: add under rule-files:
#   - /etc/suricata/rules/local.rules
```

**Reload sequence (use this every time rules change)** *[PPLX; commands checked on Suricata 7.0.10]*:

```bash
sudo suricata-update                                     # 1. refresh ET Open → /var/lib/suricata/rules/suricata.rules
sudo suricata -T -c /etc/suricata/suricata.yaml -v       # 2. config + rule syntax test (must say "successfully loaded")
sudo suricatasc -c ruleset-reload-nonblocking            # 3. live reload, no restart
sudo suricatasc -c ruleset-reload-time                   #    confirm the reload happened
sudo suricatasc -c ruleset-stats
```

- **Interface or af-packet changes need a full restart:** `sudo systemctl restart suricata` *[PPLX]*.
- `kill -USR2 $(pidof suricata)` also triggers a rule reload (older method).

The 8 local rules (`rules/local.rules`, SIDs 1000001–1000008) passed `suricata -T` and each one fired once in the loopback replay **[VERIFIED-TEST]**:

| SID | Detects | Threshold |
|-----|---------|-----------|
| 1000001 | TCP SYN rate (port scan) | 20 SYN / 10s by_src |
| 1000002 | SSH connection burst to :22 | 5 SYN / 60s by_src |
| 1000003 | HTTP UA contains `Nmap` | none |
| 1000004 | HTTP UA contains `Nikto` | limit 1/min |
| 1000005 | HTTP UA starts `curl/` (info) | limit 1/min |
| 1000006 | HTTP GET burst | 20 GET / 10s by_src |
| 1000007 | `../`, `..\`, `%2e%2e%2f` in **raw** URI | none |
| 1000008 | `<script` in (decoded) URI | none |

### A3. Regression: testmynids

```bash
curl -s http://testmynids.org/uid/index.html
jq -c 'select(.event_type=="alert" and .alert.signature_id==2100498)' "$EVE"
```

Expected: SID **2100498** `GPL ATTACK_RESPONSE id check returned root`. Note this one is outbound/response traffic, so it only fires if the victim itself runs the curl.

### A4. Hydra SSH brute force (finish + confirm)

```bash
# Kali: small lists so it finishes quickly
printf 'root\nadmin\nubuntu\n' > /tmp/users.txt
printf 'password\n123456\ntoor\nadmin\n' > /tmp/pass.txt
hydra -L /tmp/users.txt -P /tmp/pass.txt -t 4 -W 1 -f ssh://TARGET_IP
```

```bash
# Ubuntu: network view
jq -c 'select(.event_type=="alert" and .dest_port==22)' "$EVE" \
  | jq -s 'group_by(.alert.signature_id) | map({sid:.[0].alert.signature_id, msg:.[0].alert.signature, n:length})'
# Host view: correlate with sshd (the network rules can't see passwords) [PPLX]
sudo journalctl -u ssh --since "13:00" | grep -E 'Failed password|Invalid user|Accepted' | tail -40
sudo journalctl -u ssh --since "13:00" | grep -c 'Failed password'
```

| SID | Message | Status |
|-----|---------|--------|
| **2001219** | `ET SCAN Potential SSH Scan` | **[VERIFIED-ET]** active; `flags:S,12`, 5 SYN / 120s by_src to `$HOME_NET 22`. **[VERIFIED-TEST]** fired |
| **1000002** | `LOCAL LAB SSH connection burst` | local, 5 SYN / 60s. **[VERIFIED-TEST]** fired |
| 2006546 | `ET SCAN LibSSH Based Frequent SSH Connections…` | **[VERIFIED-ET]** active, but needs `libssh` in the client banner, so it may not fire for Hydra |
| 2011497 | `ET SCAN Hydra User-Agent` | **[VERIFIED-ET]** active but **HTTP only**, so it will not fire on SSH |

**No ET Open rule detects failed SSH passwords**, since SSH is encrypted *[PPLX; consistent with the ET check]*. Both alerts count **connection attempts**, not guesses, so the `journalctl` count is your proof of password guessing.

```bash
jq -c 'select(.event_type=="alert") | select(.dest_port==22)' "$EVE" > ~/lab/evidence/eve-alerts-hydra.json
sudo journalctl -u ssh --since "13:00" > ~/lab/evidence/sshd-auth.log
```

**MITRE:** T1110.001 Brute Force: Password Guessing; T1021.004 Remote Services: SSH.

---

## Block B: 1:30–2:45, Nmap then web scan

**Negative control first (2 min)** *[PPLX]*: one normal `ssh user@TARGET_IP` login and one `curl -A "Mozilla/5.0" http://TARGET_IP/`. Record that no scan/brute alerts fired. Your report needs this to claim the rules aren't just noisy.

### B1. Nmap (Kali)

Test set *[PPLX]*:

```bash
sudo nmap -sS -p 1-200 TARGET_IP                               # → 1000001 (SYN rate)
sudo nmap -sV -p 22,80 TARGET_IP                               # → service probes; may also trip 2001219 on :22
sudo nmap -p 80 --script http-headers TARGET_IP                # → 2009358 + 1000003 (NSE User-Agent)
```

| SID | Message | Status |
|-----|---------|--------|
| **2009358** | `ET SCAN Nmap Scripting Engine User-Agent Detected (Nmap Scripting Engine)` | **[VERIFIED-ET]** active; **[VERIFIED-TEST]** fired |
| 2009359 | `… (Nmap NSE)` | **[VERIFIED-ET]** active |
| 2018489 | `ET SCAN NMAP OS Detection Probe` | **[VERIFIED-ET]** active; needs `-O` |
| 2024364 | `ET SCAN Possible Nmap User-Agent Observed` | **[VERIFIED-ET] direction is `$HOME_NET -> any` (outbound)**, so it **won't fire for Kali → victim** (correction to the earlier draft) |
| 2000537, 2009582–2009584 | `ET SCAN NMAP -sS window *` | **[VERIFIED-ET] commented out**, so plain `-sS` gets no ET alert |
| **1000001 / 1000003** | local SYN rate / Nmap UA | **[VERIFIED-TEST]** fired |

```bash
jq -c 'select(.event_type=="alert") | select(.alert.signature|test("Nmap|NMAP|SCAN|SYN";"i"))' "$EVE" > ~/lab/evidence/eve-alerts-nmap.json
```

**MITRE:** T1046 Network Service Discovery; T1595.001 Active Scanning.

### B2. Web scan: curl then Nikto

Web server on Ubuntu: `sudo apt-get install -y apache2` (preferred). Note that `python3 -m http.server` also trips `ET INFO Python SimpleHTTP ServerBanner` (2034636) on every response **[VERIFIED-TEST]**, which adds noise.

```bash
# Kali: curl tests [PPLX]
curl -v http://TARGET_IP/                                            # → 1000005 (curl UA, info)
curl -s --path-as-is "http://TARGET_IP/../../etc/passwd"             # → 1000007 (+ ET 2049400)
curl -s "http://TARGET_IP/search?q=%3Cscript%3Ealert(1)%3C/script%3E" # → 1000008 (+ ET 2009714)
for i in $(seq 1 25); do curl -s -o /dev/null "http://TARGET_IP/p$i"; done   # → 1000006 (GET burst); 10+ in 60s also → ET 2002825

# Kali: Nikto, default UA then custom UA [PPLX]
nikto -h http://TARGET_IP -maxtime 5m -o /tmp/nikto-default.txt     # → 2002677 + 1000004
nikto -h http://TARGET_IP -maxtime 3m -useragent "Mozilla/5.0" -o /tmp/nikto-customua.txt
#   (check the flag with `nikto -H`; with a custom UA the UA rules should NOT fire, but 1000006 still should. That shows the evasion point)
```

| SID | Message | Status |
|-----|---------|--------|
| **2002677** | `ET SCAN Nikto Web App Scan in Progress` | **[VERIFIED-ET]** active; UA `(Nikto`, **5 hits / 60s** by_src (one request doesn't fire it, **[VERIFIED-TEST]**) |
| 2011390 | `ET SCAN Nikto Scan Remote File Include Retrieval` | listed previously; only if Nikto fetches cirt.net rfiinc |
| 2002825 | `ET POLICY/INFO POSSIBLE Web Crawl using Curl` | **[VERIFIED-ET]** active, inbound, **10 curl requests / 60s** (single curl didn't fire, **[VERIFIED-TEST]**) |
| 2013028 | `ET POLICY curl User-Agent Outbound` | **[VERIFIED-ET] commented out + outbound only**, so it never fires on curl from Kali *(Perplexity flagged the direction; the commented-out status is new)* |
| 2049400 | `ET WEB_SERVER /etc/passwd Detected in URI` | **[VERIFIED-TEST]** fired on the traversal curl (needs `$HTTP_SERVERS` to cover the victim) |
| 2009714 | `ET WEB_SERVER Script tag in URI Possible Cross Site Scripting Attempt` | **[VERIFIED-TEST]** fired on the encoded script curl |
| 1000004–1000008 | local web rules | **[VERIFIED-TEST]** all fired |

```bash
jq -c 'select(.event_type=="alert") | select(.app_proto=="http" or (.alert.signature|test("Nikto|WEB|HTTP|curl";"i")))' "$EVE" > ~/lab/evidence/eve-alerts-web.json
jq -c 'select(.event_type=="http") | select(.src_ip=="ATTACKER_IP") | {t:.timestamp,ua:.http.http_user_agent,url:.http.url,st:.http.status}' "$EVE" | head -30
```

**MITRE:** T1595.002 Vulnerability Scanning; T1190 (attempted).

### B3. Pitfalls *[PPLX]*

- Thresholds count **packets/requests/connections, not passwords**.
- HTTP rules need **plaintext HTTP**; nothing on 443 is inspected without TLS keys.
- **User-Agents are attacker-controlled**: the custom-UA Nikto run proves it.
- Always pair a positive test with a **negative control**.
- Run each scenario more than once and report counts like "5/5 runs detected" *[PPLX]*.

### B4. Screenshot checklist (before the break)

1. Kali: each command + output
2. Ubuntu: `fast.log` lines per SID
3. jq alert-count-by-SID summary
4. `suricata.yaml` HOME_NET + af-packet snippet, `ethtool -k` output
5. `journalctl -u ssh` Failed password lines

---

## Block C: 3:00–4:15, incident report

Use `incident-report-template.md` (13 sections, NIST SP 800-61r3-shaped). **One report per scenario** *[PPLX]*, or one report with three scenario subsections if time is short.

```bash
jq -c 'select(.event_type=="alert") | {t:.timestamp, sid:.alert.signature_id, msg:.alert.signature}' "$EVE" | jq -s 'sort_by(.t)'
sha256sum ~/lab/evidence/* > ~/lab/evidence/SHA256SUMS      # evidence inventory [PPLX]
suricata -V; suricata-update --version; nmap --version | head -1; nikto -Version 2>/dev/null | head -3
```

---

## Block D: 4:15–5:00, README + push

1. Create the repo layout from `README-draft.md` (`config/ rules/ scenarios/ reports/ evidence/ tests/ scripts/ docs/`).
2. Copy `rules/local.rules`, a **sanitised** `config/suricata.yaml` excerpt, the report(s), evidence + SHA256SUMS.
3. Check for secrets before committing: `grep -rniE 'password|passwd|token|secret' .` (lab wordlists are fine; real creds are not).
4. Commit + push from your laptop (Grok Bot does **not** push):

```bash
git init && git branch -M main
git add README.md docs/ config/ rules/ scenarios/ reports/ evidence/ tests/ scripts/
git commit -m "Suricata IDS lab: SSH brute force, Nmap, web scan detection + local rules + incident report"
git remote add origin git@github.com:joveteo/suricata-lab.git
git push -u origin main
```

---

## Evidence jq cheat-sheet

```bash
EVE=/var/log/suricata/eve.json
jq -c 'select(.event_type=="alert")' "$EVE" | jq -s 'group_by(.alert.signature_id) | map({sid:.[0].alert.signature_id, msg:.[0].alert.signature, n:length}) | sort_by(-.n)'
jq -c 'select(.event_type=="alert" and .alert.signature_id>=1000001 and .alert.signature_id<=1000008)' "$EVE"    # local rules only
jq -c 'select(.event_type=="alert") | select(.timestamp >= "2026-10-23T13:30:00" and .timestamp <= "2026-10-23T14:45:00")' "$EVE"
```

Or `../scripts/extract-alerts.sh "$EVE" ./evidence`.

---

## Troubleshooting

1. **No inbound alerts at all → HOME_NET.** If Kali is inside HOME_NET, `$EXTERNAL_NET -> $HOME_NET` rules never match. Set HOME_NET to the victim /32 *[PPLX]*, run `suricata -T`, then reload.
2. **Wrong interface.** Run `ps -ww -C suricata -o args=` and `ip -br address`, then `tcpdump -ni IFACE` while Kali sends traffic. Changing the interface needs `systemctl restart suricata` *[PPLX]*.
3. **Stream / HTTP rules miss, `SURICATA TCPv4 invalid checksum` floods.** Turn off GRO/LRO with `ethtool -K IFACE gro off lro off` *[PPLX]*. In the loopback replay, offloaded checksums produced 591 `invalid checksum` decoder alerts **[VERIFIED-TEST]**. For pcap replays use `-k none`. Only on a live NIC, and only if needed, also set `checksum-checks: no` under af-packet (record it in the report).
4. **Rules not loaded / stale.** `suricata-update` → `suricata -T` → `suricatasc -c ruleset-reload-nonblocking` → `suricatasc -c ruleset-stats`. Confirm a SID is present: `grep -n "sid:2001219;" /var/lib/suricata/rules/suricata.rules`.
5. **Threshold not met.** 2001219 needs 5 SYN in 120s, 2002677 needs 5 Nikto hits in 60s, and 2002825 needs 10 curl requests in 60s. Slow tools (`hydra -t 1`) can stay under the thresholds.
6. **`suricatasc` fails.** `unix-command: enabled: yes` is missing, or the socket path differs (`ls /var/run/suricata*`).
7. **Empty eve.json.** `sudo suricatasc -c reopen-log-files` or restart.

---

## Confirm-on-box checklist

- [ ] `IFACE`, `TARGET_IP`, Suricata version (`suricata -V`)
- [ ] HOME_NET = victim /32; `$HTTP_SERVERS` covers the victim (defaults to `$HOME_NET`)
- [ ] `local.rules` listed in `rule-files` and `ruleset-stats` shows 0 failed
- [ ] GRO/LRO off on `IFACE`
- [ ] Apache on :80 (prefer it over python http.server)
- [ ] Nikto version supports `-useragent` (`nikto -H`)

---

## Sources

- ET Open: https://rules.emergingthreats.net/open/suricata/rules/emerging-scan.rules and `emerging-policy.rules` (fetched 22 Oct 2026)
- Suricata, adding your own rules: https://docs.suricata.io/en/latest/rule-management/adding-your-own-rules.html
- Suricata YAML: https://docs.suricata.io/en/latest/configuration/suricata-yaml.html
- NIST SP 800-61r3: https://csrc.nist.gov/pubs/sp/800/61/r3/final
- Perplexity thread (Suricata): https://www.perplexity.ai/search/8ec7fbcf-f606-42ed-be35-3464f6cf19be
