# SPL Queries — Investigation 2 (BOTS v3)
 
**Target:** 192.168.3.130 | **Dataset:** BOTS v3 | **Tool:** Splunk Enterprise
**Author:** Saniya
 
All queries below were run against `index=botsv3`, scoped to host `192.168.3.130` unless otherwise noted. Each query includes **why it was run** and the **result** it produced, organized by investigation phase so the methodology can be followed end-to-end or reused for hunting on other hosts.
 
---
 
## Phase 1 — Host Identification
 
### Q1.1 — Check which sourcetypes are available for this host
**Why:** Determines what investigation is possible. No Sysmon = no process-level evidence, rely on network logs only.
```spl
index=botsv3 src_ip=192.168.3.130 OR dest_ip=192.168.3.130
| stats count by sourcetype
| sort -count
```
**Result:** 10 sourcetypes present. No `XmlWinEventLog` or Sysmon confirmed — network-layer evidence only.
 
### Q1.2 — Machine fingerprinting: hostname, MAC, user agents
**Why:** MAC prefix reveals hardware type (VMware = virtual machine). User agents reveal every application making HTTP requests, including malware (python-requests, BITS).
```spl
index=botsv3 sourcetype=stream:http src_ip=192.168.3.130
| stats values(src_host) as hostname,
        values(src_mac) as mac_address,
        values(http_user_agent) as user_agents
  by src_ip
```
**Result:** MAC `00:0C:29` = VMware VM. Windows 10 (NT 10.0 in UA). `python-requests/2.18.4` and `Microsoft BITS/7.8` flagged as anomalous.
 
---
 
## Phase 2 — Map All External Destinations
 
### Q2.1 — All destinations with traffic pattern analysis
**Why:** `dc(uri_path)` = distinct count of unique paths. `dc=1` with high count = beaconing (same URL hit repeatedly). `dc=count` with high count = scraping (every request different page). A normal workstation contacts 20–40 destinations/day — 235 unique destinations is immediately suspicious.
```spl
index=botsv3 sourcetype=stream:http src_ip=192.168.3.130
| stats count, values(http_method) as methods,
        dc(uri_path) as unique_paths
  by dest_ip, site
| sort -count
```
**Result:** `track.contently.com` — 41 POSTs, dc=1 → **BEACON**. `visitcalifornia.com` — 146 GETs, dc=146 → **SCRAPING**. 12+ ad networks contacted → **AD FRAUD**.
 
---
 
## Phase 3 — C2 Beacon Analysis (Finding 2)
 
### Q3.1 — Inspect the suspicious POST destination
**Why:** 41 POSTs to a dc=1 destination = likely beaconing. Timing and payload need verification to confirm.
```spl
index=botsv3 sourcetype=stream:http src_ip=192.168.3.130
site="track.contently.com"
| table _time, uri_path, http_user_agent, bytes_out, bytes_in, status
| sort _time
```
 
### Q3.2 — Calculate exact beacon intervals using delta
**Why:** `delta` calculates the time difference between consecutive events. Consistent intervals = automated timer = malware, not human. Constant `bytes_out` = hardcoded packet = beacon structure.
```spl
index=botsv3 sourcetype=stream:http src_ip=192.168.3.130
site="track.contently.com"
| sort _time
| delta _time as time_diff p=1
| table _time, uri_path, bytes_out, bytes_in, status, time_diff
```
**Result:** Interval ≈ 5 seconds. `bytes_out` = 305, constant across all 41 requests. HTTP 201 confirms the C2 server was live and actively responding.
 
---
 
## Phase 4 — Python Module Analysis (Finding 3)
 
### Q4.1 — What was the python-requests module contacting?
**Why:** `python-requests` is never produced by real browsers. Its presence confirms a Python script is running on this host.
```spl
index=botsv3 sourcetype=stream:http src_ip=192.168.3.130
http_user_agent="python-requests/2.18.4"
| stats count by site, http_method
| sort -count
```
**Result:** Only destination = `ipinfo.io`, 5 GET requests.
 
### Q4.2 — What exact path was queried on ipinfo.io?
**Why:** `/json` with no parameter = machine checking its own public IP — confirms a secondary beacon for IP monitoring. Constant `bytes_in` = IP never changed during observation.
```spl
index=botsv3 sourcetype=stream:http src_ip=192.168.3.130
http_user_agent="python-requests/2.18.4"
| table _time, uri_path, uri_query, bytes_in, bytes_out, status
| sort _time
```
**Result:** `/json`, no `uri_query`. `bytes_in` = 144, constant. Intervals: 15:15, 16:15, 17:13, 18:09, 18:54 (~60 min apart).
 
---
 
## Phase 5 — Scraping User-Agent Verification
 
### Q5.1 — Which user agent was doing the web scraping?
**Why:** Determines which malware module is responsible for scraping — tells us if `python-requests` or the spoofed Edge UA was scraping.
```spl
index=botsv3 sourcetype=stream:http src_ip=192.168.3.130
| where site IN ("www.visitcalifornia.com",
                 "www.distillerytrail.com",
                 "fsd.servicemax.com")
| stats count by site, http_user_agent, http_method
```
**Result:** All scraping used the spoofed Edge UA (not `python-requests`), confirming two independent malware modules with different roles.
 
---
 
## Phase 6 — POST Data / Fingerprint Analysis (Finding 4)
 
### Q6.1 — What was submitted in POST requests to servicemax.com?
**Why:** `form_data` shows the actual POST body — direct evidence of what data was being sent (e.g., credential stuffing or bot-detection bypass).
```spl
index=botsv3 sourcetype=stream:http src_ip=192.168.3.130
site="fsd.servicemax.com" http_method=POST
| table _time, uri_path, form_data
```
**Result:** `gdbcRetrieveToken` = fabricated browser fingerprint (14 attributes). `bloom_handle_stats_adding` = fake ad impression submitted.
 
---
 
## Phase 7 — BITS Delivery Analysis (Finding 1)
 
### Q7.1 — What did BITS download?
**Why:** BITS is abused by malware to download payloads via a trusted Windows service. The URI path reveals the exact file downloaded.
```spl
index=botsv3 sourcetype=stream:http src_ip=192.168.3.130
http_user_agent="Microsoft BITS/7.8"
| table _time, site, dest_ip, uri_path, bytes_in, bytes_out, status
| sort _time
```
**Result:** `PepperFlashPlayer.crx3` downloaded from Google CDN (`gvt1.com`). `.crx3` = Chrome Extension format — not a real Flash installer. Repeated downloads suggest automated persistence/reinstallation.
 
---
 
## Phase 8 — SMB Discovery (Finding 7)
 
### Q8.1 — What SMB activity came from this host?
**Why:** SMB from a compromised host could indicate lateral movement. Checking `dest_ip` (specific machine or broadcast?), `command` (file access or discovery?), and `filename` (what was accessed?) clarifies intent.
```spl
index=botsv3 sourcetype=stream:smb src_ip=192.168.3.130
| table _time, dest_ip, command, filename, share
| sort _time
```
**Result:** `dest_ip=192.168.3.255` (broadcast — not a specific host). `command=transaction` (host enumeration, no files accessed). 18 events at exact 12-minute intervals = automated timer.
 
---
 
## Phase 9 — Internal Traffic Check (Finding 8)
 
### Q9.1 — Which internal IPs received traffic from this host?
**Why:** Compromised machines often try to reach other internal hosts for lateral movement. A high count to one internal IP warrants investigation.
```spl
index=botsv3 sourcetype=stream:ip src_ip=192.168.3.130
| where dest_ip LIKE "192.168.%"
| stats count by dest_ip
| sort -count
```
**Result:** `192.168.3.2` received 6,821 events — suspicious volume.
 
### Q9.2 — Identify what machine 192.168.3.2 is
**Why:** Must identify the target before concluding lateral movement — could be a domain controller (critical), file server, or DNS server.
```spl
index=botsv3 src_ip=192.168.3.2 OR dest_ip=192.168.3.2
| stats count by sourcetype, host
| sort -count
```
**Result:** `hostname=BTUN-L`, with heavy `stream:dns` activity → internal DNS server.
 
### Q9.3 — What protocol was the traffic using?
**Why:** TCP = active session (potential attack). UDP = connectionless (likely DNS). Protocol determines whether this is lateral movement.
```spl
index=botsv3 sourcetype=stream:ip src_ip=192.168.3.130 dest_ip=192.168.3.2
| stats count by protocol, protoid
| sort -count
```
**Result:** 100% UDP, `protoid=17` = DNS. Not lateral movement.
 
### Q9.4 — Did 192.168.3.2 respond? (bidirectional check)
**Why:** Symmetric traffic = interactive session. Asymmetric = query/response. DNS traffic is asymmetric (many queries, few responses).
```spl
index=botsv3 sourcetype=stream:ip src_ip=192.168.3.2
| stats count by dest_ip
| sort -count
```
**Result:** Only 11 events returned — consistent with DNS query/response. Lateral movement ruled out.
 
---
 
## Phase 10 — DNS Reconnaissance (Finding 6)
 
### Q10.1 — Discover correct field names for stream:dns
**Why:** `stream:dns` uses `query{}`, not `query` (multi-value field with braces). Always run `fieldsummary` on a new sourcetype before querying it — zero results from a query almost always means the wrong field name.
```spl
index=botsv3 sourcetype=stream:dns src_ip=192.168.3.130
| fieldsummary
| table field, count
| where count > 0
| sort -count
```
 
### Q10.2 — All DNS queries from this host (top 20)
**Why:** Every domain this machine tried to reach appears here. Anomalous volumes to internal hostnames indicate reconnaissance; NIMLOC queries indicate NetBIOS host enumeration.
```spl
index=botsv3 sourcetype=stream:dns src_ip=192.168.3.130
| stats count by "query{}", "query_type{}"
| sort -count
| head 20
```
**Result:** `splunk.froth.ly` = 2,445 (SIEM). NIMLOC = 520+ (host enumeration). `sepmserver` = 750+ (AV server). `wpad` = 361+ (proxy discovery).
 
### Q10.3 — What IPs did domains resolve to?
**Why:** Confirms which IP each domain resolves to. Cross-referencing with HTTP destinations builds the evidence chain: DNS query → IP → HTTP connection.
```spl
index=botsv3 sourcetype=stream:dns src_ip=192.168.3.130
| stats count by "query{}", "host_addr{}"
| sort -count
| head 20
```
**Result:** `splunk.froth.ly` → `34.215.24.225` (AWS) — confirms the org's SIEM is cloud-hosted.
 
---
 
## Utility Queries
 
### U1 — Field name discovery for any sourcetype
Use when a query returns 0 results despite events existing. Replace sourcetype with whichever you are investigating.
```spl
index=botsv3 sourcetype=stream:http src_ip=192.168.3.130
| fieldsummary
| table field, count, distinct_count
| where count > 0
| sort -count
```
 
### U2 — Detect beaconing patterns across all destinations
Finds any destination being hit repeatedly at regular intervals.
```spl
index=botsv3 sourcetype=stream:http src_ip=192.168.3.130
| bin _time span=1m
| stats count by _time, site, uri_path
| where count >= 2
| sort _time, site
```
 
### U3 — Data volume analysis per destination
Detects potential exfiltration: high `mb_out` to unknown external IPs.
```spl
index=botsv3 sourcetype=stream:http src_ip=192.168.3.130
| stats sum(bytes_out) as total_bytes_out,
        sum(bytes_in) as total_bytes_in,
        count as requests
  by site, dest_ip
| eval mb_out=round(total_bytes_out/1048576, 2)
| eval mb_in=round(total_bytes_in/1048576, 2)
| sort -mb_out
| table site, dest_ip, requests, mb_out, mb_in
```
 
---
*Investigation conducted by Saniya | BOTS v3 Dataset | Splunk Enterprise | MITRE ATT&CK v13*
