# Investigation 2 — Compromised Internal Machine Analysis
### BOTS v3 Dataset | Splunk Enterprise | SOC Analyst Portfolio
 
---
 
## Table of Contents
1. [Executive Summary](#executive-summary)
2. [Investigation Scope](#investigation-scope)
3. [Attack Timeline](#attack-timeline)
4. [Findings](#findings)
   - [Finding 1 — Malware Delivery via BITS Job Abuse](#finding-1--malware-delivery-via-bits-job-abuse)
   - [Finding 2 — Primary C2 Beaconing (5-Second Interval)](#finding-2--primary-c2-beaconing-5-second-interval)
   - [Finding 3 — Secondary Beacon — IP Self-Identification](#finding-3--secondary-beacon--ip-self-identification)
   - [Finding 4 — Browser Fingerprint Fabrication](#finding-4--browser-fingerprint-fabrication--bot-detection-bypass)
   - [Finding 5 — Coordinated Ad Fraud Traffic](#finding-5--coordinated-traffic-to-advertising-networks)
   - [Finding 6 — Internal Reconnaissance via DNS](#finding-6--internal-reconnaissance-via-dns)
   - [Finding 7 — Network Discovery via SMB Broadcast](#finding-7--network-discovery-via-smb-broadcast)
   - [Finding 8 — Internal Traffic to 192.168.3.2 (Ruled Out)](#finding-8--high-volume-internal-traffic-to-192168320-ruled-out)
5. [MITRE ATT&CK Summary](#mitre-attck-summary)
6. [IOCs](#indicators-of-compromise-iocs)
7. [Recommended Response Actions](#recommended-response-actions)
---
 
## Executive Summary
 
During analysis of the BOTS v3 dataset, internal host **192.168.3.130** (Windows 10, VMware VM, MAC: `00:0C:29:47:CA:40`) was identified as compromised with a sophisticated, multi-module malware infection. The machine generated **37,854 total events** across 10 sourcetypes and **2,207 HTTP requests** to **235 unique external destinations**.
 
**Confirmed malware capabilities:**
- Triple-beacon C2 architecture (5-second HTTP, 12-minute SMB, 60-minute IP check)
- BITS-based download of a file disguised as Chrome Flash Player update
- Browser fingerprint fabrication to bypass bot-detection systems
- Coordinated ad fraud traffic across 12+ major advertising networks
- Internal reconnaissance targeting the SIEM, AV server, and proxy infrastructure
> **Evidence Standard:** Every finding is backed by a specific SPL query and direct log evidence. Where the dataset does not contain direct confirmation (no Sysmon/EDR telemetry was available — confirmed in sourcetype check), findings are explicitly labeled as assessed rather than confirmed. This reflects real-world SOC reporting standards.
 
> **Scope Limitation:** No Sysmon or Windows Event Log telemetry was available for this host — only network-layer logs (stream:http, stream:dns, stream:ip, stream:smb, etc.). Findings describing process execution or file installation are based on network evidence and reasonable inference, not direct process-level confirmation.
 
---
 
## Investigation Scope
 
| Parameter | Value |
|---|---|
| Dataset | Boss of the SOC (BOTS) v3 |
| Splunk Index | `botsv3` |
| Target Host | 192.168.3.130 |
| Host OS | Windows 10 (64-bit, VMware VM) |
| MAC Address | 00:0C:29:47:CA:40 (VMware OUI) |
| Investigation Date | 2018-08-20 |
| Total Events | 37,854 |
| Sourcetypes | stream:http, stream:dns, stream:ip, stream:tcp, stream:smb, stream:udp |
| Framework | MITRE ATT&CK v13 |
 
---
 
## Attack Timeline
 
| Time | Event | Significance |
|---|---|---|
| 15:15:01 | Slow beacon starts — ipinfo.io/json | Hourly IP self-identification begins |
| 15:24:08 | SMB broadcasts begin — 192.168.3.255 | 12-minute network discovery interval starts |
| 15:28:29 | Browser fingerprint submitted to servicemax.com | Bot detection bypass attempt |
| 15:28:30 | Fast C2 beacon starts — track.contently.com | 5-second C2 heartbeat begins |
| 15:28:48 | Fake ad impression — Bloom WordPress plugin | Ad fraud traffic observed |
| 16:15:24 | ipinfo.io second check-in | +60 min from first |
| 17:13:29 | ipinfo.io third check-in | +58 min from second |
| 18:09:15 | ipinfo.io fourth check-in | +56 min from third |
| 18:54:27 | BITS downloads PepperFlashPlayer.crx3 | Suspicious file download via trusted service |
| 18:54:48 | ipinfo.io fifth check-in | +45 min from fourth |
| Throughout | Ad fraud traffic to 12+ ad networks | OpenX, AppNexus, Criteo, Taboola, etc. |
| Throughout | DNS recon — splunk.froth.ly (2,445 queries) | Anomalous SIEM-hostname targeting |
| Throughout | Web scraping — visitcalifornia, distillerytrail | Automated content harvesting pattern |
 
---
 
## Findings
 
---
 
### Finding 1 — Malware Delivery via BITS Job Abuse
 
**Severity:** 🔴 CRITICAL | **Confidence:** High
 
**Indicator:** `Microsoft BITS/7.8` user agent downloading a `.crx3` file from Google CDN
 
**SPL Query:**
```spl
index=botsv3 sourcetype=stream:http src_ip=192.168.3.130
http_user_agent="Microsoft BITS/7.8"
| table _time, site, dest_ip, uri_path, bytes_in, bytes_out, status
| sort _time
```
 
**Evidence:**
 
| Field | Value |
|---|---|
| Time | 2018-08-20 18:54:26 onwards (repeated) |
| Site | redirector.gvt1.com / r3---sn-a5mlrn7r.gvt1.com |
| URI Path | `/edgedl/release2/chrome_component/AKF2Puc6-vYu_30.0.0.134/30.0.0.134_win64_PepperFlashPlayer.crx3` |
| User Agent | Microsoft BITS/7.8 |
| Delivery Source | Google CDN (trusted infrastructure) |
| Pattern | Repeated download attempts within seconds — automated retry behavior |
 
Windows Background Intelligent Transfer Service (BITS) was used to download a file named `PepperFlashPlayer.crx3` from Google's own CDN. BITS is a trusted Windows system service normally used for Windows Updates, meaning this traffic would typically bypass firewall and AV scrutiny. The `.crx3` extension identifies this as a **Chrome Extension package** — not the format Adobe Flash installers use (`.exe` or `.msi`). This inconsistency between the claimed filename and actual file type is the primary indicator of masquerading.
 
**Payload Analysis:**
 
The filename `PepperFlashPlayer` closely mimics a real and recognizable Chrome browser component (Adobe Pepper Flash), making it convincing to both end users and automated scanning tools.
 
> ⚠️ **Evidence Limitation — Installation Not Confirmed:** No Sysmon, Windows Event Log, or Chrome extension telemetry was available for this host. As a result, installation and execution of this downloaded file inside the browser **CANNOT be directly confirmed** from this dataset. What is confirmed is the download itself. To confirm installation, an analyst would need: Sysmon Event ID 1 (process creation), Chrome extension directory artifacts, or EDR telemetry showing the `.crx3` being loaded by `chrome.exe`.
 
**MITRE ATT&CK:**
- `T1197` — BITS Jobs
- `T1036.005` — Masquerading: Match Legitimate Name
- `T1176` — Browser Extensions *(applies if installation is confirmed)*
---
 
### Finding 2 — Primary C2 Beaconing (5-Second Interval)
 
**Severity:** 🔴 CRITICAL | **Confidence:** High
 
**Indicator:** 41 identical HTTP POSTs to `track.contently.com/track` at ~5 second intervals
 
**SPL Query:**
```spl
index=botsv3 sourcetype=stream:http src_ip=192.168.3.130
site="track.contently.com"
| sort _time
| delta _time as time_diff p=1
| table _time, uri_path, bytes_out, bytes_in, status, time_diff
```
 
**Evidence:**
 
| Field | Value |
|---|---|
| Destination | track.contently.com (52.86.117.247) |
| URI Path | `/track` (single hardcoded endpoint) |
| HTTP Method | POST |
| Total Beacons | 41 confirmed requests |
| bytes_out | **305 bytes — CONSTANT across all 41 requests** |
| bytes_in | 1,062–1,189 bytes (variable — C2 instructions) |
| HTTP Status | 201 Created (server actively acknowledging) |
| Beacon Interval | ~5 seconds (range: 0.8s–140s, core = 5,000ms) |
| User Agent | Mozilla/5.0...Chrome/64.0...Edge/17.17134 **(spoofed)** |
 
**Beacon Interval Proof (time_diff column):**
```
15:31:29 → 5.016s    15:31:34 → 5.127s    15:31:39 → 4.864s
15:31:44 → 5.007s    15:31:49 → 5.000s    15:31:55 → 5.173s
```
 
The constant `bytes_out=305` across all 41 requests confirms a hardcoded, structured beacon packet. Variable `bytes_in` (1,062–1,189 bytes) confirms the C2 server was actively sending different instructions per request. HTTP 201 confirms the destination server was live and responsive. The user agent claims Microsoft Edge — this is contradicted by the request behavior, as no real browser sends an identical-sized POST to the same endpoint every 5 seconds continuously.
 
**MITRE ATT&CK:**
- `T1071.001` — Application Layer Protocol: Web Protocols
- `T1036` — Masquerading (spoofed Edge user agent)
- `T1102` — Web Service
---
 
### Finding 3 — Secondary Beacon — IP Self-Identification
 
**Severity:** 🟠 HIGH | **Confidence:** High
 
**Indicator:** Hourly automated queries to `ipinfo.io/json` via `python-requests/2.18.4`
 
**SPL Queries:**
```spl
index=botsv3 sourcetype=stream:http src_ip=192.168.3.130
http_user_agent="python-requests/2.18.4"
| stats count by site, http_method
| sort -count
 
index=botsv3 sourcetype=stream:http src_ip=192.168.3.130
http_user_agent="python-requests/2.18.4"
| table _time, uri_path, bytes_in, bytes_out, status
| sort _time
```
 
**Evidence:**
 
| Field | Value |
|---|---|
| Destination | ipinfo.io/json |
| User Agent | python-requests/2.18.4 (Python library — not a browser) |
| Total Requests | 5 over 3.5-hour window |
| bytes_out | 533–537 (near-constant structured request) |
| bytes_in | **144 (constant — same response = public IP unchanged)** |
| Intervals | 15:15 → 16:15 (+60m) → 17:13 (+58m) → 18:09 (+56m) → 18:54 (+45m) |
 
`python-requests/2.18.4` is the default user agent for Python's requests library — never produced by genuine human browsing. A script queried `ipinfo.io/json` (no target IP specified = requests caller's own public IP) approximately hourly. The constant `bytes_in=144` confirms the public IP did not change during the observation window. This uses a different user agent than Finding 2, confirming **two separate malware modules**.
 
**MITRE ATT&CK:**
- `T1016` — System Network Configuration Discovery
- `T1059.006` — Command and Scripting Interpreter: Python
- `T1071.001` — Application Layer Protocol: Web Protocols (secondary channel)
---
 
### Finding 4 — Browser Fingerprint Fabrication & Bot Detection Bypass
 
**Severity:** 🟠 HIGH | **Confidence:** High
 
**Indicator:** Fabricated browser fingerprint JSON submitted to WordPress bot-detection endpoint
 
**SPL Query:**
```spl
index=botsv3 sourcetype=stream:http src_ip=192.168.3.130
site="fsd.servicemax.com" http_method=POST
| table _time, uri_path, form_data
```
 
**Evidence — form_data submitted to `gdbcRetrieveToken`:**
```
action=gdbcRetrieveToken
requestTime=1534759108502
browserInfo={
  "screenWidth":1275, "screenHeight":839,
  "engine":52, "features":127,
  "windows_nt":"10.0", "win64":true, "x64":true,
  "chrome":"64.0.3282.140", "safari":"537.36", "edge":"17.17134"
}
```
 
A POST request submitted a detailed browser fingerprint (screen dimensions, rendering engine flags, OS version, browser versions) to `gdbcRetrieveToken` — a WordPress security plugin that issues anti-bot verification tokens. All 14 submitted attributes were internally consistent with the user agent string used elsewhere on this host. The identical request was repeated twice within 1 millisecond (timestamps ending `.502` and `.503`), consistent with an automated retry mechanism.
 
A separate POST (`action=bloom_handle_stats_adding`) submitted fabricated ad-impression statistics to a WordPress email opt-in plugin, inflating engagement statistics for mailing list `075348e620`.
 
**MITRE ATT&CK:**
- `T1036` — Masquerading
- `T1496` — Resource Hijacking (fabricated impression data)
---
 
### Finding 5 — Coordinated Traffic to Advertising Networks
 
**Severity:** 🟠 HIGH | **Confidence:** High
 
**Indicator:** Automated requests to 12+ advertising networks with no corresponding browser session
 
**SPL Query:**
```spl
index=botsv3 sourcetype=stream:http src_ip=192.168.3.130
| stats count, values(http_method) as methods,
  dc(uri_path) as unique_paths by dest_ip, site
| sort -count
```
 
**Ad Network Contact Map:**
 
| Ad Network | Domain | Requests | Methods |
|---|---|---|---|
| OpenX | us-u.openx.net | 29 | GET |
| OpenX | tribune-d.openx.net | 9 | GET |
| AppNexus/Xandr | secure.adnxs.com | 7 | GET |
| Rubicon Project | fastlane.rubiconproject.com | 7 | GET |
| Criteo | bidder.criteo.com | 7 | POST |
| Taboola | trc.taboola.com / images.taboola.com | 17 | GET |
| Casale Media | as.casalemedia.com | 13 | GET+POST |
| Google Ads | tpc.googlesyndication.com | 6 | GET |
| Amazon DSP | aax.amazon-adsystem.com | 7 | GET |
 
**Web Scraping Pattern (count = unique_paths = automated crawl):**
 
| Site | Requests | Unique Paths | Pattern |
|---|---|---|---|
| www.visitcalifornia.com | 146 | 146 | 1:1 ratio — every request hit a new page |
| www.distillerytrail.com | 73 | 73 | 1:1 ratio — every request hit a new page |
| www.brewertalk.com | 829 | 45 | High repeat-access to a fixed set of pages |
 
This host contacted 12+ distinct ad exchange domains within the observation window with no corresponding legitimate browsing session recorded. The 1:1 count-to-unique-paths ratio on `visitcalifornia.com` and `distillerytrail.com` indicates systematic, sequential page access rather than typical human browsing.
 
**MITRE ATT&CK:**
- `T1496` — Resource Hijacking
- `T1119` — Automated Collection
---
 
### Finding 6 — Internal Reconnaissance via DNS
 
**Severity:** 🟠 HIGH | **Confidence:** High
 
**Indicator:** 6,580 DNS queries revealing targeted internal infrastructure mapping
 
**SPL Queries:**
```spl
index=botsv3 sourcetype=stream:dns src_ip=192.168.3.130
| stats count by "query{}", "query_type{}"
| sort -count
| head 20
 
index=botsv3 sourcetype=stream:dns src_ip=192.168.3.130
| stats count by "query{}", "host_addr{}"
| sort -count
| head 20
```
 
**Top DNS Queries:**
 
| Domain Queried | Count | Type | Significance |
|---|---|---|---|
| splunk.froth.ly | 2,445 | A | **Anomalously high — SIEM hostname** |
| NIMLOC encoded strings (x4) | 520+ | NIMLOC | NetBIOS host enumeration pattern |
| sepmserver (all suffixes) | 750+ | A/AAAA | AV management server — repeated lookup |
| wpad (all suffixes) | 361+ | A | Proxy auto-discovery — repeated lookup |
| BTUN-L.local | 34 | * | Internal DNS server confirmed |
 
**DNS Resolution Confirmed:** `splunk.froth.ly` → `34.215.24.225` (AWS) — 2,177 times
 
2,445 queries to a single internal hostname (`splunk.froth.ly`) from one workstation is far outside normal baseline behavior and is consistent with deliberate reconnaissance of the organization's Splunk SIEM deployment. The NIMLOC queries indicate NetBIOS-based host enumeration. Repeated lookups for `sepmserver` (Symantec Endpoint Protection Manager) and `wpad` (proxy auto-discovery) suggest the host was probing for security and network infrastructure.
 
**MITRE ATT&CK:**
- `T1590` — Gather Victim Network Information
- `T1018` — Remote System Discovery
- `T1518.001` — Security Software Discovery
- `T1016` — System Network Configuration Discovery
---
 
### Finding 7 — Network Discovery via SMB Broadcast
 
**Severity:** 🟡 MEDIUM | **Confidence:** High
 
**Indicator:** SMB broadcast transactions to `192.168.3.255` every ~12 minutes
 
**SPL Query:**
```spl
index=botsv3 sourcetype=stream:smb src_ip=192.168.3.130
| table _time, dest_ip, command, filename, share
| sort _time
```
 
**Evidence:**
 
| Field | Value |
|---|---|
| Destination | 192.168.3.255 (subnet broadcast address) |
| Command | `transaction` (SMB browser protocol) |
| Total Events | 18 broadcasts |
| Interval | ~12 minutes (consistent) |
| Files / Shares Accessed | **None recorded — discovery only** |
 
**12-minute timing proof:**
```
15:24:08 → 15:36:08 → 15:48:07 → 16:00:07 → 16:12:07
(each exactly 12 minutes apart — automated timer, not human)
```
 
The host broadcasted SMB transactions to the entire subnet at consistent ~12-minute intervals. No filename or share value was recorded — meaning this dataset shows no evidence of file access or lateral movement — only host-discovery broadcast traffic.
 
**MITRE ATT&CK:**
- `T1018` — Remote System Discovery
- `T1046` — Network Service Scanning
---
 
### Finding 8 — High-Volume Internal Traffic to 192.168.3.2 (Ruled Out as Lateral Movement)
 
**Severity:** ℹ️ INFORMATIONAL | **Confidence:** High
 
**Indicator:** 6,821 internal events to 192.168.3.2 — investigated and resolved as DNS traffic
 
**SPL Queries:**
```spl
index=botsv3 sourcetype=stream:ip src_ip=192.168.3.130
| where dest_ip LIKE "192.168.%"
| stats count by dest_ip
| sort -count
 
index=botsv3 src_ip=192.168.3.2 OR dest_ip=192.168.3.2
| stats count by sourcetype, host
| sort -count
 
index=botsv3 sourcetype=stream:ip src_ip=192.168.3.130 dest_ip=192.168.3.2
| stats count by protocol, protoid
| sort -count
```
 
**Investigation Steps:**
 
| Step | Finding |
|---|---|
| Internal IP map | 192.168.3.2 received 6,821 events — far higher than gateway (35) or broadcast (153) |
| Host identification | 192.168.3.2 = hostname BTUN-L, with heavy stream:dns activity (6,648 events) |
| Protocol check | All 5,155 protocol-tagged events were **UDP, protoid=17** (consistent with DNS, not TCP) |
| Reverse traffic check | Only 11 events returned from 192.168.3.2 — asymmetric, consistent with DNS response |
 
**Conclusion:** This traffic was investigated because of its volume, but the protocol (100% UDP) and the destination's role (internal DNS resolver) indicate this represents the compromised host's DNS queries being routed through BTUN-L — not lateral movement. This finding is documented to show the investigative process and formally rule out a possible explanation.
 
**MITRE ATT&CK:** Not applicable — this documents an investigated and resolved lead, not a confirmed technique.
 
---
 
## MITRE ATT&CK Summary
 
| # | Finding | Tactic | Technique ID | Technique Name |
|---|---|---|---|---|
| 1 | BITS Delivery | Defense Evasion | T1197 | BITS Jobs |
| 1 | Name Masquerading | Defense Evasion | T1036.005 | Match Legitimate Name |
| 1 | Payload (assessed) | Persistence | T1176 | Browser Extensions |
| 2 | Fast C2 Beacon | Command & Control | T1071.001 | Web Protocols |
| 2 | UA Spoofing | Defense Evasion | T1036 | Masquerading |
| 2 | Domain Abuse | Command & Control | T1102 | Web Service |
| 3 | IP Self-Check | Discovery | T1016 | Network Config Discovery |
| 3 | Python Script | Execution | T1059.006 | Python Interpreter |
| 4 | Fingerprint Spoof | Defense Evasion | T1036 | Masquerading |
| 4 | Impression Fraud | Impact | T1496 | Resource Hijacking |
| 5 | Ad Fraud | Impact | T1496 | Resource Hijacking |
| 5 | Web Scraping | Collection | T1119 | Automated Collection |
| 6 | SIEM Targeting | Discovery | T1590 | Gather Victim Network Info |
| 6 | NetBIOS Enum | Discovery | T1018 | Remote System Discovery |
| 6 | AV Server Mapping | Discovery | T1518.001 | Security Software Discovery |
| 6 | WPAD Discovery | Discovery | T1016 | Network Config Discovery |
| 7 | SMB Discovery | Discovery | T1018 | Remote System Discovery |
| 7 | Network Scanning | Discovery | T1046 | Network Service Scanning |
 
---
 
## Indicators of Compromise (IOCs)
 
### Network IOCs
| Type | Value | Context |
|---|---|---|
| IP | 52.86.117.247 | Primary C2 server (track.contently.com) |
| Domain | track.contently.com | Primary C2 — 41 POST beacons |
| Domain | ipinfo.io | Secondary beacon — hourly IP check |
| URL Path | `/edgedl/release2/chrome_component/.../PepperFlashPlayer.crx3` | Malware delivery path |
| CDN | redirector.gvt1.com | BITS download source |
 
### Host IOCs
| Type | Value | Context |
|---|---|---|
| IP | 192.168.3.130 | Compromised host |
| MAC | 00:0C:29:47:CA:40 | VMware NIC — confirms VM environment |
| User Agent | python-requests/2.18.4 | Non-browser scripted HTTP client |
| User Agent | Microsoft BITS/7.8 | File download mechanism |
| File | 30.0.0.134_win64_PepperFlashPlayer.crx3 | Malicious Chrome extension download |
 
### Behavioral IOCs
| Behavior | Threshold | Significance |
|---|---|---|
| HTTP POST to same URI | 41 requests in window | Beaconing pattern |
| bytes_out constant across POSTs | 305 bytes exact x41 | Hardcoded packet structure |
| python-requests UA from workstation | Any occurrence | Script-based malware |
| BITS download of .crx3 file | Repeated within seconds | Inconsistent with Windows Update |
| SMB broadcast at fixed intervals | 18 events, ~12 min apart | Automated discovery timer |
 
---
 
## Recommended Response Actions
 
### Immediate (0–1 hour)
- Isolate 192.168.3.130 from the network
- Block 52.86.117.247 at the perimeter firewall
- Capture memory image before shutdown — needed for process-level confirmation of Finding 1 payload analysis
- Preserve and extend log retention for this host
### Short-term (1–24 hours)
- Hunt for same beacon pattern (track.contently.com, 5-sec POST) on all other internal hosts
- Pull Chrome extension data from endpoint to confirm or rule out extension installation
- Review BITS job history: `bitsadmin /list /allusers /verbose`
- Verify sepmserver AV configuration for unauthorized changes
- Alert Splunk/SIEM team — SIEM was actively targeted (2,445 DNS queries to splunk.froth.ly)
### Long-term (1–7 days)
- Deploy Sysmon or EDR telemetry to close the evidence gap identified in Finding 1
- Implement Chrome Extension allowlisting via Group Policy
- Add SIEM detection rules for BITS downloads from non-Microsoft domains
- Review WPAD proxy configuration for unauthorized access
---
 
*Investigation by Saniya | BOTS v3 Dataset | Splunk Enterprise | MITRE ATT&CK v13*
