# Investigation 2 — Compromised Internal Machine Analysis
 
> **BOTS v3 Dataset | Splunk Enterprise | 2018-08-20**
 
---
 
## Quick Summary
 
| Parameter | Value |
|---|---|
| Target Host | 192.168.3.130 |
| Host OS | Windows 10 (64-bit, VMware VM) |
| MAC Address | 00:0C:29:47:CA:40 (VMware OUI) |
| Total Events | 37,854 across 10 sourcetypes |
| HTTP Requests | 2,207 to 235 unique external destinations |
| Findings | 8 (7 confirmed, 1 ruled out) |
| Severity | CRITICAL |
 
---
 
## What Was Found
 
This machine was running a sophisticated multi-module malware that simultaneously:
 
- 📡 **Beaconed to a C2 server every 5 seconds** via HTTP POST with constant 305-byte payload
- 🔍 **Checked its own public IP hourly** using a Python script (python-requests/2.18.4)
- 📡 **Broadcast SMB discovery packets every 12 minutes** to map the internal network
- 💾 **Downloaded a malicious Chrome extension** disguised as PepperFlashPlayer via BITS
- 🤖 **Fabricated a complete browser fingerprint** to bypass WordPress bot detection
- 💰 **Generated fake ad traffic** across 12+ ad networks (OpenX, AppNexus, Criteo, Taboola)
- 🌐 **Scraped websites automatically** (visitcalifornia.com: 146 requests, 146 unique paths)
- 🗺️ **Mapped internal infrastructure** via DNS — targeting Splunk SIEM (2,445 queries), AV server, and proxy
---
 
## Files in This Folder
 
| File | Description |
|---|---|
| `README.md` | This file — quick overview |
| `Investigation_2_Report.md` | Full detailed report with all findings |
| `SPL_Queries_Investigation_2.spl` | All SPL queries used, with comments |
| `screenshots/` | Evidence screenshots from Splunk |
 
---
 
## Key Evidence Highlights
 
### Beaconing Proof — bytes_out constant across all 41 requests
```
15:31:29 -> time_diff=5.016s   bytes_out=305
15:31:34 -> time_diff=5.127s   bytes_out=305
15:31:39 -> time_diff=4.864s   bytes_out=305
15:31:44 -> time_diff=5.007s   bytes_out=305
15:31:49 -> time_diff=5.000s   bytes_out=305
```
 
### Hourly IP Check Timing
```
15:15:01 → ipinfo.io/json
16:15:24 → ipinfo.io/json  (+60 min)
17:13:29 → ipinfo.io/json  (+58 min)
18:09:15 → ipinfo.io/json  (+56 min)
18:54:48 → ipinfo.io/json  (+45 min)
```
 
### BITS Download — Malware Delivery
```
URI: /edgedl/release2/chrome_component/AKF2Puc6-vYu_30.0.0.134/
     30.0.0.134_win64_PepperFlashPlayer.crx3
Site: redirector.gvt1.com (Google CDN)
UA:   Microsoft BITS/7.8
```
 
### Browser Fingerprint Fabricated
```json
browserInfo={
  "screenWidth":1275, "screenHeight":839,
  "windows_nt":"10.0", "win64":true,
  "chrome":"64.0.3282.140", "edge":"17.17134"
}
```
 
---
 
## MITRE ATT&CK Coverage
 
| Finding | Technique ID | Technique Name |
|---|---|---|
| 1 | T1197 | BITS Jobs |
| 1 | T1036.005 | Masquerading: Match Legitimate Name |
| 1 | T1176 | Browser Extensions (assessed) |
| 2 | T1071.001 | Application Layer Protocol: Web |
| 2 | T1036 | Masquerading |
| 2 | T1102 | Web Service |
| 3 | T1016 | System Network Configuration Discovery |
| 3 | T1059.006 | Python Interpreter |
| 4 | T1036 | Masquerading |
| 4 | T1496 | Resource Hijacking |
| 5 | T1496 | Resource Hijacking |
| 5 | T1119 | Automated Collection |
| 6 | T1590 | Gather Victim Network Information |
| 6 | T1018 | Remote System Discovery |
| 6 | T1518.001 | Security Software Discovery |
| 6 | T1016 | System Network Configuration Discovery |
| 7 | T1018 | Remote System Discovery |
| 7 | T1046 | Network Service Scanning |
 
---
 
## IOCs at a Glance
 
```
IP:     52.86.117.247         (C2 server — track.contently.com)
Domain: track.contently.com   (Primary C2 — 41 POST beacons)
Domain: ipinfo.io             (Secondary beacon — hourly IP check)
File:   PepperFlashPlayer.crx3 (Malicious Chrome extension)
UA:     python-requests/2.18.4 (Malware recon module)
UA:     Microsoft BITS/7.8    (Malware delivery mechanism)
MAC:    00:0C:29:47:CA:40     (Compromised VM)
```
 
---
 
[⬅️ Back to Main Repository](../README.md)
