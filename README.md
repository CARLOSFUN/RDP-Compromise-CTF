# VM RDP Compromise – End-to-End SOC Investigation (CTF)

[![Status: Complete](https://img.shields.io/badge/Status-Complete-brightgreen)](#)
[![Technique Mapping](https://img.shields.io/badge/MITRE-ATT%26CK-blue)](#mitre-techniques)
[![KQL](https://img.shields.io/badge/Queries-KQL-informational)](#kql-queries)

A hands-on investigation of a **cloud VM RDP compromise** using **Microsoft Defender for Endpoint (MDE)** and **Advanced Hunting (KQL)**.  
This README contains **the entire case**: flags, queries, evidence screenshots, timeline, and remediation in a single page.

---

## Table of Contents
- [Scenario](#scenario)
- [Key Findings (Flags)](#key-findings-flags)
- [Attack Timeline (UTC)](#attack-timeline-utc)
- [KQL Queries (Beginner-Friendly)](#kql-queries)
- [Evidence Screenshots](#evidence-screenshots)
- [Investigation Summary](#investigation-summary)
- [5W1H: Who / What / When / Where / Why / How](#5w1h-who--what--when--where--why--how)
- [Recommendations](#recommendations)
- [MITRE Techniques](#mitre-techniques)
- [About the Analyst](#about-the-analyst)

---

## Scenario

**SOC Challenge:** Virtual Machine Compromise – “Hide Your RDP: Password Spray Leads to Full Compromise”  
**Environment:** Cloud Windows VM (hosts contain `"flare"`)  
**Investigative Tools:** Microsoft Defender for Endpoint (MDE) Advanced Hunting (KQL), Microsoft Sentinel (where available)  
**Incident Date:** 14-September-2025  
**Investigation Window:** **15–22 September 2025 (UTC)**

---

## Key Findings (Flags)

| # | Question | Answer |
|---|---|---|
| 1 | Attacker IP Address | `159.26.106.84` |
| 2 | Compromised Account | `slflare` |
| 3 | Executed Binary Name | `msupdate.exe` |
| 4 | Full Command Line | `"C:\Users\Public\msupdate.exe" -ExecutionPolicy Bypass -File "C:\Users\Public\update_check.ps1"` |
| 5 | Persistence Task Name | `MicrosoftUpdateSync` |
| 6 | Defender Setting Modified | `C:\Windows\Temp` (exclusion) |
| 7 | Earliest Discovery Command | `"cmd.exe" /c systeminfo"` |
| 8 | Archive Created | `backup_sync.zip` |
| 9 | C2 Destination | `185.92.220.87` |
| 10 | Exfiltration IP:Port | `185.92.220.87:8081` |

---

## Attack Timeline (UTC)

- **04:39:48 – 17 Sep:** Defender exclusion added → `C:\Windows\Temp`  
- **04:40:28 – 17 Sep:** Discovery → `"cmd.exe" /c systeminfo`  
- **04:41:30 – 17 Sep:** Archive created → `backup_sync.zip`  
- **04:42:17 – 17 Sep:** First outbound to **185.92.220.87**  
- **04:43:42 – 17 Sep:** Exfil attempt → **185.92.220.87:8081** (HTTP POST with `curl.exe`)

---

## KQL Queries

> **Tip:** Start broad, then tighten. If you get no results, widen the time window or temporarily remove `DeviceName` filtering.

### 1) Initial Access (Flags 1–2)
```kusto
DeviceLogonEvents
| where Timestamp between (datetime(2025-09-15T00:00:00Z) .. datetime(2025-09-22T23:59:59Z))
| where DeviceName contains "flare"
| where LogonType == "RemoteInteractive"   // RDP
| project Timestamp, DeviceName, AccountName, RemoteIP, ActionType, LogonType
| order by Timestamp asc

<img width="1250" height="391" alt="image" src="https://github.com/user-attachments/assets/de70ff22-aaa0-48e8-b19b-adcb2c764c69" />

