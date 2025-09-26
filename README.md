# VM RDP Compromise – End-to-End SOC Investigation (CTF)

[![Status: Complete](https://img.shields.io/badge/Status-Complete-brightgreen)](#)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-blue)](#mitre-techniques)
[![KQL](https://img.shields.io/badge/Queries-KQL-informational)](#kql--steps--results)

A hands-on investigation of a **cloud VM RDP compromise** using **Microsoft Defender for Endpoint (MDE) Advanced Hunting (KQL)**.  
This page contains **everything**: flags, steps, queries, results (screenshot slots), timeline, and recommendations—**all in one place**.

---

## Scenario

- **Challenge:** “Hide Your RDP: Password Spray Leads to Full Compromise”
- **Environment:** Cloud Windows VM (hostnames contain **"flare"**)
- **Tools:** Microsoft Defender for Endpoint (Advanced Hunting), Sentinel (where available)
- **Incident Date:** 14-Sep-2025  
- **Investigation Window (UTC):** **15–22 Sep 2025**

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
- **04:43:42 – 17 Sep:** Exfil attempt → **185.92.220.87:8081** (`curl.exe` POST)

---

# KQL + Steps + Results

**Tips:**

1. In MDE Advanced Hunting, set **Time** to **Custom** → `2025-09-15 00:00:00` to `2025-09-22 23:59:59` (UTC).
2. Start broad, then filter. If you get no hits, widen time or temporarily remove the `DeviceName` filter.

---

### Flag 1 — Initial Access (Attacker IP)

**Goal:** Find earliest **RDP** success to a “flare” host; capture **RemoteIP**.
**Steps:** Run → sort **Timestamp asc** → pick the earliest success.

```kusto
DeviceLogonEvents
| where Timestamp between (datetime(2025-09-15T00:00:00Z) .. datetime(2025-09-22T23:59:59Z))
| where DeviceName contains "flare"
| where LogonType == "RemoteInteractive"   // RDP
| project Timestamp, DeviceName, AccountName, RemoteIP, ActionType, LogonResult
| order by Timestamp asc
```

**Result:**
✅ **Flag 1:** `159.26.106.84`

Inline evidence:
![RDP success - Flag 1](evidence/screenshots/01_rdp_success.png)

---

### Flag 2 — Initial Access (Account)

**Goal:** Identify account used for RDP.
**Steps:** Use the same query as Flag 1 and inspect `AccountName` on the earliest successful `LogonResult`.

```kusto
DeviceLogonEvents
| where Timestamp between (datetime(2025-09-15T00:00:00Z) .. datetime(2025-09-22T23:59:59Z))
| where DeviceName contains "flare"
| where LogonType == "RemoteInteractive"   // RDP
| project Timestamp, DeviceName, AccountName, RemoteIP, ActionType, LogonResult
| order by Timestamp asc
```

**Result:**
✅ **Flag 2:** `slflare`

Inline evidence:
![RDP success - Account (Flag 2)](evidence/screenshots/01_rdp_success.png)

---

### Flag 3 — Malicious Execution (Binary name)

**Goal:** Identify executed binary name (renamed PowerShell binary).
**Steps:** Search process events for `msupdate.exe` or process command line references.

```kusto
DeviceProcessEvents
| where Timestamp between (datetime(2025-09-15T00:00:00Z) .. datetime(2025-09-22T23:59:59Z))
| where DeviceName contains "flare"
| where FileName == "msupdate.exe" or ProcessCommandLine has @"\Users\Public\msupdate.exe"
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

**Result:**
✅ **Flag 3:** `msupdate.exe` (from `C:\Users\Public\`)

Inline evidence:
![msupdate.exe execution - Flag 3](evidence/screenshots/02_msupdate_exec_full_cmd.png)

---

### Flag 4 — Malicious Execution (Full command line)

**Goal:** Capture the full command line used to run the binary.
**Steps:** Use the same process query and open the `ProcessCommandLine` field.

```kusto
DeviceProcessEvents
| where Timestamp between (datetime(2025-09-15T00:00:00Z) .. datetime(2025-09-22T23:59:59Z))
| where DeviceName contains "flare"
| where FileName == "msupdate.exe" or ProcessCommandLine has @"\Users\Public\msupdate.exe"
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

**Result:**
✅ **Flag 4:** `"C:\Users\Public\msupdate.exe" -ExecutionPolicy Bypass -File "C:\Users\Public\update_check.ps1"`

Inline evidence:
![msupdate full cmdline - Flag 4](evidence/screenshots/02_msupdate_exec_full_cmd.png)

---

### Flag 5 — Persistence (Scheduled Task Name)

**Goal:** Confirm scheduled task name used for persistence.
**Steps:** Search `DeviceProcessEvents` for `ProcessCommandLine` references to the task name and check `DeviceRegistryEvents` for `TaskCache` entries.

```kusto
// Process-side reference to the task name
DeviceProcessEvents
| where Timestamp between (datetime(2025-09-15T00:00:00Z) .. datetime(2025-09-22T23:59:59Z))
| where DeviceName contains "flare"
| where ProcessCommandLine has "MicrosoftUpdateSync"
| project Timestamp, DeviceName, FileName, ProcessCommandLine
| order by Timestamp asc
```

```kusto
// Registry evidence in TaskCache (optional)
DeviceRegistryEvents
| where Timestamp between (datetime(2025-09-15T00:00:00Z) .. datetime(2025-09-22T23:59:59Z))
| where DeviceName contains "flare"
| where RegistryKey contains @"\Schedule\TaskCache"
| where RegistryKey contains "MicrosoftUpdateSync" or RegistryValueData contains "MicrosoftUpdateSync"
| project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData
| order by Timestamp asc
```

**Result:**
✅ **Flag 5:** `MicrosoftUpdateSync`

Inline evidence:
![Scheduled task evidence - Flag 5](evidence/screenshots/03_task_MicrosoftUpdateSync.png)

---

### Flag 6 — Defense Evasion (Defender Exclusion Path)

**Goal:** Identify folder added to Defender exclusions.
**Steps:** Hunt registry writes under `...\Windows Defender\Exclusions\Paths`.

```kusto
DeviceRegistryEvents
| where Timestamp between (datetime(2025-09-15T00:00:00Z) .. datetime(2025-09-22T23:59:59Z))
| where DeviceName contains "flare"
| where RegistryKey contains @"Windows Defender\Exclusions\Paths"
| project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData
| order by Timestamp asc
```

**Result:**
✅ **Flag 6:** `C:\Windows\Temp`

Inline evidence:
![Defender exclusion - Flag 6](evidence/screenshots/04_defender_exclusion_windows_temp.png)

---

### Flag 7 — Discovery (Earliest Recon Command)

**Goal:** Find earliest host reconnaissance (e.g., `systeminfo`).
**Steps:** Search `cmd.exe` process command lines for `systeminfo` and take earliest timestamp.

```kusto
DeviceProcessEvents
| where Timestamp between (datetime(2025-09-15T00:00:00Z) .. datetime(2025-09-22T23:59:59Z))
| where DeviceName contains "flare" and FileName == "cmd.exe"
| where ProcessCommandLine has "systeminfo"
| project Timestamp, DeviceName, FileName, ProcessCommandLine
| order by Timestamp asc
| take 1
```

**Result:**
✅ **Flag 7:** `"cmd.exe" /c systeminfo`

Inline evidence:
![cmd systeminfo - Flag 7](evidence/screenshots/05_cmd_systeminfo.png)

---

### Flag 8 — Collection (Archive Created)

**Goal:** Confirm staging of an archive for exfiltration (e.g., `backup_sync.zip`).
**Steps:** Search file create events for the archive name.

```kusto
DeviceFileEvents
| where Timestamp between (datetime(2025-09-15T00:00:00Z) .. datetime(2025-09-22T23:59:59Z))
| where DeviceName contains "flare"
| where ActionType == "FileCreated" and FileName == "backup_sync.zip"
| project Timestamp, DeviceName, FolderPath, FileName
| order by Timestamp asc
```

**Result:**
✅ **Flag 8:** `backup_sync.zip` (typically in `%LOCALAPPDATA%\Temp`)

Inline evidence:
![backup\_sync created - Flag 8](evidence/screenshots/06_backup_sync_created.png)

---

### Flag 9 — C2 Destination (External IP contacted)

**Goal:** Identify suspicious external destination contacted by the host.
**Steps:** List outbound connections and inspect `RemoteIP`, `RemotePort`, `InitiatingProcessFileName`.

```kusto
DeviceNetworkEvents
| where Timestamp between (datetime(2025-09-15T00:00:00Z) .. datetime(2025-09-22T23:59:59Z))
| where DeviceName contains "flare"
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp asc
```

**Result:**
✅ **Flag 9:** `185.92.220.87`

Inline evidence:
![network C2 - Flag 9](evidence/screenshots/07_network_185.92.220.87.png)

---

### Flag 10 — Exfiltration Attempt (IP:Port)

**Goal:** Confirm upload attempt to external server (ip:port).
**Steps:** Hunt for `curl.exe` processes doing multipart POSTs (look for `-F "file=@...") and check `RemoteIP:RemotePort`.

```kusto
DeviceProcessEvents
| where Timestamp between (datetime(2025-09-15T00:00:00Z) .. datetime(2025-09-22T23:59:59Z))
| where DeviceName contains "flare" and FileName == "curl.exe"
| project Timestamp, DeviceName, ProcessCommandLine
| order by Timestamp asc
```

**Result:**
✅ **Flag 10:** `185.92.220.87:8081` (multipart POST of `backup_sync.zip`)

Inline evidence:
![curl exfil POST - Flag 10](evidence/screenshots/08_curl_post_8081.png)

---

## Investigation Summary

An external IP (`159.26.106.84`) successfully authenticated to a “flare” VM via RDP using the account `slflare`. The attacker executed a renamed PowerShell binary (`C:\Users\Public\msupdate.exe`) with `-ExecutionPolicy Bypass`, created persistence (`MicrosoftUpdateSync`), added a Defender exclusion for `C:\Windows\Temp`, performed discovery (`cmd.exe` /c `systeminfo`), staged an archive (`backup_sync.zip`), contacted `185.92.220.87`, and attempted exfiltration via HTTP to `185.92.220.87:8081` using `curl.exe`.

**Impact:** Medium — data staging observed; single endpoint; no availability impact noted.

**Where / Notable paths:**

* `C:\Users\Public\msupdate.exe`
* `C:\ProgramData\Microsoft\Windows\Update\mscloudsync.ps1`
* `C:\Users\SLFlare\AppData\Local\Temp\backup_sync.zip`
* Defender Exclusion: `C:\Windows\Temp`

---

## Recommendations (short)

**Immediate**

* Isolate host; block `159.26.106.84` & `185.92.220.87` (esp. port `8081`).
* Remove persistence (scheduled task `MicrosoftUpdateSync`, related services/scripts).
* Eradicate payloads: `msupdate.exe`, `mscloudsync.ps1`, `backup_sync.zip`.

**Short-Term (1–30 days)**

* Enforce RDP MFA/NLA/JIT + IP allow-lists.
* Enable PowerShell logging; alert on `-ExecutionPolicy Bypass` from Public/Temp.
* Alert on Defender exclusions under `...\Windows Defender\Exclusions\Paths`.

**Long-Term**

* Egress filtering + TLS inspection for non-standard ports (e.g., `8081`).
* ASR / App Control to block LOLBin abuse and execution from user-writable paths.
* Credential hygiene: lockout thresholds, stronger password policy, spray detection.

---

## MITRE Techniques (mapped)

* T1110.001 – Brute Force: Password Guessing
* T1078 – Valid Accounts
* T1059.003 – Command & Scripting Interpreter (Windows cmd)
* T1204.002 – User Execution (Malicious File)
* T1053.005 – Scheduled Task/Job
* T1562.001 – Impair Defenses (Defender exclusions)
* T1082 – System Information Discovery
* T1560.001 – Archive Collected Data
* T1071.001 – Application Layer Protocol (HTTP/S)
* T1048.003 – Exfiltration Over Unencrypted Protocol

---


