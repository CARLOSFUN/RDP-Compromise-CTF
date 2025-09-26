# VM RDP Compromise – End-to-End SOC Investigation (CTF)

[![Status: Complete](https://img.shields.io/badge/Status-Complete-brightgreen)](#)
[![MITRE ATT\&CK](https://img.shields.io/badge/MITRE-ATT%26CK-blue)](#3-who--what--when--where--why--how-required)
[![KQL](https://img.shields.io/badge/Queries-KQL-informational)](#1-kql-queries-steps--results)

A hands-on investigation of a **cloud VM RDP compromise** using **Microsoft Defender for Endpoint (MDE) Advanced Hunting (KQL)**.
This page contains **everything**: flags, steps, queries, results (screenshot slots), timeline, and recommendations — **all in one place**.

---

## Scenario

* **Challenge:** “Hide Your RDP: Password Spray Leads to Full Compromise”
* **Environment:** Cloud Windows VM (hostnames contain **"flare"**)
* **Tools:** Microsoft Defender for Endpoint (Advanced Hunting), Sentinel (optional)
* **Incident Date:** 14-Sep-2025
* **Investigation Window (UTC):** **15–22 Sep 2025**

---

## Key Findings (Flags)

| #  | Question                   | Answer                                                                                            |
| -- | -------------------------- | ------------------------------------------------------------------------------------------------- |
| 1  | Attacker IP Address        | `159.26.106.84`                                                                                   |
| 2  | Compromised Account        | `slflare`                                                                                         |
| 3  | Executed Binary Name       | `msupdate.exe`                                                                                    |
| 4  | Full Command Line          | `"C:\Users\Public\msupdate.exe" -ExecutionPolicy Bypass -File "C:\Users\Public\update_check.ps1"` |
| 5  | Persistence Task Name      | `MicrosoftUpdateSync`                                                                             |
| 6  | Defender Setting Modified  | `C:\Windows\Temp` (exclusion)                                                                     |
| 7  | Earliest Discovery Command | `"cmd.exe" /c systeminfo"`                                                                        |
| 8  | Archive Created            | `backup_sync.zip`                                                                                 |
| 9  | C2 Destination             | `185.92.220.87`                                                                                   |
| 10 | Exfiltration IP:Port       | `185.92.220.87:8081`                                                                              |

---

## Attack Timeline (UTC)

* **04:39:48 – 17 Sep:** Defender exclusion added → `C:\Windows\Temp`
* **04:40:28 – 17 Sep:** Discovery → `"cmd.exe" /c systeminfo`
* **04:41:30 – 17 Sep:** Archive created → `backup_sync.zip`
* **04:42:17 – 17 Sep:** First outbound to **185.92.220.87**
* **04:43:42 – 17 Sep:** Exfil attempt → **185.92.220.87:8081** (`curl.exe` POST)

---

## 📑 Table of Contents

1. [KQL Queries, Steps & Results](#1-kql-queries-steps--results)
2. [Investigation Summary](#2-investigation-summary-required)
3. [Who / What / When / Where / Why / How](#3-who--what--when--where--why--how-required)
4. [Recommendations](#4-recommendations-required)

---

## 1. KQL Queries, Steps & Results

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
![RDP success - Flag 1] <img width="1046" height="276" alt="image" src="https://github.com/user-attachments/assets/5964def5-c9fd-407e-a577-12299fd10373" />


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
![RDP success - Account (Flag 2)] <img width="1046" height="276" alt="image" src="https://github.com/user-attachments/assets/5964def5-c9fd-407e-a577-12299fd10373" />


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
![msupdate.exe execution - Flag 3]<img width="1046" height="295" alt="image" src="https://github.com/user-attachments/assets/081f4de6-8e5c-45f2-8c2f-8b89a19b8f5d" />


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
![msupdate full cmdline - Flag 4]<img width="1046" height="295" alt="flag4" src="https://github.com/user-attachments/assets/9594adb3-ff7d-4999-9966-d7583a2749e1" />


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
![Scheduled task evidence - Flag 5]<img width="1046" height="295" alt="flag5" src="https://github.com/user-attachments/assets/1be2e5df-2dc6-432f-a351-b2a76f5e982f" />


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
![Defender exclusion - Flag 6] <img width="1046" height="295" alt="flag6" src="https://github.com/user-attachments/assets/24133ac1-3536-4ee4-9ac6-d62eabdd96d7" />


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
![cmd systeminfo - Flag 7]<img width="1046" height="295" alt="flag7" src="https://github.com/user-attachments/assets/0a04b30a-b11c-4e89-9fec-93928f4dd338" />


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
![backup\_sync created - Flag 8]<img width="1046" height="295" alt="flag8" src="https://github.com/user-attachments/assets/611ee842-9cb6-4c63-9ad0-912ed3f6abe3" />


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

## 2. Investigation Summary (Required)

**What Happened:**
An external IP (`159.26.106.84`) successfully authenticated to the `slflare` account on a flare VM via RDP. The attacker executed `msupdate.exe`, added a scheduled task (`MicrosoftUpdateSync`), excluded `C:\Windows\Temp` from Defender, ran `systeminfo`, created `backup_sync.zip`, contacted C2 (`185.92.220.87`), and attempted exfil via HTTP to port `8081`.

**Timeline:**

* **Start:** `2025-09-17 04:39:48 UTC` (Defender exclusion write)
* **End:** `2025-09-17 04:43:42 UTC` (curl POST exfil attempt)
* **Duration:** ~**3m 54s**
* **Impact:** **Medium**

---

## 3. Who / What / When / Where / Why / How (Required)

**Who:**

* **Attacker:** `159.26.106.84` (initial RDP source); `185.92.220.87` (C2/exfil host)
* **Victim Account:** `slflare`
* **Affected System:** `slflarewinsysmo` (cloud VM)
* **Impact on Users:** Possible exposure of files in `backup_sync.zip`; no availability impact noted.

**What:**

* **Attack Type:** RDP brute force / password spray leading to compromise
* **Malicious Activities:**

  * Executed renamed PowerShell (`msupdate.exe`) with ExecutionPolicy Bypass
  * Persistence via **MicrosoftUpdateSync** (scheduled task)
  * Added Defender exclusion (`C:\Windows\Temp`)
  * Reconnaissance via `"cmd.exe" /c systeminfo`
  * Created archive `backup_sync.zip`
  * C2 connection + attempted exfil to `185.92.220.87:8081`
* **MITRE ATT&CK Mapping:**

  * T1110.001 – Brute Force
  * T1078 – Valid Accounts
  * T1204.002 – User Execution
  * T1059.003 – Command Interpreter
  * T1053.005 – Scheduled Task
  * T1562.001 – Impair Defenses
  * T1082 – System Discovery
  * T1560.001 – Archive Data
  * T1071.001 – Application Layer Protocol
  * T1048.003 – Exfiltration over Unencrypted Protocol

**When:**

* First Activity: `2025-09-17 04:39:48 UTC`
* Last Activity: `2025-09-17 04:43:42 UTC`
* Duration: ~**3m 54s**
* Detection Time: `2025-09-17 04:43:42 UTC`
* Still Active? No

**Where:**

* Target: `slflarewinsysmo`
* Origin: `159.26.106.84`
* Segment: Cloud VM / Lab
* Files:

  * `C:\Users\Public\msupdate.exe`
  * `C:\ProgramData\Microsoft\Windows\Update\mscloudsync.ps1`
  * `C:\Users\SLFlare\AppData\Local\Temp\backup_sync.zip`
  * Defender exclusion: `C:\Windows\Temp`

**Why:**

* Motive: Data theft + persistence
* Value: User data, possible pivot point

**How:**

* Initial Access: RDP with valid creds (password spraying)
* Tools: msupdate.exe (renamed PowerShell), cmd.exe, curl.exe
* Persistence: Task `"MicrosoftUpdateSync"`
* Collection: `backup_sync.zip`
* Comms: HTTP(S) → `185.92.220.87`, exfil to `185.92.220.87:8081`

---

## 4. Recommendations (Required)

**Immediate:**

1. Isolate host & block outbound to `185.92.220.87` (esp. `8081`)
2. Remove persistence (`MicrosoftUpdateSync`) + artifacts
3. Delete payloads (`msupdate.exe`, `mscloudsync.ps1`, `backup_sync.zip`)

**Short-term (1–30 days):**
4. Harden RDP (MFA, NLA, IP allowlists/JIT)
5. Enable PowerShell logging (block `-ExecutionPolicy Bypass` abuse)
6. Alert on Defender exclusions (esp. writable dirs like Temp)

**Long-term:**
7. Egress filtering + TLS inspection for ports like `8081`
8. ASR/App Control: block LOLBin abuse + user-writable execs
9. Credential hygiene: strong passwords, lockouts, spray detection

**Detection Improvements:**

* Gaps: limited URL/UA context → rely on IP + process cmdline
* Alerts: new scheduled tasks, Defender exclusions, curl.exe POST with file upload
* Queries: start broad → refine by `DeviceName contains "flare"`

**Report Status:** Complete

**Next Review:** 29-Sep-2025

**Distribution:** Cyber Range

