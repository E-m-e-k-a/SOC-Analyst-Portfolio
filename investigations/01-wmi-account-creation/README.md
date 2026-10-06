# Incident Report: Unauthorized Local Account Creation via WMI

## 📋 Executive Summary
On February 14, 2022, an investigation was triggered following the detection of a new local user account creation on the host `Micheal.Beaven`. Triage revealed that an attacker utilized Windows Management Instrumentation (WMI) to remotely execute a command, creating a local user account named "Alberto". This activity indicates an adversary establishing persistence on the endpoint.

## 🕒 Incident Timeline
*   **Feb 14, 2022 (Event Time):** Windows Security Event 4720 logged a new user account "Alberto" being created with a suspicious UAC flag (`0x15`).
*   **May 11, 2022 (Ingest Time):** Splunk ingested the logs, prompting further investigation.

## 🔍 Technical Analysis & Splunk Queries

### 1. Account Creation Detection (Windows Event ID 4720)
The investigation began by searching for the creation of new user accounts across the environment.
**Query:** `index=main EventID="4720"`
**Findings:** Exactly 1 event found. A new account was created for `Alberto` on host `Micheal.Beaven` with the following suspicious attributes:
*   `New UAC Value`: `0x15` (Normal Account, Password Not Required)
*   `Password Last Set`: `<never>`
![Event 4720](https://raw.githubusercontent.com/E-m-e-ka/SOC-Analyst-Portfolio/main/investigations/01-wmi-account-creation/event_4720.png)
![Target Username](https://raw.githubusercontent.com/E-m-e-ka/SOC-Analyst-Portfolio/main/investigations/01-wmi-account-creation/target_username.png)


### 2. Root Cause Analysis via Sysmon (Event ID 1)
![Sysmon Event 1](https://raw.githubusercontent.com/E-m-e-ka/SOC-Analyst-Portfolio/main/investigations/01-wmi-account-creation/sysmon_event_1.png)
To determine *how* the account was created, the investigation pivoted to Sysmon process creation logs.
**Query:** `index=main EventID=1 Alberto`
**Findings:** 4 events returned. The `CommandLine` field revealed the exact attack vector:
```cmd
"C:\Windows\System32\Wbem\WMIC.exe" /node:WORKSTATION6 process call create "net user /add Alberto paw0rd1"
```
## 🎯 MITRE ATT&CK Mapping
*   **T1047:** Windows Management Instrumentation (Used to execute the remote process).
*   **T1136.001:** Create Account: Local Account (Created the "Alberto" account).
*   **T1059.003:** Command and Scripting Interpreter: Windows Command Shell (`net user` command).

## 🚨 Indicators of Compromise (IOCs)
*   **Hostname:** `Micheal.Beaven` (WORKSTATION6)
*   **User Account:** `Alberto` / Password: `paw0rd1`
*   **Process:** `WMIC.exe`
*   **Command Line:** `net user /add Alberto paw0rd1`
*   **Event IDs:** Windows Security 4720, Sysmon 1

## 🛡️ Recommendations & Containment
1.  **Isolate Host:** Immediately isolate `WORKSTATION6` (`Micheal.Beaven`) from the network.
2.  **Account Remediation:** Disable and delete the unauthorized "Alberto" account.
3.  **Credential Reset:** Force a password reset for all local and domain accounts that logged into `WORKSTATION6`.
4.  **Hunting:** Search the environment for other instances of `WMIC.exe /node:` or `net user /add` to identify further lateral movement.
