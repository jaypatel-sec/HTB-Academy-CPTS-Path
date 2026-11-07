# Attacking Common Applications — Skills Assessment III

| Field | Details |
|-------|---------|
| Module | 24 — Attacking Common Applications |
| Assessment | Skills Assessment III |
| Difficulty | Medium |
| OS | Windows |
| Target | `10.129.95.200` |
| Date | September 2026 |

---

## Table of Contents

- [Attack Chain Summary](#attack-chain-summary)
- [Question 1 — Hardcoded Database Password in MultimasterAPI.dll](#question-1--hardcoded-database-password-in-multimasterapidll)
- [Flags](#flags)
- [Lessons Learned](#lessons-learned)
- [Full Attack Chain Reference](#full-attack-chain-reference)
- [Commands Reference](#commands-reference)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)

---

## Attack Chain Summary

| Step | Technique | Outcome |
|------|-----------|--------|
| 1 | RDP access with provided credentials | Desktop session on Windows target as `administrator` |
| 2 | File Explorer navigation to `C:\inetpub\wwwroot\bin` | Located `MultimasterAPI.dll` — a .NET web API assembly |
| 3 | Drag `MultimasterAPI.dll` into **dnSpy** | Decompiled .NET assembly reveals hardcoded SQL connection string |
| 4 | Inspect `DatabaseConfiguration` class | Extracted plaintext database password from connection string |

---

## Question 1 — Hardcoded Database Password in MultimasterAPI.dll

**Question:** "What is the hardcoded password for the database connection in the MultimasterAPI.dll file?"

### Step 1 — Connect via RDP

The assessment provides initial access credentials. **xfreerdp** is used to establish a Remote Desktop Protocol session to the target Windows host. The `administrator` account provides full desktop access, simulating a scenario where an attacker has obtained local admin credentials or is performing an internal assessment with provided access.

```bash
Hackerpatel007_1@htb[/htb]$ xfreerdp /v:10.129.95.200 /u:administrator /p:HTB{flag_redacted} /dynamic-resolution
```

```
[17:33:32:641] [15032:15035] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[17:33:32:641] [15032:15035] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[17:33:32:641] [15032:15035] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
<SNIP>
```

The `/dynamic-resolution` flag allows the RDP window to resize to match the local display — useful for working comfortably in the remote desktop environment.

### Step 2 — Navigate to the Web Application Binary Directory

Once the desktop session is open, File Explorer is used to navigate to `C:\inetpub\wwwroot\bin`. This is the standard IIS web root binary directory — ASP.NET and .NET Framework applications store their compiled DLL assemblies here. The file `MultimasterAPI.dll` is present in this directory.

> **Key concept:** IIS-hosted .NET web applications compile to DLL assemblies stored in `/bin/` under the web root. These DLLs are the compiled forms of the application's source code. When source code is not available, decompiling the DLL with a .NET reverse engineering tool recovers near-source-quality code, including any hardcoded values that were baked into the compiled binary.

### Step 3 — Decompile the DLL with dnSpy

**dnSpy** is an open-source .NET debugger and assembly editor that can decompile `.NET` DLL files back to C# or VB.NET source code. It is located at `C:\Tools\dnSpy\dnSpy.exe` on the target.

The `MultimasterAPI.dll` file is dragged directly onto the `dnSpy.exe` executable (or opened via File → Open). **dnSpy** immediately decompiles all classes and namespaces within the assembly and presents them in a readable tree view.

### Step 4 — Locate the Hardcoded Credential in the SQL Connection String

Browsing the decompiled assembly tree in dnSpy, the database configuration class is located. Within it, a SQL Server connection string is hardcoded directly in the C# code:

```
Server=MULTIMASTER;Database=Hub_DB;User Id=finder;Password=HTB{flag_redacted};
```

The connection string reveals:
- **Server:** `MULTIMASTER`
- **Database:** `Hub_DB`
- **User:** `finder`
- **Password:** `HTB{flag_redacted}`

> **Note:** The password is embedded directly in the application's compiled binary rather than being read from a configuration file, environment variable, or secrets manager. This means even if the web server's filesystem were locked down, the credential is still recoverable by any user who can access and decompile the DLL — including any attacker who obtains the DLL through directory traversal, file read vulnerabilities, or physical access to the server.

> **Answer:** `HTB{flag_redacted}`

---

## Flags

| Question | Description | Answer |
|----------|-------------|--------|
| Q1 | Hardcoded DB password in `MultimasterAPI.dll` | `HTB{flag_redacted}` |

---

## Lessons Learned

- **Hardcoded credentials in compiled .NET assemblies are trivially recoverable.** Developers sometimes assume that compiled DLL files are "safe" because they are not plaintext source code. This is a fundamental misconception — .NET assemblies compiled to IL (Intermediate Language) bytecode are fully reversible to near-original C# with tools like **dnSpy**, **ILSpy**, or **dotPeek**. Any string, including connection strings, API keys, or passwords, that is hardcoded in the source becomes permanently embedded in the compiled output and is recoverable without any special access.

- **The `C:\inetpub\wwwroot\bin` directory is always the first stop when auditing IIS-hosted .NET applications.** In real engagements, any access to the filesystem of an IIS server (via LFI, arbitrary file read, SMB share access, or physical/RDP access) should include downloading the DLL files from the web application's `/bin/` directory for offline decompilation. This often yields database credentials, internal API keys, SMTP credentials, and other secrets baked into the application during development.

- **SQL connection strings are the highest-value target when reversing .NET web application assemblies.** A SQL connection string with a username and password gives direct database access, which in Windows environments often means:
  1. Lateral movement via SQL Server's `xp_cmdshell` if the DB user has sysadmin privileges
  2. Credential harvesting from application database tables (users, session tokens, API keys)
  3. Data exfiltration of sensitive business records

- **Secrets must never be hardcoded — use externalized configuration with access controls.** The correct approach is to store database credentials in:
  - `web.config` with DPAPI encryption (Windows)
  - Environment variables injected at runtime
  - Azure Key Vault / AWS Secrets Manager / HashiCorp Vault
  - Encrypted app settings files with keys stored separately from the web root

  Any of these approaches prevents the credential from appearing in decompiled code, even if the DLL is obtained by an attacker.

- **dnSpy enables live debugging of running .NET applications, not just static analysis.** Beyond credential hunting, dnSpy can attach to running IIS worker processes (`w3wp.exe`) and set breakpoints in decompiled code — allowing an attacker (or penetration tester with appropriate access) to intercept runtime values, modify business logic at runtime, and observe application behaviour from inside the process. This is a powerful post-exploitation technique on Windows targets running .NET applications.

---

## Full Attack Chain Reference

```
xfreerdp /v:10.129.95.200 /u:administrator -> RDP session established
        ↓
File Explorer -> C:\inetpub\wwwroot\bin
        ↓
MultimasterAPI.dll identified (compiled .NET assembly)
        ↓
C:\Tools\dnSpy\dnSpy.exe <- drag MultimasterAPI.dll
        ↓
.NET assembly decompiled to C#
        ↓
DatabaseConfiguration class -> SQL connection string
  Server=MULTIMASTER | Database=Hub_DB | User=finder | Password=HTB{flag_redacted}
        ↓
Hardcoded credential extracted [HTB{flag_redacted}]
```

---

## Commands Reference

| Command | Purpose |
|---------|---------|
| `xfreerdp /v:<target> /u:administrator /p:<password> /dynamic-resolution` | Establish RDP session with dynamic screen resolution |
| `C:\inetpub\wwwroot\bin` | Standard IIS .NET application binary directory — target for DLL harvesting |
| `dnSpy.exe` (File → Open → MultimasterAPI.dll) | Decompile .NET assembly and browse class/method tree |
| Drag-and-drop DLL onto `dnSpy.exe` | Alternate method to open assembly for decompilation |

---

## MITRE ATT&CK Mapping

| Technique | Sub-Technique | Description |
|-----------|---------------|-------------|
| T1021 | T1021.001 — Remote Desktop Protocol | xfreerdp connection to Windows target using `administrator` credentials via RDP |
| T1083 | — | File and Directory Discovery — File Explorer navigation to `C:\inetpub\wwwroot\bin` to locate `MultimasterAPI.dll` |
| T1552 | T1552.001 — Credentials in Files | Extraction of hardcoded SQL database password from compiled .NET DLL using dnSpy decompilation |

---

*Part of the HTB Academy CPTS path — Attacking Common Applications module.*  
*Penetration Tester role in India | Target: January 2027*
