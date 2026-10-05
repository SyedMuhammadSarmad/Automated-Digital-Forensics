---
name: forensics-breach-autopsy
description: DFIR breach investigation skill using the SIFT Forensic MCP Server. Runs Volatility, RegRipper, bulk_extractor, Plaso, and evtxexport via MCP to reconstruct breach timelines, extract IOCs, find persistence/lateral-movement/credential-access/exfil artifacts. Use when analyzing Windows memory dumps, disk images (.E01/.dd), EVTX logs, or registry hives. Triggers automatically during DFIR work — run the right phase before drawing conclusions.
---

# Forensics Breach Autopsy Skill

DFIR investigation via SIFT MCP Server with token-efficient findings extraction.

---

## SCRIPT LOCATION

```
~/.agent/skills/forensics-breach-autopsy/scripts/investigate.py
```

---

## WHEN TO INVOKE (Auto-Detection)

| Context | Signal | Phase |
|---------|--------|-------|
| **Triage** | New evidence, unknown scope, "what do we have" | `triage` |
| **Persistence hunt** | Run keys, services, scheduled tasks, startup | `persistence` |
| **Lateral movement** | RDP, SMB, PsExec, credential reuse, network hops | `lateral` |
| **Credential theft** | lsass, hashdump, malfind, failed logins, SAM | `credential` |
| **Data exfiltration** | Staging dirs, archives, suspicious outbound, C2 | `exfil` |
| **Timeline rebuild** | "when did", "sequence", chronology needed | `timeline` |
| **Audit trail** | Verify findings, court-ready log | `audit` |

**DO NOT INVOKE when:**
- Evidence path is unknown (ask user first)
- Writing the final report (use doc-coauthoring)
- No evidence file is available yet

---

## DECISION LOGIC

### 1. Identify Phase

```
Priority: User specifies → Alert type → Evidence type → "triage"
```

### 2. Match Evidence Paths to Phase

| Phase | Required Paths |
|-------|---------------|
| `triage` | `--image-path` OR `--memory-path` |
| `persistence` | `--hive-path` AND/OR `--image-path` AND/OR `--memory-path` |
| `lateral` | `--evtx-path` AND/OR `--memory-path` AND/OR `--ntuser-path` AND/OR `--image-path` |
| `credential` | `--memory-path` AND/OR `--evtx-path` AND/OR `--sam-path` |
| `exfil` | `--memory-path` AND/OR `--image-path` AND/OR `--evtx-path` |
| `timeline` | `--evidence-dir` |
| `audit` | (no paths needed) |

### 3. Select Output Type

| Goal | Output Type |
|------|-------------|
| Triage / full info | `all` |
| Fast high signal | `suspicious` |
| IOC extraction | `iocs` |
| Per-tool summary | `summary` |

---

## EVIDENCE DISCOVERY

When user provides an evidence directory, discover all paths automatically:

```bash
EVIDENCE_DIR="<path provided by user in prompt>"

# Auto-discover evidence files
DISK_IMAGE=$(find "$EVIDENCE_DIR" -type f -iname "*.E01" 2>/dev/null | head -1)
MEMORY=$(find "$EVIDENCE_DIR" -type f \( -iname "*.raw" -o -iname "*.dmp" -o -iname "*.mem" \) 2>/dev/null \
  | xargs -I{} stat --format="%s %n" {} 2>/dev/null | sort -rn | head -1 | awk '{print $2}')
EVTX=$(find "$EVIDENCE_DIR"     -type f -iname "Security.evtx" 2>/dev/null | head -1)
SOFTWARE=$(find "$EVIDENCE_DIR" -type f -iname "SOFTWARE"      2>/dev/null | head -1)
SYSTEM=$(find "$EVIDENCE_DIR"   -type f -iname "SYSTEM"        2>/dev/null | head -1)
SAM=$(find "$EVIDENCE_DIR"      -type f -iname "SAM"           2>/dev/null | head -1)
NTUSER=$(find "$EVIDENCE_DIR"   -type f -iname "NTUSER.DAT"    2>/dev/null | head -1)
```

## KNOWN DATASETS

```bash
# ROCBA case:
EVIDENCE_DIR="/path/to/evidence/rocba/"

# VANKO case:
EVIDENCE_DIR="/path/to/evidence/vanko/"

# Any new case — path comes from user prompt
```

---

## EXECUTION

Always use the full path to investigate.py (or relative to the repo root):

```bash
INVESTIGATE="./.agent/skills/forensics-breach-autopsy/scripts/investigate.py"
```

### Step 0 — Triage (always first, always --output-type all)

```bash
python3 $INVESTIGATE --phase triage \
  --image-path $DISK_IMAGE \
  --memory-path $MEMORY \
  --output-type all
```

### Step 1 — Persistence (run TWICE — SOFTWARE then SYSTEM)

> CRITICAL: SOFTWARE = run keys. SYSTEM = services (BITS, drivers).

```bash
# Pass 1 — SOFTWARE hive
python3 $INVESTIGATE --phase persistence \
  --hive-path $SOFTWARE \
  --image-path $DISK_IMAGE \
  --memory-path $MEMORY \
  --output-type suspicious

# Pass 2 — SYSTEM hive
python3 $INVESTIGATE --phase persistence \
  --hive-path $SYSTEM \
  --image-path $DISK_IMAGE \
  --memory-path $MEMORY \
  --output-type suspicious
```

### Step 2 — Lateral Movement

> CRITICAL: Always include --image-path for prefetch (finds MRC.exe, PSEXEC etc).

```bash
python3 $INVESTIGATE --phase lateral \
  --evtx-path $EVTX \
  --memory-path $MEMORY \
  --ntuser-path $NTUSER \
  --image-path $DISK_IMAGE \
  --output-type suspicious
```

### Step 3 — Credential Access

```bash
python3 $INVESTIGATE --phase credential \
  --memory-path $MEMORY \
  --evtx-path $EVTX \
  --sam-path $SAM \
  --output-type summary
```

### Step 4 — Exfiltration

```bash
python3 $INVESTIGATE --phase exfil \
  --memory-path $MEMORY \
  --image-path $DISK_IMAGE \
  --evtx-path $EVTX \
  --output-type suspicious
```

### Step 5 — Audit Trail

```bash
python3 $INVESTIGATE --phase audit
```

---

## PHASE → TOOLS MAPPING

### `triage`
- `identify_evidence(evidence_path)` — file type + MD5
- `list_partitions(image_path)` — mmls partition table
- `get_filesystem_info(image_path, offset)` — fsstat OS version

### `persistence`
- `get_registry_run_keys(hive_path)` — RegRipper run keys (SOFTWARE hive)
- `get_services(hive_path)` — RegRipper services (SYSTEM hive)
- `get_scheduled_tasks(image_path, offset)` — fls grep .job/.xml
- `get_process_cmdlines(memory_path)` — Volatility cmdline
- `get_services_memory(memory_path)` — Volatility svcscan

### `lateral`
- `get_rdp_logins(evtx_path)` — Event 4624 LogonType 10
- `get_explicit_credentials(evtx_path)` — Event 4648
- `get_rdp_history(ntuser_path)` — RegRipper tsclient
- `get_network_connections(memory_path)` — Volatility netscan
- `get_prefetch(image_path, offset)` — MRC/PSEXEC/MIMIKATZ .pf files ← CRITICAL

### `credential`
- `get_password_hashes(memory_path)` — Volatility hashdump (NTLM)
- `get_injected_code(memory_path)` — Volatility malfind / lsass injection
- `get_dll_list(memory_path)` — Volatility dlllist
- `get_sam_accounts(sam_path)` — RegRipper samparse
- `get_failed_logins(evtx_path)` — Event 4625 spray detection
- `get_lsa_secrets(memory_path)` — Volatility lsadump

### `exfil`
- `get_external_connections(memory_path)` — netscan ports 3389/443/8080/4444/22
- `get_staging_files(image_path, offset)` — Temp dir .zip/.rar/.7z/.bat
- `get_file_access_events(evtx_path)` — Event 4663
- `get_strings_memory(memory_path)` — strings grep external IPs

### `timeline`
- `build_timeline(evidence_dir)` — log2timeline → Plaso
- `query_timeline(filter_query)` — psort CSV output

### `audit`
- `get_audit_log()` — all findings from findings.jsonl

---

## KEY FINDINGS INTERPRETATION

### RDP Brute Force
```
Event 4625 rapid succession from same IP = credential stuffing
RDP tools: FreeRDP, Rdesktop, mstsc, Remmina = attacker RDP clients
```

### Attacker Tool Execution (Prefetch)
```
MRC.EXE    = Maxon Remote Control RAT (NOT legitimate)
NETSH.EXE  = firewall bypass
MIMIKATZ   = credential dumper
PSEXEC     = lateral movement
RUNDLL32   = DLL payload execution
```

### BITS Abuse
```
BITS service modified during attack window
= silent exfil/download/persistence
LastWrite time matches attack = NOT coincidental
```

### Staging Files
```
Numbered .zip files in Temp = attacker data staging
StarFury*.zip = project name = stolen intellectual property
```

### False Positives to IGNORE
```
iCloud connections (17.248.138.x)  = legitimate Apple traffic
OneDrive connections (52.114.x.x)  = legitimate Microsoft traffic
Teams connections (52.114.x.x)     = legitimate Microsoft traffic
Google Drive (172.217.x.x)         = legitimate Google traffic
Activity before attack window      = legitimate user activity
```

---

## ERROR HANDLING

| Error | Action |
|-------|--------|
| `[SIFT_CALL_FAILED]` | MCP server error — check mcp_server.py |
| `[NO_TOOLS_RAN]` | Missing required `--*-path` flags for this phase |
| `[NO_SUSPICIOUS_FINDINGS]` | Normal for triage — use `--output-type all` |
| `[EMPTY_RESULTS]` | Tool ran but found nothing — use `--output-type all` |
| Tool timeout | Volatility on 18GB RAM is slow — 5-10 min cold, instant cached |

---

## OUTPUT FORMAT

```
FINDING: [what was found]
EVIDENCE: [tool] → [file]
CONFIDENCE: HIGH / MEDIUM / LOW
MITRE: [ATT&CK ID and name]
TIMESTAMP: [UTC time]
```