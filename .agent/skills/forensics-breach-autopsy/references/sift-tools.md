# SIFT Forensic MCP Server — Tool Reference

*27 tools across 6 investigation categories*

Server: `FastMCP("SIFT Forensic Server")` · Transport: stdio
Findings log: `~/sift-breach-autopsy/logs/findings.jsonl`

---

## Supervisor Tools

### `identify_evidence`
Identify evidence file type and calculate MD5 hash. Skips MD5 for files >1 GB.
- **`evidence_path`** (str, required): Path to evidence file
- Returns: `{file_type, size, md5}`

### `list_partitions`
List all partitions using `mmls`. Returns offsets needed for filesystem analysis.
- **`image_path`** (str, required): Disk image path
- Returns: `{partitions}` — raw mmls output

### `get_filesystem_info`
Get filesystem type and Windows OS version using `fsstat`.
- **`image_path`** (str, required)
- **`offset`** (int, default 0): Partition offset from `list_partitions`
- Returns: `{filesystem_info}`

---

## Persistence Tools

### `get_registry_run_keys`
Extract auto-start programs from run keys via RegRipper. Flags Temp/AppData/Roaming paths HIGH.
- **`hive_path`** (str, required): SYSTEM or NTUSER.DAT hive
- Returns: `{raw, suspicious: [], confidence}`

### `get_services`
Extract Windows services from SYSTEM hive via RegRipper.
- **`hive_path`** (str, required)
- Returns: `{services}`

### `get_scheduled_tasks`
List scheduled task files (.job, .xml) from disk image via `fls`.
- **`image_path`** (str, required)
- **`offset`** (int, default 0)
- Returns: `{tasks}`

### `get_process_cmdlines`
Get process command lines from memory via `vol windows.cmdline`. Flags hidden/bypass/encoded.
- **`memory_path`** (str, required)
- Returns: `{raw, suspicious: []}`

### `get_services_memory`
Scan all Windows services from memory including hidden via `vol windows.svcscan`.
- **`memory_path`** (str, required)
- Returns: `{services}`

---

## Lateral Movement Tools

### `get_rdp_logins`
Extract RDP login events (4624 LogonType 10) from Security.evtx.
- **`evtx_path`** (str, required)
- Returns: `{events}`

### `get_explicit_credentials`
Find explicit credential use (4648) indicating lateral movement.
- **`evtx_path`** (str, required)
- Returns: `{events}`

### `get_rdp_history`
Extract RDP connection history from NTUSER.DAT via RegRipper tsclient.
- **`ntuser_path`** (str, required)
- Returns: `{rdp_history}`

### `get_network_connections`
Get all TCP/UDP connections from memory via `vol windows.netscan`. Pre-filters external ESTABLISHED.
- **`memory_path`** (str, required)
- Returns: `{raw, external_connections: []}`

### `get_prefetch`
List .pf prefetch files from disk. Pre-flags PSEXEC/MIMIKATZ/WMIC/MSHTA.
- **`image_path`** (str, required)
- **`offset`** (int, default 0)
- Returns: `{raw, suspicious_executions: []}`

### `get_bulk_extractor`
Scan target for IPs, URLs, emails, domains via `bulk_extractor`. Output to `/tmp/be_output/`.
- **`target_path`** (str, required): Disk image or memory dump
- Returns: `{ip.txt, url.txt, email.txt, domain.txt}` — up to 2000 chars each

---

## Credential Access Tools

### `get_password_hashes`
Extract NTLM hashes via `vol windows.registry.hashdump`. Logged HIGH confidence.
- **`memory_path`** (str, required)
- Returns: `{hashes}`

### `get_injected_code`
Detect injected code via `vol windows.malware.malfind`. Pre-filters lsass injection.
- **`memory_path`** (str, required)
- Returns: `{raw, lsass_injection: []}`

### `get_dll_list`
List DLLs per process via `vol windows.dlllist`.
- **`memory_path`** (str, required)
- Returns: `{dlls}`

### `get_sam_accounts`
Extract local accounts + timestamps from SAM hive via RegRipper samparse.
- **`sam_path`** (str, required)
- Returns: `{accounts}`

### `get_failed_logins`
Find failed logins (4625) — password spray indicator.
- **`evtx_path`** (str, required)
- Returns: `{failed_logins}`

### `get_lsa_secrets`
Extract LSA secrets via `vol windows.registry.lsadump`. Logged HIGH confidence.
- **`memory_path`** (str, required)
- Returns: `{lsa_secrets}`

---

## Exfiltration Tools

### `get_external_connections`
Find suspicious external connections from netscan (ports 443/8080/4444/22). Logged HIGH.
- **`memory_path`** (str, required)
- Returns: `{raw, suspicious_connections: []}`

### `get_staging_files`
Find staging files in Temp dirs. Pre-flags .zip/.rar/.7z/cred/dump.
- **`image_path`** (str, required)
- **`offset`** (int, default 0)
- Returns: `{raw, suspicious_files: []}`

### `get_file_access_events`
Find file access events (4663) before exfiltration.
- **`evtx_path`** (str, required)
- Returns: `{file_access_events}`

### `get_strings_memory`
Extract external IPs from memory strings via `strings -n 8 | grep IPv4`. Returns up to 50 unique IPs.
- **`memory_path`** (str, required)
- Returns: `{strings}`

---

## Synthesis Tools

### `build_timeline`
Build unified forensic timeline via `log2timeline`. Output: `/tmp/timeline.plaso`.
- **`evidence_dir`** (str, required): Directory containing all evidence
- Returns: `{plaso_file, status}`

### `query_timeline`
Query Plaso timeline via `psort -o l2tcsv`. Requires `build_timeline` first.
- **`filter_query`** (str, default ""): Optional filter string
- Returns: `{timeline}` — CSV up to 5000 chars

### `get_audit_log`
Return all forensic findings from `~/sift-breach-autopsy/logs/findings.jsonl`.
- Returns: `{findings: [{timestamp, agent, tool, input, output, confidence, finding_id}], total}`

---

## Finding ID Format

`{AGENT_PREFIX}-{HHMMSS}` — e.g. `PER-143022` (persistence agent, 14:30:22 UTC)

Agent prefixes: `sup` (supervisor), `per` (persistence), `lat` (lateral), `cre` (credential), `exi` (exfil), `syn` (synthesis)
