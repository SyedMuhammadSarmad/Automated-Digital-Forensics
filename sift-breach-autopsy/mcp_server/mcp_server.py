from fastmcp import FastMCP
import subprocess
import json
import datetime
import os
import hashlib

mcp = FastMCP("SIFT Forensic Server")

LOG_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "logs", "findings.jsonl"))
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
CACHE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "cache"))
os.makedirs(CACHE_DIR, exist_ok=True)


def run_cmd(cmd):
    result = subprocess.run(
        cmd,
         shell=True,
        capture_output=True,
        text=True,
        timeout=1800
    )
    return result.stdout + result.stderr


def run_cmd_cached(cmd):
    """Like run_cmd, but caches output keyed on the exact command string.

    First run for a given command executes it and saves the output to /tmp.
    Every later run with the SAME command reads the cached file instantly.
    Because the key is the full command string (which already includes the
    evidence path, offset, and plugin name), different inputs get different
    caches automatically, and identical commands share one cache.

    NOTE: /tmp clears on reboot, so caches must be re-warmed (re-run prestage)
    after any restart. The first (cold) run still pays the full scan cost, so
    pre-stage all slow tools before a demo.
    """
    key = hashlib.md5(cmd.encode()).hexdigest()[:12]
    cache_file = f"{CACHE_DIR}/cmdcache_{key}.txt"
    if os.path.exists(cache_file):
        with open(cache_file) as f:
            return f.read()
    output = run_cmd(cmd)
    with open(cache_file, "w") as f:
        f.write(output)
    return output


def log_finding(agent, tool, input_data, output, confidence="MEDIUM"):
    entry = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "agent": agent,
        "tool": tool,
        "input": input_data,
        "output": str(output)[:500],
        "confidence": confidence,
        "finding_id": f"{agent[:3].upper()}-{datetime.datetime.utcnow().strftime('%H%M%S')}"
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")
    return entry

@mcp.tool()
def identify_evidence(evidence_path: str) -> dict:
    """Identify type of evidence file and calculate MD5 hash for integrity verification."""
    file_output = run_cmd(f"file '{evidence_path}'")

    # Check file size first - skip MD5 for files larger than 1GB
    size_output = run_cmd(f"du -sh '{evidence_path}'")
    size_bytes = run_cmd(f"stat -c%s '{evidence_path}'").strip()

    try:
        size = int(size_bytes)
        if size > 1_000_000_000:  # larger than 1GB
            md5 = "skipped - file too large (>1GB)"
        else:
            md5 = run_cmd(f"md5sum '{evidence_path}'").strip()
    except:
        md5 = "could not calculate"

    result = {
        "file_type": file_output.strip(),
        "size": size_output.strip(),
        "md5": md5
    }
    log_finding("supervisor", "identify_evidence", {"path": evidence_path}, str(result))
    return result

@mcp.tool()
def list_partitions(image_path: str) -> dict:
    """List all partitions in disk image using mmls. Returns offsets needed for filesystem analysis."""
    output = run_cmd(f"mmls '{image_path}'")
    log_finding("supervisor", "list_partitions", {"image": image_path}, output)
    return {"partitions": output}

@mcp.tool()
def get_filesystem_info(image_path: str, offset: int = 0) -> dict:
    """Get filesystem type and Windows OS version from disk image using fsstat."""
    output = run_cmd(f"fsstat -o {offset} '{image_path}'")
    log_finding("supervisor", "get_filesystem_info", {"image": image_path, "offset": offset}, output)
    return {"filesystem_info": output}

# ── PERSISTENCE TOOLS ─────────────────────────────────────
@mcp.tool()
def get_registry_run_keys(hive_path: str) -> dict:
    """Extract auto-start programs from Windows registry run keys using RegRipper. Finds malware persistence."""
    output = run_cmd(f"regripper -r '{hive_path}' -p run")
    LEGITIMATE_RUN = ["onedrive", "teams", "slack", "googledrive", "dropbox",
                  "icloud", "zoom", "discord", "spotify", "chrome", "edge"]
    suspicious = [
        line for line in output.split("\n")
        if any(x in line.lower() for x in ["temp\\", "programdata\\temp", "appdata\\local\\temp"])
        and not any(x in line.lower() for x in LEGITIMATE_RUN)
    ]
    confidence = "HIGH" if suspicious else "LOW"
    log_finding("persistence", "get_registry_run_keys", {"hive": hive_path}, output, confidence)
    return {"raw": output, "suspicious": suspicious, "confidence": confidence}

@mcp.tool()
def get_services(hive_path: str) -> dict:
    """Extract Windows services from SYSTEM hive using RegRipper. Finds malicious auto-start services."""
    output = run_cmd(f"regripper -r '{hive_path}' -p services")
    log_finding("persistence", "get_services", {"hive": hive_path}, output)
    return {"services": output}

@mcp.tool()
def get_scheduled_tasks(image_path: str, offset: int = 0) -> dict:
    """List scheduled task files from disk image. Finds attacker-created tasks for persistence.
    SLOW (fls -r on full disk) → cached."""
    output = run_cmd_cached(f"fls -r -o {offset} '{image_path}' | grep -i task")
    log_finding("persistence", "get_scheduled_tasks", {"image": image_path}, output)
    return {"tasks": output}

@mcp.tool()
def get_process_cmdlines(memory_path: str) -> dict:
    """Get command line arguments of all running processes from memory dump using Volatility.
    SLOW (Volatility on memory image) → cached."""
    output = run_cmd_cached(f"vol -f '{memory_path}' windows.cmdline")
    LEGITIMATE = ["teams.exe", "slack.exe", "onedrive.exe", "googledrivefs",
              "chrome.exe", "msedge.exe", "crashpad", "filecoauth",
              "microsoftedge", "icloud", "dropbox", "zoom"]
    suspicious = [
        line for line in output.split("\n")
        if any(x in line.lower() for x in ["temp\\", "bypass", "encoded", "-enc ", "hidden", "-nop ", "invoke"])
        and not any(x in line.lower() for x in LEGITIMATE)
    ]
    log_finding("persistence", "get_process_cmdlines", {"memory": memory_path}, output)
    return {"raw": output, "suspicious": suspicious}

@mcp.tool()
def get_services_memory(memory_path: str) -> dict:
    """Scan all Windows services from memory including hidden ones using Volatility svcscan.
    SLOW (Volatility on memory image) → cached."""
    output = run_cmd_cached(f"vol -f '{memory_path}' windows.svcscan")
    log_finding("persistence", "get_services_memory", {"memory": memory_path}, output)
    return {"services": output}

# ── LATERAL MOVEMENT TOOLS ────────────────────────────────
@mcp.tool()
def get_rdp_logins(evtx_path: str) -> dict:
    """Extract RDP remote login events from Security.evtx. Event ID 4624 LogonType 10."""
    output = run_cmd(f"evtxexport '{evtx_path}' | grep -A 20 '4624'")
    log_finding("lateral", "get_rdp_logins", {"evtx": evtx_path}, output)
    return {"events": output}

@mcp.tool()
def get_explicit_credentials(evtx_path: str) -> dict:
    """Find explicit credential usage between machines. Event ID 4648 indicates lateral movement."""
    output = run_cmd(f"evtxexport '{evtx_path}' | grep -A 20 '4648'")
    log_finding("lateral", "get_explicit_credentials", {"evtx": evtx_path}, output)
    return {"events": output}

@mcp.tool()
def get_rdp_history(ntuser_path: str) -> dict:
    """Extract RDP connection history from NTUSER.DAT. Shows which machines attacker connected to."""
    output = run_cmd(f"regripper -r '{ntuser_path}' -p tsclient")
    log_finding("lateral", "get_rdp_history", {"ntuser": ntuser_path}, output)
    return {"rdp_history": output}

@mcp.tool()
def get_network_connections(memory_path: str) -> dict:
    """Get all TCP/UDP network connections from memory using Volatility netscan. Finds C2 connections.
    SLOW (Volatility on memory image) → cached."""
    output = run_cmd_cached(f"vol -f '{memory_path}' windows.netscan")
    external = [
        line for line in output.split("\n")
        if line and not any(x in line for x in ["127.0.0", "0.0.0.0", "::1"])
        and any(x in line for x in ["ESTABLISHED", "CLOSED", "CLOSE_WAIT"])
    ]
    log_finding("lateral", "get_network_connections", {"memory": memory_path}, output)
    return {"raw": output, "external_connections": external}

@mcp.tool()
def get_prefetch(image_path: str, offset: int = 0) -> dict:
    """List Windows prefetch files from disk image. Shows which programs were executed by attacker.
    SLOW (fls fallback recursive scan) → cached. The fast inode path is tried first;
    if it returns nothing, the recursive scan runs (and its result is cached)."""
    # The two-step fls logic produces a single command result we want cached as a unit,
    # so we resolve it here and cache the final output via a stable synthetic key.
    import hashlib as _h
    key = _h.md5(f"prefetch:{image_path}:{offset}".encode()).hexdigest()[:12]
    cache_file = f"{CACHE_DIR}/cmdcache_{key}.txt"
    if os.path.exists(cache_file):
        with open(cache_file) as f:
            output = f.read()
    else:
        output = run_cmd(f"fls -o {offset} '{image_path}' 247513 2>/dev/null | grep -i '\\.pf'")
        if not output.strip():
            output = run_cmd(f"fls -r -o {offset} '{image_path}' | grep -i '\\.pf'")
        with open(cache_file, "w") as f:
            f.write(output)

    suspicious = [
        line for line in output.split("\n")
        if any(x in line.upper() for x in ["PSEXEC", "MIMIKATZ", "WMIC", "RUNDLL", "MSHTA", "MRC", "NETSH"])
    ]
    log_finding("lateral", "get_prefetch", {"image": image_path}, output)
    return {"raw": output, "suspicious_executions": suspicious}

@mcp.tool()
def get_bulk_extractor(target_path: str) -> dict:
    """Carve network IPs from disk/memory via bulk_extractor net scanner. Finds C2 infrastructure.
    Cache-first: this tool produces a DIRECTORY of files (ip.txt, ip_histogram.txt), not a single
    stdout stream, so it uses its own directory-based cache (not run_cmd_cached)."""
    key = hashlib.md5(target_path.encode()).hexdigest()[:10]
    output_dir = f"{CACHE_DIR}/be_output_{key}"
    cache_marker = f"{output_dir}/.complete"

    if not os.path.exists(cache_marker):
        run_cmd(f"rm -rf {output_dir} && mkdir -p {output_dir}")
        run_cmd(f"bulk_extractor -j $(nproc) -E net -o {output_dir} '{target_path}'")
        run_cmd(f"touch {cache_marker}")

    results = {}
    for fname in ["ip.txt", "ip_histogram.txt"]:
        fpath = f"{output_dir}/{fname}"
        if os.path.exists(fpath):
            with open(fpath) as f:
                results[fname] = f.read()[:3000]
    log_finding("lateral", "get_bulk_extractor", {"target": target_path}, str(results))
    return results

# ── CREDENTIAL ACCESS TOOLS ───────────────────────────────
@mcp.tool()
def get_password_hashes(memory_path: str) -> dict:
    """Extract NTLM password hashes from memory using Volatility hashdump. Critical credential finding.
    SLOW (Volatility on memory image) → cached."""
    output = run_cmd_cached(f"vol -f '{memory_path}' windows.registry.hashdump")
    log_finding("credential", "get_password_hashes", {"memory": memory_path}, output, "HIGH")
    return {"hashes": output}

@mcp.tool()
def get_injected_code(memory_path: str) -> dict:
    """Detect injected malicious code in processes using Volatility malfind. Finds process injection.
    SLOW (Volatility malfind on memory image, the slowest plugin) → cached."""
    output = run_cmd_cached(f"vol -f '{memory_path}' windows.malware.malfind")
    lsass = [line for line in output.split("\n") if "lsass" in line.lower()]
    log_finding("credential", "get_injected_code", {"memory": memory_path}, output)
    return {"raw": output, "lsass_injection": lsass}

@mcp.tool()
def get_dll_list(memory_path: str) -> dict:
    """List DLLs loaded per process using Volatility dlllist. Detects injected or malicious DLLs.
    SLOW (Volatility on memory image) → cached."""
    output = run_cmd_cached(f"vol -f '{memory_path}' windows.dlllist")
    log_finding("credential", "get_dll_list", {"memory": memory_path}, output)
    return {"dlls": output}

@mcp.tool()
def get_sam_accounts(sam_path: str) -> dict:
    """Extract local user accounts and timestamps from SAM registry hive using RegRipper."""
    output = run_cmd(f"regripper -r '{sam_path}' -p samparse")
    log_finding("credential", "get_sam_accounts", {"sam": sam_path}, output)
    return {"accounts": output}

@mcp.tool()
def get_failed_logins(evtx_path: str) -> dict:
    """Find failed login attempts from Security.evtx. Event ID 4625 indicates password spraying."""
    output = run_cmd(f"evtxexport '{evtx_path}' | grep -A 15 '4625'")
    log_finding("credential", "get_failed_logins", {"evtx": evtx_path}, output)
    return {"failed_logins": output}

@mcp.tool()
def get_lsa_secrets(memory_path: str) -> dict:
    """Extract LSA secrets from memory using Volatility lsadump. Finds cached credentials.
    SLOW (Volatility on memory image) → cached."""
    output = run_cmd_cached(f"vol -f '{memory_path}' windows.registry.lsadump")
    log_finding("credential", "get_lsa_secrets", {"memory": memory_path}, output, "HIGH")
    return {"lsa_secrets": output}

# ── EXFILTRATION TOOLS ────────────────────────────────────
@mcp.tool()
def get_external_connections(memory_path: str) -> dict:
    """Find suspicious external network connections from memory. Identifies C2 and data exfiltration channels.
    SLOW (Volatility netscan on memory image) → cached. NOTE: this runs the SAME command as
    get_network_connections, so they share one cache automatically (whichever runs first warms it)."""
    output = run_cmd_cached(f"vol -f '{memory_path}' windows.netscan")
    external = [
        line for line in output.split("\n")
        if line and not any(x in line for x in ["127.0", "0.0.0.0"])
        and any(x in line for x in ["3389", "4444", "8080", "443", "22", "ESTABLISHED"])
    ]
    log_finding("exfil", "get_external_connections", {"memory": memory_path}, str(external), "HIGH")
    return {"raw": output, "suspicious_connections": external}

@mcp.tool()
def get_staging_files(image_path: str, offset: int = 0) -> dict:
    """Find data staging files in Temp directories. Identifies files prepared for exfiltration.
    SLOW (fls -r on full disk) → cached."""
    output = run_cmd_cached(f"fls -r -o {offset} '{image_path}' | grep -i temp")
    suspicious = [
        line for line in output.split("\n")
        if any(x in line.lower() for x in [".zip", ".rar", ".7z", ".tar", "cred", "dump", "data"])
    ]
    log_finding("exfil", "get_staging_files", {"image": image_path}, output)
    return {"raw": output, "suspicious_files": suspicious}

@mcp.tool()
def get_file_access_events(evtx_path: str) -> dict:
    """Find file access events before exfiltration from Security.evtx. Event ID 4663."""
    output = run_cmd(f"evtxexport '{evtx_path}' | grep -A 15 '4663'")
    log_finding("exfil", "get_file_access_events", {"evtx": evtx_path}, output)
    return {"file_access_events": output}

@mcp.tool()
def get_strings_memory(memory_path: str) -> dict:
    """Extract readable strings from memory to find hardcoded C2 IP addresses and URLs.
    SLOW (strings over full memory image) → cached."""
    output = run_cmd_cached(
        f"strings -n 8 '{memory_path}' | grep -E '^[0-9]{{1,3}}\\.[0-9]{{1,3}}\\.[0-9]{{1,3}}\\.[0-9]{{1,3}}$' | grep -v '127.0\\|0.0.0\\|255.255' | sort -u | head -50"
    )
    log_finding("exfil", "get_strings_memory", {"memory": memory_path}, output)
    return {"strings": output}

# ── SYNTHESIS TOOLS ───────────────────────────────────────
@mcp.tool()
def build_timeline(evidence_dir: str) -> dict:
    """Build unified forensic timeline from all evidence sources using log2timeline and Plaso."""
    plaso_file = "/tmp/timeline.plaso"
    output = run_cmd(f"log2timeline --storage-file {plaso_file} '{evidence_dir}'")
    log_finding("synthesis", "build_timeline", {"evidence_dir": evidence_dir}, output)
    return {"plaso_file": plaso_file, "status": output}

@mcp.tool()
def query_timeline(filter_query: str = "") -> dict:
    """Query the forensic timeline and return chronological events. Use after build_timeline."""
    plaso_file = "/tmp/timeline.plaso"
    output_csv = "/tmp/timeline_output.csv"
    cmd = f"psort -o l2tcsv '{plaso_file}' -w '{output_csv}'"
    if filter_query:
        cmd += f" \"{filter_query}\""
    run_cmd(cmd)
    if os.path.exists(output_csv):
        with open(output_csv) as f:
            csv_content = f.read()[:5000]
    else:
        csv_content = "No timeline found. Run build_timeline first."
    log_finding("synthesis", "query_timeline", {"filter": filter_query}, csv_content)
    return {"timeline": csv_content}

@mcp.tool()
def get_audit_log() -> dict:
    """Return complete audit trail of all forensic findings. Used by judges to verify investigation."""
    if not os.path.exists(LOG_FILE):
        return {"findings": []}
    with open(LOG_FILE) as f:
        findings = [json.loads(line) for line in f if line.strip()]
    return {"findings": findings, "total": len(findings)}

if __name__ == "__main__":
    mcp.run(transport="stdio")