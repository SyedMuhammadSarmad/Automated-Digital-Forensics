#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SIFT Forensic Breach Autopsy - MCP orchestrator.

Connects to the SIFT MCP server via stdio, runs phase-specific forensic
tools, then filters findings locally (0 LLM tokens) to return only what
Claude needs. Mirrors the fetch-docs.py pattern from fetch-library-docs.

SIFT MCP server: FastMCP stdio transport
  ./sift-breach-autopsy/mcp_server/.venv/bin/python3
  ./sift-breach-autopsy/mcp_server/mcp_server.py

Usage:
  python investigate.py --phase persistence --hive-path /evidence/SYSTEM --memory-path /evidence/mem.dmp
  python investigate.py --phase lateral --evtx-path /evidence/Security.evtx --memory-path /evidence/mem.dmp
  python investigate.py --phase credential --memory-path /evidence/mem.dmp --output-type summary
  python investigate.py --phase triage --image-path /evidence/disk.E01
  python investigate.py --phase timeline --evidence-dir /evidence/
  python investigate.py --phase audit
"""

import argparse
import json
import os
import re
import sys
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

import importlib.util
_spec = importlib.util.spec_from_file_location(
    "mcp_client", os.path.join(SCRIPT_DIR, "mcp-client.py")
)
_mcp_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mcp_mod)
StdioTransport = _mcp_mod.StdioTransport
MCPClient = _mcp_mod.MCPClient
MCPClientError = _mcp_mod.MCPClientError


# ─── SIFT Server Command ─────────────────────────────────────────────────────

# SIFT_CMD = (
#     "/path-to-your/sift-breach-autopsy/mcp_server/.venv/bin/python3 "
#     "/path-to-your/sift-breach-autopsy/mcp_server/mcp_server.py"
# )

# Otherwise this the dyamic path for SIFT_CMD if you face issues in it do it in the above mentioned way
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "../../../../"))
VENV_PYTHON = os.path.join(PROJECT_ROOT, "sift-breach-autopsy", "mcp_server", ".venv", "bin", "python3")
SERVER_SCRIPT = os.path.join(PROJECT_ROOT, "sift-breach-autopsy", "mcp_server", "mcp_server.py")

# Fallback to system python3 if they didn't create a .venv
PYTHON_EXEC = VENV_PYTHON if os.path.exists(VENV_PYTHON) else "python3"

SIFT_CMD = f"{PYTHON_EXEC} '{SERVER_SCRIPT}'"

# ─── Global Persistent MCP Client ────────────────────────────────────────────
_transport = None
_client = None

def get_client() -> MCPClient:
    """Get or create a persistent MCP client connection."""
    global _transport, _client
    if _client is None:
        _transport = StdioTransport(get_sift_cmd())
        _client = MCPClient(_transport)
    return _client

def get_sift_cmd() -> str:
    return os.environ.get("SIFT_MCP_CMD", SIFT_CMD)


# ─── MCP Tool Caller ─────────────────────────────────────────────────────────

def call_tool(tool: str, params: dict, verbose: bool = False) -> dict:
    """Call one SIFT MCP tool using persistent connection."""
    if verbose:
        print(f"[TOOL] {tool}({json.dumps(params)})", file=sys.stderr)

    try:
        client = get_client()
        result = client.call_tool(tool, params)

        content = result.get("content", [])
        if content:
            raw = content[0].get("text", "{}")
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                return {"raw": raw}
        return result

    except MCPClientError as e:
        print(f"[SIFT_CALL_FAILED] Tool: {tool}\nError: {e}", file=sys.stderr)
        return {"error": str(e)}
    except Exception as e:
        print(f"[SIFT_CALL_FAILED] Tool: {tool}\nError: {e}", file=sys.stderr)
        return {"error": str(e)}
# ─── Phase → Tool Runners ─────────────────────────────────────────────────────

def run_triage(args) -> list[tuple[str, dict]]:
    results = []
    evidence = args.image_path or args.memory_path or args.evidence_dir
    if evidence:
        results.append(("identify_evidence", call_tool("identify_evidence", {"evidence_path": evidence}, args.verbose)))
    if args.image_path:
        results.append(("list_partitions", call_tool("list_partitions", {"image_path": args.image_path}, args.verbose)))
        results.append(("get_filesystem_info", call_tool("get_filesystem_info",
            {"image_path": args.image_path, "offset": args.offset}, args.verbose)))
    return results


def run_persistence(args) -> list[tuple[str, dict]]:
    results = []
    if args.hive_path:
        results.append(("get_registry_run_keys", call_tool("get_registry_run_keys", {"hive_path": args.hive_path}, args.verbose)))
        results.append(("get_services", call_tool("get_services", {"hive_path": args.hive_path}, args.verbose)))
    if args.image_path:
        results.append(("get_scheduled_tasks", call_tool("get_scheduled_tasks",
            {"image_path": args.image_path, "offset": args.offset}, args.verbose)))
    if args.memory_path:
        results.append(("get_process_cmdlines", call_tool("get_process_cmdlines", {"memory_path": args.memory_path}, args.verbose)))
        results.append(("get_services_memory", call_tool("get_services_memory", {"memory_path": args.memory_path}, args.verbose)))
    return results


def run_lateral(args) -> list[tuple[str, dict]]:
    results = []
    if args.evtx_path:
        results.append(("get_rdp_logins", call_tool("get_rdp_logins", {"evtx_path": args.evtx_path}, args.verbose)))
        results.append(("get_explicit_credentials", call_tool("get_explicit_credentials", {"evtx_path": args.evtx_path}, args.verbose)))
    if args.ntuser_path:
        results.append(("get_rdp_history", call_tool("get_rdp_history", {"ntuser_path": args.ntuser_path}, args.verbose)))
    if args.memory_path:
        results.append(("get_network_connections", call_tool("get_network_connections", {"memory_path": args.memory_path}, args.verbose)))
    if args.image_path:
        results.append(("get_prefetch", call_tool("get_prefetch",
            {"image_path": args.image_path, "offset": args.offset}, args.verbose)))
    target = args.memory_path or args.image_path
    if target:
        results.append(("get_bulk_extractor", call_tool("get_bulk_extractor", {"target_path": target}, args.verbose)))
    return results


def run_credential(args) -> list[tuple[str, dict]]:
    results = []
    if args.memory_path:
        results.append(("get_password_hashes", call_tool("get_password_hashes", {"memory_path": args.memory_path}, args.verbose)))
        results.append(("get_injected_code", call_tool("get_injected_code", {"memory_path": args.memory_path}, args.verbose)))
        results.append(("get_dll_list", call_tool("get_dll_list", {"memory_path": args.memory_path}, args.verbose)))
        results.append(("get_lsa_secrets", call_tool("get_lsa_secrets", {"memory_path": args.memory_path}, args.verbose)))
    if args.sam_path:
        results.append(("get_sam_accounts", call_tool("get_sam_accounts", {"sam_path": args.sam_path}, args.verbose)))
    if args.evtx_path:
        results.append(("get_failed_logins", call_tool("get_failed_logins", {"evtx_path": args.evtx_path}, args.verbose)))
    return results


def run_exfil(args) -> list[tuple[str, dict]]:
    results = []
    if args.memory_path:
        results.append(("get_external_connections", call_tool("get_external_connections", {"memory_path": args.memory_path}, args.verbose)))
        results.append(("get_strings_memory", call_tool("get_strings_memory", {"memory_path": args.memory_path}, args.verbose)))
    if args.image_path:
        results.append(("get_staging_files", call_tool("get_staging_files",
            {"image_path": args.image_path, "offset": args.offset}, args.verbose)))
    if args.evtx_path:
        results.append(("get_file_access_events", call_tool("get_file_access_events", {"evtx_path": args.evtx_path}, args.verbose)))
    return results


def run_timeline(args) -> list[tuple[str, dict]]:
    results = []
    if args.evidence_dir:
        results.append(("build_timeline", call_tool("build_timeline", {"evidence_dir": args.evidence_dir}, args.verbose)))
    results.append(("query_timeline", call_tool("query_timeline", {"filter_query": args.topic or ""}, args.verbose)))
    return results


def run_audit(_args) -> list[tuple[str, dict]]:
    return [("get_audit_log", call_tool("get_audit_log", {}))]


PHASE_RUNNERS = {
    "triage":      run_triage,
    "persistence": run_persistence,
    "lateral":     run_lateral,
    "credential":  run_credential,
    "exfil":       run_exfil,
    "timeline":    run_timeline,
    "audit":       run_audit,
}


# ─── Output Formatters ────────────────────────────────────────────────────────

_IOC_RE = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"           # IPv4
    r"|[0-9a-fA-F]{64}\b"                     # SHA256
    r"|[0-9a-fA-F]{40}\b"                     # SHA1
    r"|[0-9a-fA-F]{32}\b"                     # MD5
    r"|(?:https?|ftp)://[^\s\"]+"             # URL
    r"|\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|cn|xyz|onion)\b"  # domain
)


def _text_of(result: dict) -> str:
    """Flatten a result dict to searchable text."""
    return json.dumps(result, indent=0)


def format_suspicious(results: list[tuple[str, dict]]) -> str:
    """Show only pre-filtered suspicious lists and HIGH-confidence findings."""
    parts = []
    for tool, data in results:
        if "error" in data:
            continue
        susp = (
            data.get("suspicious")
            or data.get("suspicious_connections")
            or data.get("suspicious_files")
            or data.get("suspicious_executions")
            or data.get("lsass_injection")
            or data.get("external_connections")
        )
        confidence = data.get("confidence", "")
        if susp:
            parts.append(f"### {tool}")
            if confidence:
                parts.append(f"**Confidence: {confidence}**\n")
            for item in (susp if isinstance(susp, list) else [susp]):
                if item:
                    parts.append(f"- {item}")
            parts.append("")
        elif confidence == "HIGH":
            # No pre-filtered list but explicitly HIGH — show raw truncated
            raw = data.get("raw", data.get("hashes", data.get("lsa_secrets", "")))
            if raw:
                parts.append(f"### {tool} [HIGH]")
                parts.append(str(raw)[:500])
                parts.append("")
    return "\n".join(parts) if parts else "[NO_SUSPICIOUS_FINDINGS]\n\nNo high-confidence suspicious items found. Try --output-type all."


def format_iocs(results: list[tuple[str, dict]]) -> str:
    """Extract all IOCs across all tool results."""
    found: dict[str, set] = {"IPv4": set(), "SHA256": set(), "SHA1": set(), "MD5": set(), "URL": set(), "Domain": set()}
    bulk = {}

    for tool, data in results:
        if "error" in data:
            continue
        # bulk_extractor returns structured by type
        if tool == "get_bulk_extractor":
            for k, v in data.items():
                if v:
                    bulk[k] = v[:1000]
            continue
        text = _text_of(data)
        for ioc in _IOC_RE.findall(text):
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc):
                found["IPv4"].add(ioc)
            elif len(ioc) == 64:
                found["SHA256"].add(ioc)
            elif len(ioc) == 40:
                found["SHA1"].add(ioc)
            elif len(ioc) == 32 and ioc.isalnum():
                found["MD5"].add(ioc)
            elif ioc.startswith("http"):
                found["URL"].add(ioc)
            else:
                found["Domain"].add(ioc)

    parts = []
    for kind, iocs in found.items():
        if iocs:
            parts.append(f"### {kind} ({len(iocs)})")
            for ioc in sorted(iocs)[:30]:
                parts.append(f"- `{ioc}`")
            parts.append("")
    if bulk:
        parts.append("### bulk_extractor")
        for k, v in bulk.items():
            parts.append(f"**{k}**\n```\n{v}\n```\n")

    return "\n".join(parts) if parts else "[NO_IOCS_FOUND]\n\nNo IOCs extracted. Try --output-type all."


def format_summary(results: list[tuple[str, dict]]) -> str:
    """One-line summary per tool with confidence and key finding count."""
    lines = ["| Tool | Confidence | Key Findings |", "|------|------------|--------------|"]
    for tool, data in results:
        if "error" in data:
            lines.append(f"| `{tool}` | ERROR | {data['error'][:60]} |")
            continue
        conf = data.get("confidence", "-")
        susp = (
            data.get("suspicious") or data.get("suspicious_connections")
            or data.get("suspicious_files") or data.get("suspicious_executions")
            or data.get("lsass_injection") or data.get("external_connections")
        )
        count = len(susp) if isinstance(susp, list) else ("1" if susp else "0")
        lines.append(f"| `{tool}` | {conf} | {count} suspicious items |")
    return "\n".join(lines)


def format_all(results: list[tuple[str, dict]]) -> str:
    """Full raw output from all tools."""
    parts = []
    for tool, data in results:
        parts.append(f"## {tool}\n")
        parts.append(json.dumps(data, indent=2))
        parts.append("\n---\n")
    return "\n".join(parts)


OUTPUT_FORMATTERS = {
    "suspicious": format_suspicious,
    "iocs":       format_iocs,
    "summary":    format_summary,
    "all":        format_all,
    "full":       format_all,
}


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="SIFT DFIR breach autopsy via MCP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Phases:
  triage      identify_evidence + list_partitions + get_filesystem_info
  persistence registry run keys, services, scheduled tasks, process cmdlines
  lateral     RDP logins, explicit credentials, network connections, prefetch, bulk_extractor
  credential  password hashes, injected code, DLL list, SAM accounts, failed logins, LSA secrets
  exfil       external connections, staging files, file access events, memory strings
  timeline    build_timeline (log2timeline) + query_timeline (psort)
  audit       get_audit_log (all findings from findings.jsonl)

Output types:
  suspicious  Only pre-filtered suspicious items + HIGH confidence (default, most token-efficient)
  iocs        Extract all IPs, hashes, domains, URLs across all results
  summary     One-row-per-tool table with confidence + finding count
  all         Full raw JSON output from every tool

Examples:
  %(prog)s --phase triage --image-path /evidence/disk.E01
  %(prog)s --phase persistence --hive-path /evidence/SYSTEM --memory-path /evidence/mem.dmp
  %(prog)s --phase lateral --evtx-path /evidence/Security.evtx --memory-path /evidence/mem.dmp --ntuser-path /evidence/NTUSER.DAT --image-path /evidence/disk.E01 --offset 128
  %(prog)s --phase credential --memory-path /evidence/mem.dmp --sam-path /evidence/SAM --evtx-path /evidence/Security.evtx --output-type summary
  %(prog)s --phase exfil --memory-path /evidence/mem.dmp --image-path /evidence/disk.E01 --offset 128
  %(prog)s --phase timeline --evidence-dir /evidence/ --topic "lateral movement"
  %(prog)s --phase audit
""",
    )

    parser.add_argument("--phase", "-p", required=True,
        choices=["triage", "persistence", "lateral", "credential", "exfil", "timeline", "audit"],
        help="Investigation phase")
    parser.add_argument("--output-type", "-o", default="suspicious",
        choices=["suspicious", "iocs", "summary", "all", "full"],
        help="Output format (default: suspicious)")

    # Evidence paths
    parser.add_argument("--image-path", "-i", default="", help="Disk image (.E01, .dd, .raw)")
    parser.add_argument("--memory-path", "-m", default="", help="Memory dump (.vmem, .dmp, .raw)")
    parser.add_argument("--evtx-path", "-e", default="", help="Windows event log (.evtx)")
    parser.add_argument("--hive-path", "-r", default="", help="Registry hive (SYSTEM, SOFTWARE, etc.)")
    parser.add_argument("--ntuser-path", default="", help="NTUSER.DAT (for RDP history)")
    parser.add_argument("--sam-path", default="", help="SAM registry hive")
    parser.add_argument("--evidence-dir", "-d", default="", help="Evidence directory (for timeline)")
    parser.add_argument("--offset", type=int, default=0, help="Partition offset for disk tools (default: 0)")
    parser.add_argument("--topic", "-t", default="", help="Filter query for timeline or hint")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show tool calls and token stats")

    args = parser.parse_args()

    runner = PHASE_RUNNERS[args.phase]
    results = runner(args)

    if not results:
        print(
            "[NO_TOOLS_RAN]\n\n"
            f"No tools ran for phase '{args.phase}'.\n"
            "Provide the required evidence paths for this phase:\n\n"
            "  triage:      --image-path or --memory-path\n"
            "  persistence: --hive-path and/or --image-path and/or --memory-path\n"
            "  lateral:     --evtx-path and/or --memory-path and/or --ntuser-path and/or --image-path\n"
            "  credential:  --memory-path and/or --evtx-path and/or --sam-path\n"
            "  exfil:       --memory-path and/or --image-path and/or --evtx-path\n"
            "  timeline:    --evidence-dir\n"
            "  audit:       (no paths needed)\n"
        )
        sys.exit(1)

    if args.verbose:
        raw_words = sum(len(json.dumps(d).split()) for _, d in results)
        raw_tokens = int(raw_words * 1.3)
        print(f"[INFO] {len(results)} tools ran, ~{raw_tokens} tokens raw", file=sys.stderr)

    formatter = OUTPUT_FORMATTERS[args.output_type]
    output = formatter(results)
    print(output)

    if args.verbose:
        out_words = len(output.split())
        out_tokens = int(out_words * 1.3)
        raw_tokens_total = int(sum(len(json.dumps(d).split()) for _, d in results) * 1.3)
        savings = max(0, (raw_tokens_total - out_tokens) * 100 // raw_tokens_total) if raw_tokens_total else 0
        print(f"[INFO] Output: ~{out_tokens} tokens | Savings: {savings}%", file=sys.stderr)

        # Cleanup persistent connection
    global _transport
    if _transport:
        try:
            _transport.close()
        except Exception:
            pass

if __name__ == "__main__":
    main()
