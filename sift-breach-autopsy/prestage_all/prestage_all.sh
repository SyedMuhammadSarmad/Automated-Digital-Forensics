#!/usr/bin/env bash
# prestage_all.sh — warm ALL forensic tool caches before investigation.
#
# USAGE:
#   ./prestage_all.sh /path/to/evidence/rocba/
#   ./prestage_all.sh /path/to/evidence/vanko/
#
# PLACE THIS FILE AT:
#   ./sift-breach-autopsy/prestage_all/prestage_all.sh
#
# RUN WITH:
#   chmod +x ./sift-breach-autopsy/prestage_all/prestage_all.sh
#   ./sift-breach-autopsy/prestage_all/prestage_all.sh /path/to/evidence/

set -e

# ── Require evidence path argument ───────────────────────────────────────────

if [ -z "$1" ]; then
    echo ""
    echo "ERROR: Evidence path required."
    echo ""
    echo "Usage:"
    echo "  ./prestage_all.sh /path/to/evidence/rocba/"
    echo "  ./prestage_all.sh /path/to/evidence/vanko/"
    echo ""
    exit 1
fi

EVIDENCE_DIR="$1"

if [ ! -d "$EVIDENCE_DIR" ]; then
    echo ""
    echo "ERROR: Directory not found: $EVIDENCE_DIR"
    echo ""
    exit 1
fi

# ── Paths ─────────────────────────────────────────────────────────────────────

# Get the absolute path to the root of the GitHub repository
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Set paths relative to the repository root
SCRIPT_DIR="$REPO_ROOT/.agent/skills/forensics-breach-autopsy/scripts"
CACHE_DIR="$REPO_ROOT/sift-breach-autopsy/cache"
MCP_SERVER="$REPO_ROOT/sift-breach-autopsy/mcp_server/mcp_server.py"


# ── Evidence Discovery ────────────────────────────────────────────────────────

echo ""
echo "[INFO] Discovering evidence in: $EVIDENCE_DIR"

# Disk image — .E01 first segment only (not E02, E03...)
IMG=$(find "$EVIDENCE_DIR" -type f -iname "*.E01" 2>/dev/null | head -1)
[ -z "$IMG" ] && IMG=$(find "$EVIDENCE_DIR" -type f -iname "*.e01" 2>/dev/null | head -1)
[ -z "$IMG" ] && IMG=$(find "$EVIDENCE_DIR" -type f -iname "*.dd"  2>/dev/null | head -1)

# Memory dump — largest .raw or .dmp file
MEM=$(find "$EVIDENCE_DIR" -type f \( -iname "*.raw" -o -iname "*.dmp" -o -iname "*.mem" \) 2>/dev/null \
    | xargs -I{} stat --format="%s %n" {} 2>/dev/null \
    | sort -rn | head -1 | awk '{print $2}')

# Event log and registry hives
EVTX=$(find "$EVIDENCE_DIR"     -type f -iname "Security.evtx" 2>/dev/null | head -1)
SOFTWARE=$(find "$EVIDENCE_DIR" -type f -iname "SOFTWARE"      2>/dev/null | head -1)
SYSTEM=$(find "$EVIDENCE_DIR"   -type f -iname "SYSTEM"        2>/dev/null | head -1)
SAM=$(find "$EVIDENCE_DIR"      -type f -iname "SAM"           2>/dev/null | head -1)
NTUSER=$(find "$EVIDENCE_DIR"   -type f -iname "NTUSER.DAT"    2>/dev/null | head -1)

# ── Setup ─────────────────────────────────────────────────────────────────────

mkdir -p "$CACHE_DIR"
mkdir -p "$REPO_ROOT/sift-breach-autopsy/logs"

# Patch mcp_server to use persistent cache instead of /tmp
if grep -q "/tmp/cmdcache_" "$MCP_SERVER" 2>/dev/null; then
    echo "[INFO] Patching mcp_server cache path to persistent location..."
    sed -i "s|/tmp/cmdcache_|$CACHE_DIR/cmdcache_|g" "$MCP_SERVER"
    sed -i "s|/tmp/be_output_|$CACHE_DIR/be_output_|g" "$MCP_SERVER"
    echo "[INFO] Done."
fi

# Copy any existing /tmp caches to persistent location
cp /tmp/cmdcache_*.txt "$CACHE_DIR/" 2>/dev/null && \
    echo "[INFO] Copied /tmp cache to $CACHE_DIR" || true

# ── Print Evidence Summary ────────────────────────────────────────────────────

echo ""
echo "============================================================"
echo " PRESTAGE — Forensic Tool Cache Warmer"
echo " $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "============================================================"
echo ""
echo " Evidence directory: $EVIDENCE_DIR"
echo ""
[ -f "$IMG" ]      && echo "  ✅ Disk image:    $IMG"     || echo "  ❌ Disk image:    NOT FOUND"
[ -f "$MEM" ]      && echo "  ✅ Memory dump:   $MEM"     || echo "  ❌ Memory dump:   NOT FOUND"
[ -f "$EVTX" ]     && echo "  ✅ Security.evtx: $EVTX"    || echo "  ❌ Security.evtx: NOT FOUND"
[ -f "$SOFTWARE" ] && echo "  ✅ SOFTWARE:      $SOFTWARE" || echo "  ❌ SOFTWARE:      NOT FOUND"
[ -f "$SYSTEM" ]   && echo "  ✅ SYSTEM:        $SYSTEM"   || echo "  ❌ SYSTEM:        NOT FOUND"
[ -f "$SAM" ]      && echo "  ✅ SAM:           $SAM"      || echo "  ❌ SAM:           NOT FOUND"
[ -f "$NTUSER" ]   && echo "  ✅ NTUSER.DAT:    $NTUSER"   || echo "  ❌ NTUSER.DAT:    NOT FOUND"
echo ""
echo " Cache dir: $CACHE_DIR"
echo "============================================================"
echo ""

# ── Helper ────────────────────────────────────────────────────────────────────

run_phase() {
    local step="$1"
    local phase="$2"
    shift 2
    local args=("$@")

    echo -n "  [$step] phase=$phase ... "
    start=$(date +%s)

    python3 "$SCRIPT_DIR/investigate.py" \
        --phase "$phase" \
        "${args[@]}" \
        --output-type all > /dev/null 2>&1 \
        && status="✅" || status="❌"

    end=$(date +%s)
    echo "$status  ($(( end - start ))s)"
}

# ── Phase 1: Lateral ──────────────────────────────────────────────────────────

LATERAL_ARGS=()
[ -f "$EVTX" ]   && LATERAL_ARGS+=(--evtx-path   "$EVTX")
[ -f "$MEM" ]    && LATERAL_ARGS+=(--memory-path  "$MEM")
[ -f "$NTUSER" ] && LATERAL_ARGS+=(--ntuser-path  "$NTUSER")
[ -f "$IMG" ]    && LATERAL_ARGS+=(--image-path   "$IMG")

if [ ${#LATERAL_ARGS[@]} -gt 0 ]; then
    run_phase "1/5 lateral" lateral "${LATERAL_ARGS[@]}"
else
    echo "  [1/5 lateral] ⏭  skipped — no evidence found"
fi

# ── Phase 2: Persistence SOFTWARE ────────────────────────────────────────────

SOFT_ARGS=()
[ -f "$SOFTWARE" ] && SOFT_ARGS+=(--hive-path   "$SOFTWARE")
[ -f "$IMG" ]      && SOFT_ARGS+=(--image-path  "$IMG")
[ -f "$MEM" ]      && SOFT_ARGS+=(--memory-path "$MEM")

if [ ${#SOFT_ARGS[@]} -gt 0 ]; then
    run_phase "2/5 persistence-SOFTWARE" persistence "${SOFT_ARGS[@]}"
else
    echo "  [2/5 persistence-SOFTWARE] ⏭  skipped — no evidence found"
fi

# ── Phase 3: Persistence SYSTEM ──────────────────────────────────────────────

SYS_ARGS=()
[ -f "$SYSTEM" ] && SYS_ARGS+=(--hive-path   "$SYSTEM")
[ -f "$IMG" ]    && SYS_ARGS+=(--image-path  "$IMG")
[ -f "$MEM" ]    && SYS_ARGS+=(--memory-path "$MEM")

if [ ${#SYS_ARGS[@]} -gt 0 ]; then
    run_phase "3/5 persistence-SYSTEM" persistence "${SYS_ARGS[@]}"
else
    echo "  [3/5 persistence-SYSTEM] ⏭  skipped — no evidence found"
fi

# ── Phase 4: Credential ───────────────────────────────────────────────────────

CRED_ARGS=()
[ -f "$MEM" ]  && CRED_ARGS+=(--memory-path "$MEM")
[ -f "$SAM" ]  && CRED_ARGS+=(--sam-path    "$SAM")
[ -f "$EVTX" ] && CRED_ARGS+=(--evtx-path  "$EVTX")

if [ ${#CRED_ARGS[@]} -gt 0 ]; then
    run_phase "4/5 credential" credential "${CRED_ARGS[@]}"
else
    echo "  [4/5 credential] ⏭  skipped — no evidence found"
fi

# ── Phase 5: Exfil ────────────────────────────────────────────────────────────

EXFIL_ARGS=()
[ -f "$MEM" ]  && EXFIL_ARGS+=(--memory-path "$MEM")
[ -f "$IMG" ]  && EXFIL_ARGS+=(--image-path  "$IMG")
[ -f "$EVTX" ] && EXFIL_ARGS+=(--evtx-path  "$EVTX")

if [ ${#EXFIL_ARGS[@]} -gt 0 ]; then
    run_phase "5/5 exfil" exfil "${EXFIL_ARGS[@]}"
else
    echo "  [5/5 exfil] ⏭  skipped — no evidence found"
fi

# ── Summary ───────────────────────────────────────────────────────────────────

CACHE_COUNT=$(ls "$CACHE_DIR"/cmdcache_*.txt 2>/dev/null | wc -l)
CACHE_SIZE=$(du -sh "$CACHE_DIR" 2>/dev/null | cut -f1)

echo ""
echo "============================================================"
echo " PRESTAGE COMPLETE"
echo " $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo " Cache files: $CACHE_COUNT"
echo " Cache size:  $CACHE_SIZE"
echo " Cache path:  $CACHE_DIR"
echo "============================================================"
echo ""
echo " Run investigation now (instant):"
echo "   python3 ./.agent/skills/forensics-breach-autopsy/scripts/investigate.py --phase triage --output-type all"
echo ""
echo " Share cache with teammate:"
echo "   tar czf cache_$(date +%Y%m%d).tar.gz -C ./sift-breach-autopsy cache/"
echo "   # Upload tar.gz to Google Drive"
echo ""
echo " Teammate extracts with:"
echo "   tar xzf cache_*.tar.gz -C ./sift-breach-autopsy/"
echo ""
