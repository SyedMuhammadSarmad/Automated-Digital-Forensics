# DFIR Investigation Playbooks

Real-world patterns for the SIFT Forensic Skill.

---

## Pattern A: Full Breach Triage (Unknown Scope)

Start here when you have a disk image and memory dump but don't yet know the attack vector.

```bash
# Step 1 — identify evidence
python scripts/investigate.py --phase triage --image-path /evidence/disk.E01

# Step 2 — get partition offset from triage output, then run all phases
python scripts/investigate.py --phase persistence \
  --hive-path /mnt/evidence/SYSTEM \
  --memory-path /evidence/mem.dmp \
  --image-path /evidence/disk.E01 --offset 128

python scripts/investigate.py --phase lateral \
  --evtx-path /evidence/Security.evtx \
  --memory-path /evidence/mem.dmp \
  --ntuser-path /mnt/evidence/NTUSER.DAT \
  --image-path /evidence/disk.E01 --offset 128

python scripts/investigate.py --phase credential \
  --memory-path /evidence/mem.dmp \
  --sam-path /mnt/evidence/SAM \
  --evtx-path /evidence/Security.evtx --output-type summary

python scripts/investigate.py --phase exfil \
  --memory-path /evidence/mem.dmp \
  --image-path /evidence/disk.E01 --offset 128
```

---

## Pattern B: Ransomware Investigation

Focus: initial access → staging → encryption trigger

```bash
# Find staging / archive files
python scripts/investigate.py --phase exfil \
  --image-path /evidence/disk.E01 --offset 128 \
  --evtx-path /evidence/Security.evtx \
  --output-type suspicious

# Find how attacker persisted before triggering
python scripts/investigate.py --phase persistence \
  --hive-path /mnt/evidence/SYSTEM \
  --image-path /evidence/disk.E01 --offset 128 \
  --output-type suspicious

# Build timeline to sequence events
python scripts/investigate.py --phase timeline \
  --evidence-dir /evidence/ \
  --topic "encryption staging"
```

---

## Pattern C: APT Persistence Hunt

Focus: long-term dwell, registry/service persistence, LOLBins

```bash
python scripts/investigate.py --phase persistence \
  --hive-path /mnt/evidence/SYSTEM \
  --hive-path /mnt/evidence/SOFTWARE \
  --memory-path /evidence/mem.dmp \
  --image-path /evidence/disk.E01 --offset 128 \
  --output-type suspicious
```

Check `suspicious_executions` in output for MSHTA, RUNDLL32, WMIC prefetch hits.

---

## Pattern D: Credential Theft + Pass-the-Hash

Focus: lsass injection, NTLM hash extraction, explicit credential use

```bash
# Memory — injected code + hashes
python scripts/investigate.py --phase credential \
  --memory-path /evidence/mem.dmp \
  --output-type suspicious

# Event logs — 4648 explicit credential use across hosts
python scripts/investigate.py --phase lateral \
  --evtx-path /evidence/Security.evtx \
  --output-type suspicious
```

`lsass_injection` in malfind output = high-confidence credential dump. Pair with `get_explicit_credentials` 4648 events to map lateral path.

---

## Pattern E: C2 Beacon Identification

Focus: network connections, bulk_extractor IOCs, memory strings

```bash
# External connections from memory
python scripts/investigate.py --phase lateral \
  --memory-path /evidence/mem.dmp \
  --image-path /evidence/disk.E01 --offset 128 \
  --output-type iocs

# Memory strings for hardcoded IPs
python scripts/investigate.py --phase exfil \
  --memory-path /evidence/mem.dmp \
  --output-type iocs
```

Combine `external_connections` (netscan ports 443/8080/4444) with `get_strings_memory` IPs and `bulk_extractor` domains.

---

## Pattern F: Timeline Reconstruction for Court

```bash
# Build full Plaso supertimeline (slow — may take hours for large evidence)
python scripts/investigate.py --phase timeline --evidence-dir /evidence/

# Query specific attacker activity window
python scripts/investigate.py --phase timeline \
  --topic "2024-03-15 lateral movement psexec"

# Get full audit trail of investigation findings
python scripts/investigate.py --phase audit
```

`get_audit_log` returns all `finding_id` entries with timestamps for chain-of-custody documentation.

---

## Output Type Decision

| Situation | Use |
|-----------|-----|
| First look at a phase | `suspicious` — fastest, pre-filtered |
| Need blocklist / SIEM rules | `iocs` — all IPs, hashes, domains |
| Briefing an analyst | `summary` — table of tools + confidence |
| Deep dive / nothing found | `all` — full JSON, no filtering |

---

## Evidence Path Cheat Sheet

| Evidence | Typical Path (SIFT) |
|----------|---------------------|
| Disk image | `/evidence/disk.E01` |
| Memory dump | `/evidence/mem.dmp` or `mem.vmem` |
| SYSTEM hive | Mount image → `/mnt/evidence/Windows/System32/config/SYSTEM` |
| SOFTWARE hive | `/mnt/evidence/Windows/System32/config/SOFTWARE` |
| SAM hive | `/mnt/evidence/Windows/System32/config/SAM` |
| NTUSER.DAT | `/mnt/evidence/Users/<username>/NTUSER.DAT` |
| Security.evtx | `/mnt/evidence/Windows/System32/winevt/Logs/Security.evtx` |
| Evidence dir | `/evidence/` (parent of all above) |

Partition offset: read from `list_partitions` output — look for the NTFS entry Start value, multiply by 512.
