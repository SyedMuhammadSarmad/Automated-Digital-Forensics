# 🔍 Automated Digital Forensics & Breach Autopsy

An AI-powered, **Model Context Protocol (MCP)** orchestrator for Digital Forensics and Incident Response (DFIR). 

Designed to batch-process heavy forensic artifacts without hitting LLM rate limits, this suite bridges the gap between deep forensic analysis and AI-driven investigations, enabling instant, automated forensic insights.

---

## ✨ Key Features

- ⚡ **Rate-Limit Friendly:** Running raw forensic tools (Volatility, Plaso) takes minutes and produces megabytes of text. This repository uses a smart local orchestrator (`investigate.py`) that executes tools and filters findings *locally*, surfacing only high-confidence IOCs and suspicious behaviors to your LLM.
- 💾 **Prestage Cache Warmer:** Includes a bash script to pre-process evidence (e.g., overnight). When you begin your interactive AI investigation, the results are delivered instantly.
- 🤖 **Universal Agent Compatibility:** Built natively as an **Antigravity AI Skill**, but easily drops into Claude Code, Cursor, or any other CLI agent via a simple system prompt.
- 📂 **Monorepo Design:** Everything is packaged dynamically. No hardcoded paths—just clone, sync, and investigate.

---

## 🚀 Repository Structure

```text
Automated-Digital-Forensics/
├── .agent/skills/forensics-breach-autopsy/
│   ├── SKILL.md             # Native Antigravity playbook
│   └── scripts/
│       └── investigate.py   # Local tool orchestrator & filter
├── sift-breach-autopsy/
│   ├── mcp_server/          # The FastMCP Server wrapping DFIR tools
│   └── prestage_all/        # Bash script for pre-warming caches
└── README.md
```

---

## 🛠️ System Requirements & Dependencies Setup

### Evidence Requirements
An evidence directory is **required** to perform an investigation. Your evidence folder should contain standard forensic artifacts such as:
- **Disk Images:** `.E01`, `.dd`, or `.raw`
- **Memory Dumps:** `.mem`, `.dmp`, or `.vmem`
- **Windows Event Logs:** `Security.evtx`
- **Registry Hives:** `SYSTEM`, `SOFTWARE`, `SAM`, `NTUSER.DAT`

### Tool Dependencies
This suite orchestrates local tools. You must run this on a system (like a SANS SIFT Workstation) that has the tools installed, or manually set up a basic Ubuntu/WSL machine:

```bash
# Step 1: Basic OS Setup
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install -y python3 python3-pip python3-venv git curl wget p7zip-full unzip

# Step 2: SIFT Core Tools (The Sleuth Kit: fls, icat, mmls, fsstat)
sudo apt-get install -y sleuthkit

# Step 3: Volatility 3 & FastMCP
pip install volatility3 fastmcp

# Step 4: RegRipper
sudo apt-get install -y libparse-win32registry-perl
git clone https://github.com/keydet89/RegRipper3.0.git ~/regripper
sudo ln -s ~/regripper/rip.pl /usr/local/bin/regripper
sudo chmod +x ~/regripper/rip.pl

# Step 5: Windows Event Log Tools & Bulk Extractor
sudo apt-get install -y libevtx-utils bulk-extractor

# Step 6: Plaso (log2timeline)
sudo add-apt-repository -y ppa:gift/stable
sudo apt-get update
sudo apt-get install -y plaso-tools
```

---

## 📦 Installation

### 1. Clone & Build the Python Environment
The MCP Server relies on modern Python packaging. Install the dependencies using `uv`:
```bash
git clone https://github.com/YOUR_USERNAME/Automated-Digital-Forensics.git
cd Automated-Digital-Forensics/sift-breach-autopsy/mcp_server
uv sync
```
*(This creates an isolated `.venv` with the required packages without polluting your system).*

---

## ⚡ Cache Warming (Highly Recommended)

Forensic tools like memory parsing and deep recursive file searches take a long time to run. To make your AI sessions instant, run the prestage script against your evidence directory *before* starting your investigation. The results will be saved to a persistent cache.

```bash
# Return to the root of the repository
cd ../..
chmod +x sift-breach-autopsy/prestage_all/prestage_all.sh

# Run against an evidence folder (containing .E01, .mem, .evtx, hives)
./sift-breach-autopsy/prestage_all/prestage_all.sh /path/to/your/evidence/
```

---

## 🤖 Using with AI Agents

> **⚠️ IMPORTANT:** Always launch your AI agent (Antigravity CLI, Claude Code, Cursor) from the **root directory** of this repository (`Automated-Digital-Forensics/`) so that the local orchestrator paths resolve correctly.

### For Antigravity Users
Because the `.agent/` folder is included in this repository, Antigravity will automatically detect the `forensics-breach-autopsy` skill. Simply open Antigravity at the repo root and tell it:
> *"Start the triage phase on the evidence directory /path/to/evidence"*

### For Claude Code / Cursor Users
To use this with other CLI agents and avoid hitting RPM limits, provide your agent with the following system prompt:

> **System Prompt:**
> *"You are a forensic investigator. Use your forensics skill to analyze /path/to/your/evidence"*

### Manual Execution
You can also run the orchestrator manually from the terminal to instantly pull pre-filtered high-confidence IOCs:
```bash
python3 ./.agent/skills/forensics-breach-autopsy/scripts/investigate.py \
  --phase lateral \
  --evtx-path /path/to/Security.evtx \
  --memory-path /path/to/mem.dmp
```