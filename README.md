# PathFinder - AI-Powered Attack Path Simulator

A BloodHound-inspired attack path simulator powered by graph theory and AI.
Map privilege escalation chains, lateral movement routes, and critical security gaps in Active Directory environments using Claude, GPT-4o, Gemini, Mistral, and more.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-green.svg)](https://python.org)
[![No Dependencies](https://img.shields.io/badge/Dependencies-None-brightgreen.svg)]()
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red.svg)](https://attack.mitre.org)

> **Legal notice:** Read the [disclaimer](#legal-disclaimer--responsible-use) at the bottom before use.

---

## Table of Contents

- [What Is PathFinder?](#what-is-pathfinder)
- [Features](#features)
- [How It Works](#how-it-works)
- [Quick Start](#quick-start)
- [Web UI Guide](#web-ui-guide)
- [CLI Guide](#cli-guide)
- [AI Providers](#ai-providers)
- [Network JSON Format](#network-json-format)
- [Node & Edge Reference](#node--edge-reference)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Architecture](#architecture)
- [Roadmap](#roadmap)
- [Inspiration & Prior Art](#inspiration--prior-art)
- [Contributing](#contributing)
- [Legal Disclaimer & Responsible Use](#legal-disclaimer--responsible-use)
- [License](#license)

---

## What Is PathFinder?

PathFinder is an educational security research tool that models Active Directory networks as graphs and uses AI to reason over them the way a red team operator would.

You build or import a network graph where nodes represent hosts, accounts, and services, and edges represent relationships like `AdminTo`, `HasSession`, `CanRDP`, and `Kerberoastable`. From there, PathFinder:

1. Runs a local BFS graph traversal to find all attack paths from entry points to high-value targets
2. Sends the graph topology to your chosen AI model with a red-team-operator system prompt
3. Returns structured threat intelligence: attack path chains with hop-by-hop breakdowns, MITRE ATT&CK technique IDs, privilege escalation opportunities, high-value target rankings, risk ratings, and defensive recommendations

This is the kind of analysis a skilled pentester does manually when reviewing BloodHound output. PathFinder automates and augments that process.

**Who is this for?**

- Red teamers who want to quickly reason over AD graphs and find the fastest paths to DA
- Blue teamers trying to understand what attackers see and where controls should go
- Security students learning AD attack paths in an interactive, visual environment
- Pentesters who want to prototype and document attack narratives for reports
- Researchers experimenting with AI-assisted threat modeling

---

## Features

### Web UI

- Visual graph builder with drag-and-drop node types on an interactive canvas
- Right-click context menus to connect nodes, mark hosts as compromised, or trigger node-level AI analysis
- AI Threat Intelligence panel with a full structured red team report in color-coded sections
- Attack path highlighting where dangerous edges glow red after analysis
- Quick Queries with one-click questions like "Full kill chain", "Pivot points", and "Blast radius"
- Freeform chat so you can ask anything about the loaded graph in plain language
- Multi-provider support to switch between Anthropic, OpenAI, and OpenRouter in Settings
- Per-provider API key storage saved in localStorage, separate per provider
- Import and export for loading and saving network graphs as JSON
- A demo network that loads a realistic 11-node corporate AD environment in one click
- Zero dependencies, it's a single `index.html` file that opens in any modern browser

### CLI

- BFS path engine for local graph traversal with no AI required
- AI analysis for deep threat intel via any supported provider
- Multi-provider support via the `--provider anthropic|openai|openrouter` flag
- Model override with `--model` for any model on any provider
- Interactive mode to build a graph step-by-step in the terminal
- Freeform queries via `--query` to ask specific questions
- JSON output with `--output` to save the full report
- No pip installs needed, uses Python stdlib `urllib` only

### Feature Matrix

| Feature | Web UI | CLI |
|---|---|---|
| AI threat analysis | Yes | Yes |
| Local BFS path finding | Yes | Yes |
| MITRE ATT&CK annotations | Yes | Yes |
| Anthropic / OpenAI / OpenRouter | Yes | Yes |
| Import/export JSON | Yes | Yes |
| Custom freeform queries | Yes | Yes |
| Demo corporate AD network | Yes | Yes |
| Save reports | Yes | Yes |
| Visual graph canvas | Yes | No |
| Attack path edge highlighting | Yes | No |
| Interactive terminal builder | No | Yes |

---

## How It Works

### Graph Model

PathFinder represents networks as directed graphs:

```
Nodes  =  hosts, accounts, services (Workstations, DCs, Users, Admins, Databases...)
Edges  =  AD relationships (AdminTo, HasSession, CanRDP, Kerberoastable, GenericAll...)
```

This is the same underlying model used by BloodHound/SharpHound. Relationships between objects in Active Directory translate directly to edges an attacker can traverse.

### Path Finding

The CLI engine runs Breadth-First Search from every compromised or entry-point node, finding all reachable paths to high-value targets like Domain Controllers, Admin accounts, and Databases. Each path is scored by the risk level of nodes and the danger of edge types along it.

### AI Reasoning

The graph is serialized to a structured text format and sent to the AI model with an engineered system prompt:

```
You are an elite red team operator and Active Directory security researcher
with deep expertise in BloodHound attack paths, MITRE ATT&CK, and Windows
privilege escalation. Analyze the following network graph...
```

The serialized graph looks like this:

```
NETWORK GRAPH
=============
Nodes:
  - Attacker C2 [INTERNET, Risk:3] [ALREADY COMPROMISED]
  - Sam-PC [WORKSTATION, Risk:1]
  - svc_admin [ADMIN, Risk:3]
  - CORP-DC01 [DC, Risk:3]

Edges (relationships):
  Attacker C2 --[HasSession]--> Sam-PC
  Sam-PC --[CanRDP]--> svc_admin
  svc_admin --[AdminTo]--> CORP-DC01
```

The AI reasons over this topology and returns a structured report split into five sections: Critical Attack Paths, Privilege Escalation Chains, High-Value Targets, Risk Assessment, and Defensive Recommendations, each referencing specific nodes, edge types, and MITRE technique IDs.

---

## Quick Start

### Web UI

**Option A - Serve locally (recommended, required for OpenAI/OpenRouter):**

```bash
# Clone or unzip the repo, then:
python serve.py
# Opens http://localhost:8080 automatically
```

**Option B - Open directly (Anthropic only):**
```bash
# Double-click web/index.html
# Note: OpenAI and OpenRouter will fail from file:// -- use serve.py instead
```

Then:
1. Click Settings, select your AI provider, paste your API key, and save
2. Click Demo Network to load a pre-built corporate AD environment
3. Click Analyze Paths and watch the AI reason over the graph

### CLI

```bash
# No pip install required -- uses Python stdlib only

# Quick demo with Anthropic (default)
export ANTHROPIC_API_KEY=sk-ant-...
python cli/pathfinder.py --demo

# Graph analysis only -- no API key needed
python cli/pathfinder.py --demo --no-ai
```

---

## Web UI Guide

### Building a Graph

1. Add nodes by dragging any node type from the left panel onto the canvas
2. Connect nodes by right-clicking a node, selecting "Connect to...", clicking the target node, then choosing an edge type
3. Mark compromised nodes by right-clicking and selecting "Mark Compromised" to simulate a breached host
4. Move nodes by clicking and dragging

### Running Analysis

- **Full analysis:** Click Analyze Paths. The AI analyzes the entire graph and returns a structured red team report. Attack-path edges are highlighted in red.
- **Node analysis:** Right-click any node and select "AI: Analyze this node" for focused threat intel on that specific host
- **Quick Queries:** Predefined questions in the right panel for common scenarios
- **Freeform chat:** Type any question, for example "How would an attacker pivot from Sam-PC to the database?"

### Settings

Click the provider name in the top bar to:
- Choose your AI provider (Anthropic, OpenAI, or OpenRouter)
- Select a model from the dropdown
- Paste your API key, which is stored in browser localStorage and sent only to the provider directly
- Keys are stored separately per provider

### Import / Export

- **Import:** Load any PathFinder-format JSON file
- **Export:** Save the current graph and AI report

---

## CLI Guide

### Basic Usage

```bash
python cli/pathfinder.py [OPTIONS]
```

### Options

| Flag | Description |
|---|---|
| `--demo` | Run on the built-in 11-node corporate AD demo network |
| `--file PATH` | Load a network from a JSON file |
| `--interactive` | Build a network interactively in the terminal |
| `--query TEXT` | Ask a specific question instead of running full analysis |
| `--output PATH` | Save the full report to a JSON file |
| `--no-ai` | Skip AI analysis and run graph engine only (no API key needed) |
| `--provider NAME` | AI provider: `anthropic` (default), `openai`, `openrouter` |
| `--model NAME` | Override the default model for the chosen provider |
| `--api-key KEY` | Pass API key directly instead of using an environment variable |

### Examples

```bash
# Anthropic Claude (default)
export ANTHROPIC_API_KEY=sk-ant-...
python cli/pathfinder.py --demo

# OpenAI GPT-4o
export OPENAI_API_KEY=sk-...
python cli/pathfinder.py --demo --provider openai

# OpenRouter -- Mistral Large
export OPENROUTER_API_KEY=sk-or-...
python cli/pathfinder.py --demo --provider openrouter --model mistralai/mistral-large

# OpenRouter -- Gemini 2.5 Pro
python cli/pathfinder.py --demo --provider openrouter --model google/gemini-2.5-pro

# Analyze a custom network file
python cli/pathfinder.py --file my_network.json

# Ask a targeted question
python cli/pathfinder.py --demo --query "What Kerberoasting opportunities exist?"

# Graph analysis only -- no API key needed
python cli/pathfinder.py --demo --no-ai

# Full pipeline -- load, analyze, save report
python cli/pathfinder.py --file corp_network.json --output report.json

# Interactive terminal builder
python cli/pathfinder.py --interactive --output my_analysis.json
```

### Environment Variables

| Variable | Provider |
|---|---|
| `ANTHROPIC_API_KEY` | Anthropic |
| `OPENAI_API_KEY` | OpenAI |
| `OPENROUTER_API_KEY` | OpenRouter |

---

## AI Providers

### Anthropic

| Model | Notes |
|---|---|
| `claude-sonnet-4-20250514` | Recommended, fast and highly capable |
| `claude-opus-4-20250514` | Most capable, best for complex chains |
| `claude-haiku-4-5-20251001` | Fastest and cheapest |

Get a key: [console.anthropic.com](https://console.anthropic.com)

> Anthropic is the only provider that works when opening `index.html` directly as `file://`. Use `python serve.py` for OpenAI and OpenRouter.

### OpenAI

| Model | Notes |
|---|---|
| `gpt-4o` | Recommended |
| `gpt-4o-mini` | Cheaper, fast |
| `gpt-4-turbo` | Larger context |
| `o3-mini` | Reasoning model |

Get a key: [platform.openai.com/api-keys](https://platform.openai.com/api-keys)

### OpenRouter

One API key, 100+ models. Useful for comparing outputs across providers.

| Model ID | Description |
|---|---|
| `anthropic/claude-sonnet-4` | Claude Sonnet 4 |
| `openai/gpt-4o` | GPT-4o |
| `google/gemini-2.5-pro` | Gemini 2.5 Pro |
| `meta-llama/llama-3.3-70b-instruct` | Llama 3.3 70B |
| `mistralai/mistral-large` | Mistral Large |
| `deepseek/deepseek-r1` | DeepSeek R1 |

Get a key: [openrouter.ai/keys](https://openrouter.ai/keys)

---

## Network JSON Format

```json
{
  "nodes": [
    { "id": 1, "type": "internet",    "name": "Attacker C2",   "isCompromised": true  },
    { "id": 2, "type": "workstation", "name": "Sam-PC",         "isCompromised": false },
    { "id": 3, "type": "user",        "name": "sam@corp.local", "isCompromised": false },
    { "id": 4, "type": "admin",       "name": "svc_admin",      "isCompromised": false },
    { "id": 5, "type": "dc",          "name": "CORP-DC01",      "isCompromised": false }
  ],
  "edges": [
    { "from": 1, "to": 2, "type": "HasSession"     },
    { "from": 2, "to": 3, "type": "HasSession"     },
    { "from": 3, "to": 4, "type": "Kerberoastable" },
    { "from": 4, "to": 5, "type": "AdminTo"        }
  ]
}
```

---

## Node & Edge Reference

### Node Types

| Type | Label | Risk | Description |
|---|---|---|---|
| `internet` | Internet / C2 | High | External attacker entry point or C2 server |
| `workstation` | Workstation | Low | Standard user endpoint, common initial foothold |
| `server` | Server | Medium | Internal application or file server |
| `dc` | Domain Controller | High | Highest-value target, controls the entire domain |
| `user` | User Account | Low | Standard domain user account |
| `admin` | Admin Account | High | Privileged account, local or domain admin |
| `db` | Database | Medium | SQL/NoSQL server with high data exfiltration value |
| `firewall` | Firewall / DMZ | None | Network boundary device |

### Edge (Relationship) Types

| Relationship | MITRE ID | Description |
|---|---|---|
| `HasSession` | T1550 | Active user session on host, credentials may be in memory |
| `AdminTo` | T1078 | Account has local or domain admin rights on the target |
| `CanRDP` | T1021.001 | Remote Desktop Protocol access is permitted |
| `MemberOf` | | Group membership, inherits group permissions |
| `ExecuteDCOM` | T1021.003 | DCOM lateral movement is possible |
| `GenericAll` | T1222 | Full control over the target AD object |
| `AllowedToDelegate` | T1134.001 | Kerberos delegation configured |
| `Kerberoastable` | T1558.003 | SPN set, hash can be requested and cracked offline |
| `WriteDACL` | T1222 | Permission to modify the target's Access Control List |
| `Contains` | | OU or group containment relationship |

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Triggered By |
|---|---|---|---|
| T1558.003 | Kerberoasting | Credential Access | `Kerberoastable` edges |
| T1550.002 | Pass-the-Hash | Lateral Movement | `HasSession` + admin rights |
| T1550.003 | Pass-the-Ticket | Lateral Movement | `AllowedToDelegate` edges |
| T1003.006 | DCSync | Credential Access | Paths reaching a Domain Controller |
| T1021.001 | Remote Desktop Protocol | Lateral Movement | `CanRDP` edges |
| T1021.003 | Distributed Component Object Model | Lateral Movement | `ExecuteDCOM` edges |
| T1134 | Access Token Manipulation | Privilege Escalation | `HasSession` on admin hosts |
| T1134.001 | Token Impersonation/Theft | Privilege Escalation | `AllowedToDelegate` edges |
| T1078 | Valid Accounts | Initial Access / Persistence | `AdminTo` edges |
| T1222 | File/Directory Permissions Modification | Defense Evasion | `WriteDACL`, `GenericAll` |

---

## Architecture

```
pathfinder/
|-- web/
|   `-- index.html              # Self-contained browser app (vanilla JS, zero deps)
|-- cli/
|   `-- pathfinder.py           # Python CLI -- graph engine + multi-provider AI
|-- examples/
|   `-- demo_corporate_ad.json  # 11-node corporate AD demo network
|-- serve.py                    # Local HTTP server (required for OpenAI/OpenRouter)
|-- requirements.txt            # No mandatory dependencies
|-- .gitignore
|-- LICENSE
`-- README.md
```

### Web Stack

- Vanilla HTML/CSS/JS with no build step, no npm, no frameworks
- Canvas-based graph renderer using the native HTML5 Canvas API
- Direct browser-to-API calls via `fetch()`
- API keys stored in `localStorage` only and never leave your machine except to go to the provider
- Entire app lives in one self-contained `index.html`

### CLI Stack

- Python 3.8+ using standard library only (`json`, `urllib`, `collections`, `pathlib`, `argparse`)
- No `pip install` required
- BFS graph traversal engine written from scratch
- Multi-provider AI routing with per-provider request formatting

### Why No Backend?

PathFinder has no server-side component by design. Your network topology and API keys never pass through any third-party server. All requests go directly from your browser or terminal to the AI provider, which matters when the data you're analyzing could be sensitive.

---

## Roadmap

- BloodHound JSON importer to parse SharpHound `.json` collection output directly
- Neo4j backend to store and query large AD graphs at scale
- CVSS-style path scoring with a numeric risk score per discovered attack path
- MITRE ATT&CK heatmap to visualize technique coverage across the graph
- Defense simulation mode where you add a control and see which paths break
- Multi-hop Kerberos modeling for constrained/unconstrained delegation chains
- PDF report export for formatted penetration testing reports
- REST API mode to expose PathFinder as a backend service
- Custom node/edge types defined by the user
- Graph diff to compare two network snapshots and track remediation

---

## Inspiration & Prior Art

PathFinder is inspired by the following tools. It is not affiliated with or endorsed by any of them.

- **[BloodHound](https://github.com/BloodHoundAD/BloodHound)** by SpecterOps - the foundational AD attack path analysis tool. PathFinder's graph model and relationship types are directly inspired by BloodHound's data model.
- **[SharpHound](https://github.com/BloodHoundAD/SharpHound)** - the AD collection agent that feeds BloodHound.
- **[MITRE ATT&CK](https://attack.mitre.org)** - the adversary tactics and techniques framework referenced throughout PathFinder's AI analysis.
- **[PurpleSharp](https://github.com/mvelazc0/PurpleSharp)** - adversary simulation tooling for Active Directory.
- **[Impacket](https://github.com/fortra/impacket)** - the AD protocol attack library that implements many of the techniques PathFinder models.
- **[PowerView](https://github.com/PowerShellMafia/PowerSploit)** - AD enumeration module whose relationship types influenced PathFinder's edge model.

---

## Contributing

PRs are welcome. To contribute:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/bloodhound-import`)
3. Make your changes
4. Open a pull request with a clear description

Good first contributions include new node or edge types with appropriate risk ratings, additional MITRE ATT&CK technique mappings, improved path scoring heuristics, UI improvements, additional example network JSON files, and documentation fixes.

Please keep the zero-dependency philosophy intact for both the web UI and CLI.

---

## Legal Disclaimer & Responsible Use

**Read this before using PathFinder.**

### Intended Use

PathFinder is designed exclusively for:

- Authorized penetration testing where you have explicit written permission from the system owner
- Security research in controlled, isolated lab environments
- Education and learning about Active Directory attack paths, MITRE ATT&CK techniques, and defensive security
- Threat modeling of systems you own or have been contracted to assess
- CTF competitions and training platforms like HackTheBox, TryHackMe, and similar

### Prohibited Use

PathFinder must not be used to:

- Attack, enumerate, or probe any network, system, or infrastructure you do not own or lack explicit written authorization to test
- Plan, facilitate, or execute unauthorized access to computer systems
- Bypass security controls on systems without permission
- Assist in any illegal activity

### No Warranty

PathFinder is provided as-is with no warranty of any kind. The authors make no representations about the accuracy, completeness, or fitness for purpose of the tool or its AI-generated outputs.

AI-generated threat intelligence is not guaranteed to be accurate. Analysis produced by PathFinder's AI engine is probabilistic reasoning over a simplified graph model. It may miss attack paths, produce false positives, reference incorrect technique IDs, or generate analysis that doesn't apply to your environment. All AI output should be reviewed and validated by a qualified security professional before being acted upon.

### Responsibility

The authors and contributors of PathFinder accept no liability for any damage, loss, legal consequences, or harm resulting from the use or misuse of this tool. By using PathFinder, you agree that you are solely responsible for ensuring your use is lawful in your jurisdiction, that you have obtained all necessary written permissions before analyzing any network, and that you understand unauthorized computer access is a criminal offense in most countries.

### Applicable Law

Unauthorized access to computer systems is a criminal offense under laws including:

- United States - Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030
- United Kingdom - Computer Misuse Act 1990
- European Union - Directive on Attacks Against Information Systems (2013/40/EU)
- Australia - Criminal Code Act 1995, Part 10.7
- Canada - Criminal Code, Section 342.1
- And equivalent legislation in virtually every other jurisdiction

Get written permission before testing any network you don't own. If in doubt, don't.

---

## License

MIT License - see [LICENSE](LICENSE) for full terms.

---

PathFinder - graph theory meets AI-powered red team reasoning.

For education. For authorized testing. For understanding how attackers think.

Supported models: Claude, GPT-4o, Gemini, Llama, Mistral, DeepSeek
