#!/usr/bin/env python3
"""
PathFinder CLI — AI-Powered Attack Path Simulator
Supports Anthropic, OpenAI, and OpenRouter as AI providers.

Usage:
    python pathfinder.py --demo                                         # Run on built-in demo network
    python pathfinder.py --file network.json                            # Analyze a graph JSON file
    python pathfinder.py --interactive                                  # Build a graph interactively
    python pathfinder.py --demo --provider openai                       # Use OpenAI instead
    python pathfinder.py --demo --provider openrouter --model mistralai/mistral-large
    python pathfinder.py --help                                         # Show help
"""

import json
import sys
import os
import argparse
import urllib.request
import urllib.error
from pathlib import Path
from collections import defaultdict, deque
from datetime import datetime
from typing import Optional

# ── ANSI COLORS ──────────────────────────────────────────────────
class C:
    RED    = '\033[91m'
    AMBER  = '\033[93m'
    GREEN  = '\033[92m'
    CYAN   = '\033[96m'
    BLUE   = '\033[94m'
    PURPLE = '\033[95m'
    WHITE  = '\033[97m'
    DIM    = '\033[2m'
    BOLD   = '\033[1m'
    RESET  = '\033[0m'
    LINE   = '─' * 64

def col(text, color): return f"{color}{text}{C.RESET}"
def bold(text): return f"{C.BOLD}{text}{C.RESET}"

# ── NODE + EDGE TYPES ────────────────────────────────────────────
NODE_RISK = {
    'internet': 3, 'workstation': 1, 'server': 2,
    'dc': 3, 'user': 1, 'admin': 3, 'db': 2, 'firewall': 0
}

HIGH_VALUE_TYPES = {'dc', 'admin', 'db'}

DANGEROUS_EDGES = {
    'AdminTo', 'GenericAll', 'WriteDACL', 'Kerberoastable',
    'ExecuteDCOM', 'AllowedToDelegate', 'DCSync', 'ForceChangePassword'
}

# ── GRAPH ENGINE ─────────────────────────────────────────────────
class AttackGraph:
    def __init__(self):
        self.nodes = {}     # id -> {id, type, name, compromised}
        self.edges = []     # [{from, to, type}]
        self.adj = defaultdict(list)  # adjacency list

    def add_node(self, node_id: int, node_type: str, name: str, compromised: bool = False):
        self.nodes[node_id] = {
            'id': node_id, 'type': node_type,
            'name': name, 'compromised': compromised
        }

    def add_edge(self, from_id: int, to_id: int, edge_type: str):
        self.edges.append({'from': from_id, 'to': to_id, 'type': edge_type})
        self.adj[from_id].append((to_id, edge_type))

    def from_json(self, data: dict):
        for n in data.get('nodes', []):
            self.add_node(n['id'], n['type'], n['name'], n.get('isCompromised', False))
        for e in data.get('edges', []):
            self.add_edge(e['from'], e['to'], e['type'])

    def to_context_string(self) -> str:
        lines = ["NETWORK GRAPH", "=" * 40]
        lines.append("Nodes:")
        for n in self.nodes.values():
            risk = NODE_RISK.get(n['type'], 1)
            compromised = " [COMPROMISED]" if n['compromised'] else ""
            lines.append(f"  • {n['name']} [{n['type'].upper()}, Risk:{risk}]{compromised}")
        lines.append("\nEdges:")
        for e in self.edges:
            a = self.nodes.get(e['from'], {}).get('name', str(e['from']))
            b = self.nodes.get(e['to'], {}).get('name', str(e['to']))
            lines.append(f"  {a} --[{e['type']}]--> {b}")
        compromised = [n['name'] for n in self.nodes.values() if n['compromised']]
        lines.append(f"\nCompromised: {', '.join(compromised) if compromised else 'none'}")
        return '\n'.join(lines)

    def find_paths(self, start_id: int, targets: list) -> list:
        """BFS to find all paths from start to any target."""
        paths = []
        queue = deque([(start_id, [start_id], [])])
        visited_states = set()

        while queue:
            node_id, path, edge_types = queue.popleft()
            state = (node_id, tuple(path))
            if state in visited_states:
                continue
            visited_states.add(state)

            if node_id in targets and len(path) > 1:
                paths.append({'nodes': path[:], 'edges': edge_types[:]})

            if len(path) > 8:  # max depth
                continue

            for (next_id, edge_type) in self.adj.get(node_id, []):
                if next_id not in path:
                    queue.append((next_id, path + [next_id], edge_types + [edge_type]))

        return paths

    def compute_attack_paths(self) -> dict:
        """Find all attack paths from compromised/internet nodes to high-value targets."""
        start_ids = [
            n['id'] for n in self.nodes.values()
            if n['compromised'] or n['type'] in {'internet'}
        ]
        target_ids = [
            n['id'] for n in self.nodes.values()
            if n['type'] in HIGH_VALUE_TYPES
        ]

        all_paths = []
        for s in start_ids:
            paths = self.find_paths(s, target_ids)
            all_paths.extend(paths)

        # Score paths by danger
        scored = []
        for p in all_paths:
            danger_score = sum(1 for e in p['edges'] if e in DANGEROUS_EDGES)
            path_len = len(p['nodes'])
            # shorter paths with dangerous edges = higher priority
            score = danger_score * 3 + (10 - min(path_len, 10))
            scored.append({**p, 'score': score})

        scored.sort(key=lambda x: x['score'], reverse=True)
        return {
            'paths': scored,
            'total': len(scored),
            'entry_points': len(start_ids),
            'targets': len(target_ids),
        }

    def stats(self) -> dict:
        return {
            'nodes': len(self.nodes),
            'edges': len(self.edges),
            'compromised': sum(1 for n in self.nodes.values() if n['compromised']),
            'high_value': sum(1 for n in self.nodes.values() if n['type'] in HIGH_VALUE_TYPES),
        }


# ── AI ENGINE ────────────────────────────────────────────────────
SYSTEM_PROMPT = """You are an elite red team operator and Active Directory security researcher. 
You analyze network graphs to identify realistic attack paths using BloodHound-style reasoning 
and MITRE ATT&CK framework knowledge.

Structure your response with these exact headers:

## CRITICAL ATTACK PATHS
List the top 2-3 most dangerous complete paths. Format:
PATH N: NodeA —[EdgeType]→ NodeB —[EdgeType]→ ... → TARGET (Risk: CRITICAL/HIGH/MEDIUM)

## PRIVILEGE ESCALATION TECHNIQUES  
Specific TTPs applicable to this network (cite MITRE IDs like T1558.003).

## HIGH-VALUE TARGETS
Ranked list of targets with what an attacker gains from each.

## RISK ASSESSMENT
One-paragraph overall assessment with rating: CRITICAL / HIGH / MEDIUM / LOW

## DEFENSIVE RECOMMENDATIONS
5 specific actionable controls referencing real security solutions (LAPS, PAM, Tiered Admin, etc.)

Be technically precise. Max 450 words."""


PROVIDER_DEFAULTS = {
    'anthropic':  { 'model': 'claude-sonnet-4-20250514', 'env': 'ANTHROPIC_API_KEY',  'base': 'https://api.anthropic.com' },
    'openai':     { 'model': 'gpt-4o',                   'env': 'OPENAI_API_KEY',      'base': 'https://api.openai.com' },
    'openrouter': { 'model': 'anthropic/claude-sonnet-4', 'env': 'OPENROUTER_API_KEY', 'base': 'https://openrouter.ai/api' },
}

def run_ai_analysis(graph: AttackGraph, question: Optional[str] = None,
                    api_key: Optional[str] = None, provider: str = 'anthropic',
                    model: Optional[str] = None) -> str:
    """Call AI provider API for attack path analysis. Supports Anthropic, OpenAI, OpenRouter."""

    cfg = PROVIDER_DEFAULTS.get(provider)
    if not cfg:
        return f"[!] Unknown provider '{provider}'. Choose: anthropic, openai, openrouter"

    key = api_key or os.environ.get(cfg['env'])
    if not key:
        return (f"[!] No API key found for provider '{provider}'.\n"
                f"    Set the {cfg['env']} environment variable, or use --api-key.")

    chosen_model = model or cfg['model']
    context = graph.to_context_string()

    if question:
        system = ("You are an expert red team analyst. Answer concisely and technically. "
                  "Reference specific nodes and MITRE ATT&CK IDs. Max 200 words.")
        user_msg = f"{context}\n\nQuestion: {question}"
    else:
        system = SYSTEM_PROMPT
        user_msg = context

    try:
        if provider == 'anthropic':
            return _call_anthropic(key, chosen_model, system, user_msg)
        else:
            base = cfg['base']
            return _call_openai_compat(key, chosen_model, system, user_msg, base, provider)
    except Exception as e:
        return f"[!] API error: {e}"


def _call_anthropic(key: str, model: str, system: str, user_msg: str) -> str:
    """Call Anthropic Messages API using urllib (no SDK required)."""
    payload = json.dumps({
        "model": model,
        "max_tokens": 1000,
        "system": system,
        "messages": [{"role": "user", "content": user_msg}]
    }).encode()
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
        },
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            d = json.loads(resp.read())
            return d["content"][0]["text"]
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            msg = json.loads(body).get("error", {}).get("message", body)
        except Exception:
            msg = body
        if e.code == 401:
            return "[!] Invalid Anthropic API key."
        return f"[!] Anthropic API error {e.code}: {msg}"


def _call_openai_compat(key: str, model: str, system: str, user_msg: str,
                         base_url: str, provider: str) -> str:
    """Call OpenAI-compatible API (OpenAI or OpenRouter) using urllib."""
    payload = json.dumps({
        "model": model,
        "max_tokens": 1000,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user",   "content": user_msg}
        ]
    }).encode()
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {key}",
    }
    if provider == 'openrouter':
        headers["HTTP-Referer"] = "https://github.com/pathfinder-aps"
        headers["X-Title"] = "PathFinder Attack Path Simulator"

    req = urllib.request.Request(
        f"{base_url}/v1/chat/completions",
        data=payload,
        headers=headers,
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            d = json.loads(resp.read())
            return d["choices"][0]["message"]["content"]
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            msg = json.loads(body).get("error", {}).get("message", body)
        except Exception:
            msg = body
        if e.code == 401:
            return f"[!] Invalid {provider} API key."
        return f"[!] {provider} API error {e.code}: {msg}"


# ── DISPLAY ──────────────────────────────────────────────────────
def print_banner():
    print(col("""
╔═══════════════════════════════════════════════════════════════╗
║   ██████╗  █████╗ ████████╗██╗  ██╗███████╗██╗███╗   ██╗   ║
║   ██╔══██╗██╔══██╗╚══██╔══╝██║  ██║██╔════╝██║████╗  ██║   ║
║   ██████╔╝███████║   ██║   ███████║█████╗  ██║██╔██╗ ██║   ║
║   ██╔═══╝ ██╔══██║   ██║   ██╔══██║██╔══╝  ██║██║╚██╗██║   ║
║   ██║     ██║  ██║   ██║   ██║  ██║██║     ██║██║ ╚████║   ║
║   ╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═══╝   ║
║          F I N D E R  —  Attack Path Simulator               ║
║          Powered by Graph Theory + Claude AI                 ║
╚═══════════════════════════════════════════════════════════════╝
""", C.CYAN))

def print_graph_summary(graph: AttackGraph):
    st = graph.stats()
    print(col(C.LINE, C.DIM))
    print(bold("GRAPH SUMMARY"))
    print(f"  Nodes:       {col(st['nodes'], C.CYAN)}")
    print(f"  Edges:       {col(st['edges'], C.PURPLE)}")
    print(f"  Compromised: {col(st['compromised'], C.RED)}")
    print(f"  High-Value:  {col(st['high_value'], C.AMBER)}")

def print_nodes(graph: AttackGraph):
    print(col(C.LINE, C.DIM))
    print(bold("NODES"))
    for n in graph.nodes.values():
        risk = NODE_RISK.get(n['type'], 1)
        risk_col = C.RED if risk == 3 else C.AMBER if risk == 2 else C.GREEN
        comp = col(" [COMPROMISED]", C.RED) if n['compromised'] else ""
        print(f"  [{col(risk, risk_col)}] {col(n['name'], C.WHITE)} ({n['type'].upper()}){comp}")

def print_paths(paths_result: dict, graph: AttackGraph):
    print(col(C.LINE, C.DIM))
    print(bold(f"COMPUTED ATTACK PATHS ({paths_result['total']} found)"))
    if not paths_result['paths']:
        print(col("  No attack paths found between entry points and high-value targets.", C.GREEN))
        return
    for i, p in enumerate(paths_result['paths'][:5], 1):
        node_names = [graph.nodes.get(nid, {}).get('name', str(nid)) for nid in p['nodes']]
        chain = []
        for j, name in enumerate(node_names):
            chain.append(col(name, C.RED if j == len(node_names)-1 else C.CYAN))
            if j < len(p['edges']):
                chain.append(col(f" —[{p['edges'][j]}]→ ", C.DIM))
        score_col = C.RED if p['score'] > 10 else C.AMBER if p['score'] > 5 else C.GREEN
        print(f"\n  PATH {i} (Score: {col(p['score'], score_col)})")
        print(f"  {''.join(chain)}")

def print_ai_report(report: str):
    print(col(C.LINE, C.DIM))
    print(bold("AI THREAT INTELLIGENCE REPORT"))
    print(col(C.LINE, C.DIM))
    # Color MITRE IDs
    lines = report.split('\n')
    for line in lines:
        if line.startswith('## '):
            print(col(f"\n{line[3:]}", C.AMBER) + col(' ▼', C.DIM))
        elif 'CRITICAL' in line:
            print(col(line, C.RED))
        elif 'PATH' in line and '→' in line:
            print(col(line, C.CYAN))
        else:
            # highlight MITRE IDs
            import re
            highlighted = re.sub(r'T\d{4}(\.\d+)?', lambda m: col(m.group(), C.AMBER), line)
            print(highlighted)

def save_report(graph: AttackGraph, paths_result: dict, ai_report: str, output_path: str):
    report = {
        "generated": datetime.now().isoformat(),
        "tool": "PathFinder v1.0",
        "graph": {
            "nodes": list(graph.nodes.values()),
            "edges": graph.edges,
        },
        "analysis": {
            "stats": graph.stats(),
            "attack_paths": paths_result['paths'][:10],
            "ai_report": ai_report,
        }
    }
    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)
    print(col(f"\n[✓] Report saved to: {output_path}", C.GREEN))


# ── DEMO NETWORK ─────────────────────────────────────────────────
def build_demo_network() -> AttackGraph:
    g = AttackGraph()
    g.add_node(1,  'internet',    'Attacker C2',    compromised=True)
    g.add_node(2,  'firewall',    'Edge-FW',        compromised=False)
    g.add_node(3,  'workstation', 'Sam-PC',         compromised=False)
    g.add_node(4,  'workstation', 'Pal-PC',         compromised=False)
    g.add_node(5,  'user',        'sam@corp.local', compromised=False)
    g.add_node(6,  'user',        'pal@corp.local', compromised=False)
    g.add_node(7,  'server',      'FileServer-01',  compromised=False)
    g.add_node(8,  'server',      'WebApp-01',      compromised=False)
    g.add_node(9,  'admin',       'svc_admin',      compromised=False)
    g.add_node(10, 'dc',          'CORP-DC01',      compromised=False)
    g.add_node(11, 'db',          'SQLDB-Prod',     compromised=False)

    g.add_edge(1,  2,  'HasSession')
    g.add_edge(2,  3,  'CanRDP')
    g.add_edge(2,  4,  'CanRDP')
    g.add_edge(3,  5,  'HasSession')
    g.add_edge(4,  6,  'HasSession')
    g.add_edge(5,  7,  'CanRDP')
    g.add_edge(5,  9,  'MemberOf')
    g.add_edge(5,  9,  'Kerberoastable')
    g.add_edge(6,  8,  'CanRDP')
    g.add_edge(9,  10, 'AdminTo')
    g.add_edge(9,  11, 'ExecuteDCOM')
    g.add_edge(7,  10, 'GenericAll')
    g.add_edge(8,  11, 'Contains')
    return g


# ── INTERACTIVE MODE ─────────────────────────────────────────────
def interactive_mode() -> AttackGraph:
    g = AttackGraph()
    node_types = ['internet', 'workstation', 'server', 'dc', 'user', 'admin', 'db', 'firewall']
    edge_types = ['HasSession', 'AdminTo', 'CanRDP', 'MemberOf', 'ExecuteDCOM',
                  'GenericAll', 'AllowedToDelegate', 'Kerberoastable', 'WriteDACL', 'Contains']

    print(col("\n[i] INTERACTIVE GRAPH BUILDER", C.CYAN))
    print("Add nodes, then edges. Empty input to finish each section.\n")

    # Add nodes
    print(col("NODE TYPES:", C.AMBER), ', '.join(node_types))
    while True:
        name = input(col("  Node name (empty to stop): ", C.DIM)).strip()
        if not name:
            break
        ntype = input(col("  Node type: ", C.DIM)).strip().lower()
        if ntype not in node_types:
            ntype = 'workstation'
        comp = input(col("  Compromised? (y/N): ", C.DIM)).strip().lower() == 'y'
        nid = len(g.nodes) + 1
        g.add_node(nid, ntype, name, comp)
        print(col(f"  [+] Added: {name} [{ntype}] id={nid}", C.GREEN))

    if len(g.nodes) < 2:
        print(col("[!] Need at least 2 nodes. Loading demo instead.", C.RED))
        return build_demo_network()

    # Show node list for edge creation
    print(col("\nEDGE TYPES:", C.AMBER), ', '.join(edge_types))
    print("Nodes:")
    for n in g.nodes.values():
        print(f"  {n['id']}: {n['name']}")

    while True:
        edge_in = input(col("\n  Edge (from_id to_id type, empty to stop): ", C.DIM)).strip()
        if not edge_in:
            break
        parts = edge_in.split()
        if len(parts) < 3:
            print("  Format: from_id to_id EdgeType")
            continue
        try:
            f, t = int(parts[0]), int(parts[1])
            etype = parts[2] if parts[2] in edge_types else 'HasSession'
            g.add_edge(f, t, etype)
            fn = g.nodes.get(f, {}).get('name', str(f))
            tn = g.nodes.get(t, {}).get('name', str(t))
            print(col(f"  [+] {fn} --[{etype}]--> {tn}", C.GREEN))
        except (ValueError, IndexError):
            print("  Invalid input.")

    return g


# ── MAIN ─────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description='PathFinder — AI-Powered Attack Path Simulator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python pathfinder.py --demo
  python pathfinder.py --file my_network.json
  python pathfinder.py --demo --query "What Kerberoasting opportunities exist?"
  python pathfinder.py --interactive --output report.json

  # Different providers:
  ANTHROPIC_API_KEY=sk-ant-... python pathfinder.py --demo
  OPENAI_API_KEY=sk-...       python pathfinder.py --demo --provider openai
  OPENROUTER_API_KEY=sk-or-... python pathfinder.py --demo --provider openrouter
  python pathfinder.py --demo --provider openrouter --model google/gemini-2.5-pro
        """
    )
    parser.add_argument('--demo',        action='store_true', help='Run on built-in demo network')
    parser.add_argument('--file',        type=str,           help='Path to network JSON file')
    parser.add_argument('--interactive', action='store_true', help='Build graph interactively')
    parser.add_argument('--query',       type=str,           help='Ask a specific question instead of full analysis')
    parser.add_argument('--output',      type=str,           help='Save report to JSON file')
    parser.add_argument('--no-ai',       action='store_true', help='Skip AI analysis (graph only)')
    parser.add_argument('--api-key',     type=str,           help='API key for the chosen provider')
    parser.add_argument('--provider',    type=str,           default='anthropic',
                        choices=['anthropic', 'openai', 'openrouter'],
                        help='AI provider: anthropic (default), openai, or openrouter')
    parser.add_argument('--model',       type=str,           help='Model override (e.g. gpt-4o, mistralai/mistral-large)')

    args = parser.parse_args()

    if not any([args.demo, args.file, args.interactive]):
        parser.print_help()
        sys.exit(0)

    print_banner()

    # Build graph
    graph = AttackGraph()
    if args.demo:
        print(col("[*] Loading demo network (corporate AD environment)...", C.CYAN))
        graph = build_demo_network()
    elif args.file:
        path = Path(args.file)
        if not path.exists():
            print(col(f"[!] File not found: {args.file}", C.RED)); sys.exit(1)
        with open(path) as f:
            data = json.load(f)
        if 'nodes' in data and 'edges' in data:
            graph.from_json(data)
        elif 'graph' in data:
            graph.from_json(data['graph'])
        else:
            print(col("[!] Invalid JSON format. Expected {nodes: [], edges: []}", C.RED)); sys.exit(1)
        print(col(f"[*] Loaded: {args.file}", C.CYAN))
    elif args.interactive:
        graph = interactive_mode()

    print_graph_summary(graph)
    print_nodes(graph)

    # Compute paths locally
    paths_result = graph.compute_attack_paths()
    print_paths(paths_result, graph)

    # AI analysis
    ai_report = ''
    if not args.no_ai:
        print(col(C.LINE, C.DIM))
        provider_label = args.provider.upper()
        model_label    = args.model or PROVIDER_DEFAULTS[args.provider]['model']
        print(col(f"[*] Running AI analysis via {provider_label} / {model_label}...", C.CYAN))
        ai_report = run_ai_analysis(
            graph,
            question=args.query,
            api_key=args.api_key,
            provider=args.provider,
            model=args.model
        )
        print_ai_report(ai_report)
    else:
        print(col("\n[i] AI analysis skipped (--no-ai)", C.DIM))

    # Save report
    if args.output:
        save_report(graph, paths_result, ai_report, args.output)

    print(col(f"\n{C.LINE}", C.DIM))
    print(col("[✓] PathFinder analysis complete.", C.GREEN))
    print(col(f"    {paths_result['total']} attack paths found across {len(graph.nodes)} nodes", C.DIM))
    print()


if __name__ == '__main__':
    main()
