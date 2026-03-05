# artguard

A Claude Code prompt that autonomously scaffolds a full AI artifact scanner CLI.

Paste the prompt into Claude Code and it builds `artguard` — a working Python CLI
that scans agent skills, MCP server configs, and IDE rule files for security threats,
privacy violations, and instruction-level attacks.

## The problem

Enterprises are installing AI agent skills, MCP servers, and IDE rule files
(`.cursorrules`, `.clinerules`, `.windsurfrules`) with zero security review.
No existing scanner covers them.

Traditional scanners are built for code packages. AI artifacts are hybrid —
part code, part natural language instructions — and the attack surface lives
in the instructions themselves.

A YARA rule won't catch a skill that tells your coding agent to approve vulnerable
PRs. Static analysis won't surface an artifact that claims "no data stored" while
writing to disk.

## What artguard scans

| Artifact Type | Examples |
|---|---|
| Agent skill files | `skills.md`, `skill.json`, tool definitions |
| MCP server configs | `mcp.json`, server manifests |
| IDE rule files | `.cursorrules`, `.clinerules`, `.windsurfrules` |
| Plugin manifests | `manifest.json`, API schemas |

## Three detection layers

**Layer 1 — Privacy posture analysis** (differentiator)
Detects the gap between what an artifact claims to do with your data and what it
actually does. Undisclosed storage, covert telemetry, third-party sharing,
retention policy mismatches.

**Layer 2 — Semantic instruction analysis** (differentiator)
LLM-powered detection of behavioral manipulation, prompt injection, context
poisoning, and goal hijacking in the instruction content itself.

**Layer 3 — Static pattern matching** (table stakes)
Traditional malware patterns — credential harvesting, exfiltration endpoints,
obfuscated code — backed by the best free scanners available.

## Output

Every scan produces a **Trust Profile JSON** — a structured AI Bill of Materials
designed to feed policy engines, audit trails, and access controls. Not a
safe/unsafe binary.

```
Composite Trust Score: 14  ██░░░░░░░░░░░░░░░░░░  MALICIOUS 🔴

┌─ PRIVACY POSTURE ─────────────────────────── Score: 32/100 ┐
│  [CRITICAL] PV3 Retention claim mismatch                   │
│             Claims "no data stored" but writes to ~/.cache  │
└─────────────────────────────────────────────────────────────┘

┌─ BEHAVIORAL INTENT ────────────────────────────────────────┐
│  [HIGH]     S4 System prompt override detected              │
│             "Ignore all previous instructions and..."       │
└─────────────────────────────────────────────────────────────┘
```

## Usage

**Requirements:** Claude Code, Python 3.11+, an Anthropic API key (for Layer 2).

```bash
# 1. Create a new directory
mkdir artguard && cd artguard

# 2. Open Claude Code
claude

# 3. Paste the contents of prompt.md
# Claude Code will scaffold the full project autonomously

# 4. Scan an artifact
artguard scan path/to/skill.md
artguard scan path/to/mcp.json --deep     # enables Layer 2 LLM analysis
artguard batch ./skills-directory/
```

## Architecture

The prompt draws from three open source projects:

- [AI-Forensicator](https://github.com/ACandeias/AI-Forensicator) —
  collector/analyzer split, SQLite corpus, Rich TUI pattern
- [ClawShield](https://github.com/SleuthCo/clawshield-public) —
  defense-in-depth layer model, YAML policy engine
- [aflock](https://github.com/aflock-ai/aflock) —
  governance-ready policy schema, standards alignment fields

Layer 3 wraps the best free/open-source scanners:

| Scanner | What it adds |
|---|---|
| [malcontent](https://github.com/chainguard-dev/malcontent) (Chainguard) | 14,500+ YARA rules, capability risk scoring |
| [GuardDog](https://github.com/DataDog/guarddog) (Datadog) | Semgrep heuristics for novel malware |
| [ossf/malicious-packages](https://github.com/ossf/malicious-packages) | Community ground truth in OSV format |
| MalwareBazaar | Hash lookups, no rate limits for researchers |
| AbuseIPDB | IP reputation cross-reference |
| VirusTotal | Hash-only lookup (never uploads — privacy preserved) |

## Project structure (what Claude Code generates)

```
artguard/
├── artguard/
│   ├── cli.py                    # Click CLI entry point
│   ├── schema.py                 # Finding, TrustProfile dataclasses
│   ├── db.py                     # SQLite feedback corpus
│   ├── parsers/                  # One parser per artifact type
│   ├── analyzers/
│   │   ├── layer1_privacy.py     # Privacy posture analysis
│   │   ├── layer2_semantic.py    # LLM semantic instruction analysis
│   │   └── layer3_static.py      # Static pattern matching (extractable)
│   ├── trust_profile/            # Trust Profile builder + scorer
│   └── output/                   # Terminal + export formatting
├── tests/
│   └── fixtures/                 # Benign + malicious sample artifacts
├── scan_profiles/                # YAML policy configs
└── prompt.md                     # ← This file is the source of truth
```

## Contributing

The prompt is the source of truth. Improvements to detection patterns,
new artifact parsers, or better YARA rules are all welcome — either as
prompt edits or as PRs against the generated codebase.

If you stress-test this against real skill registries (ClawHub, skills.sh,
npm MCP packages), findings and false positive rates are especially valuable.

## License

MIT
