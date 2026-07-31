# ReverserX — AI-Enhanced Reverse Engineering Platform

## Overview

ReverserX is a standalone, self-contained AI-orchestrated reverse engineering
platform. It combines multiple AI models (DeepSeek R1, Claude Opus, local LLMs)
with traditional RE tooling (JADX, ADB, Frida, mitmproxy, Ghidra) to enable
autonomous multi-step analysis across Android, web APIs, and native
binaries.

The platform is not MCP glue. It ships with its own planner, executor, reviewer,
and session memory — it works without Claude Code, without Claude Desktop, and
without any external agent framework.

---

## Why This Exists — The Landscape (July 2026)

The AI+RE space has exploded in 2025-2026, but nearly every tool follows the
same pattern: wrap a single RE tool as an MCP server, plug it into Claude Code,
and let Claude's agent loop handle the rest. Here's what the field looks like
and why ReverserX is different.

### The MCP Wrapper Pattern (what everyone else does)

| Project | What it is | Limitation |
|---|---|---|
| **GhidraMCP** (LaurieWired, 9.7k stars) | Java Ghidra plugin + Python MCP bridge | Ghidra-only, needs Claude Desktop |
| **ghidra-headless-mcp** (mrphrazer) | Headless Ghidra via MCP (212 tools) | Binary-only static, needs Claude Code |
| **binary-ninja-headless-mcp** (mrphrazer) | Headless BN via MCP (181 tools) | Paid BN license, needs Claude Code |
| **ghidra-rpc** (Cellebrite) | Ghidra JSON-RPC daemon | Unix-only, no agent loop |
| **jadx-mcp-server** (zinja-coder) | Live JADX GUI via MCP | Needs JADX GUI open, static only |
| **ReVa** (cyberkaida, v7.3) | Production Ghidra HTTP MCP | Ghidra 12+ only, no agent framework |

### The Agentic RE Tools (closer, but narrower)

| Project | What it does | The gap |
|---|---|---|
| **Kong** (amruth-sn) | 5-phase native binary analysis via Ghidra + LLM | Binary-only, static-only, no mobile, no API analysis |
| **agentic-malware-analysis** (mrphrazer) | 8-phase Docker malware triage via skills | Static-only orchestrated, mobile/API absent, context-window ceiling admitted by author |
| **Android-pentest-mcp** (imcfyulong) | 27 MCP tools, 5-phase skill for Android | Tied to Claude Code, static skill doc (no dynamic planning), no native .so analysis, no proxy capture, no unpacking |
| **Exfault** | Autonomous Android pentesting SaaS | Closed source, cloud-only, Android-only, 5 tools |
| **Chimera** (TyrusRC) | 25+ backends, 6 binary formats, MCP server | No built-in agent loop, AI is opt-in single-shot calls |
| **Open-tgtylab** | 150+ MCP tools, 208 KB articles | Directory of tools, no orchestrator, relies on Claude Code |
| **JoySafeter** (JD.com) | Enterprise LangGraph agent platform | Heavy infra, not RE-specialized |

### Six Gaps Nobody Has Filled — ReverserX's Design Bets

**Gap 1: Multi-model task routing.**
Every existing tool sends everything to one model. Kong supports multiple
providers but uses whichever you configured — not "DeepSeek for code pattern
matching, Claude for vulnerability assessment, Haiku for summarization."
ReverserX routes each task to the optimal model. The cost/quality tradeoff
varies dramatically by task type, and no one should burn Opus tokens on a
`grep` result.

**Gap 2: Context-window management for decompiled code.**
This is the single hardest problem in AI-assisted RE. mrphrazer's own blog
admits: "Even with the structured pipeline, the agent produces a good triage
but not a deep analysis." The bottleneck is always context. Yet no tool has
a purpose-built context manager — they dump raw decompiled output and pray.
ReverserX chunks by class/method, ranks by relevance to the analysis goal,
enforces a token budget, and integrates ChromaDB for semantic retrieval
("find where JWT validation happens" without knowing the class name).

**Gap 3: Full static → dynamic → API feedback loop under one orchestrator.**
Android-pentest-mcp does static+dynamic as a linear skill. But no tool does
the closed loop: static finds candidate encryption → Frida hooks the live
method → proxy captures the encrypted traffic → AI cross-references the
captured ciphertext against the code and proves the implementation. Each
tool does one piece. ReverserX plans across all three domains in one session,
and the reviewer can inject a dynamic step when static findings warrant it.

**Gap 4: Standalone architecture — not MCP glue.**
Every tool in 2025-2026 requires Claude Code or Claude Desktop to function.
They give you tools; you still need an agent. ReverserX is self-contained:
its own planner, executor, reviewer, memory, and session persistence. It
works headless, as a CLI, or as an interactive shell without any external
agent framework.

**Gap 5: Deobfuscation reasoning for mobile.**
Kong has the most sophisticated deobfuscation in the field — 5 detection
heuristics, 6 symbolic tools (z3 + Ghidra), an agentic deobfuscation loop.
But it's binary-only (ELF/PE). No tool detects control flow flattening in
Smali, string encryption in DEX, or packer signatures in APKs and then
reasons about them with AI. This is wide open.

**Gap 6: Cost-aware routing with estimates.**
Kong tracks cost but doesn't route on it. No tool says: "This search task
costs $0.02 with DeepSeek vs $0.40 with Opus — same quality, using DeepSeek."
For bug bounty hunters on a budget, this matters. ReverserX estimates cost
before execution and selects the cheapest model adequate for each sub-task.

---

## High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                       CLI / Interactive Shell                     │
├──────────────────────────────────────────────────────────────────┤
│                      Agentic Orchestrator                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐ │
│  │ Planner  │  │ Executor │  │ Reviewer │  │ Session Memory   │ │
│  │ (multi-  │  │ (retry,  │  │ (assess, │  │ (findings,       │ │
│  │  step    │  │  error,  │  │  adjust, │  │  hypotheses,     │ │
│  │  plan)   │  │  context)│  │  inject) │  │  key locations)  │ │
│  └──────────┘  └──────────┘  └──────────┘  └──────────────────┘ │
├──────────────────────────────────────────────────────────────────┤
│                 AI Model Router + Cost Estimator                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐ │
│  │ DeepSeek │  │  Claude  │  │  Local   │  │  Cost Estimator  │ │
│  │   (R1)   │  │  (Opus)  │  │ (Ollama) │  │  ($/task, route)│ │
│  └──────────┘  └──────────┘  └──────────┘  └──────────────────┘ │
├──────────────────────────────────────────────────────────────────┤
│              Context Manager (the hard problem)                   │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐ │
│  │ Chunking │  │Relevance │  │  Token   │  │   ChromaDB       │ │
│  │(class/   │  │ Ranking  │  │  Budget  │  │   Semantic       │ │
│  │ method)  │  │(goal-tied│  │ Enforcer │  │   Retrieval      │ │
│  └──────────┘  └──────────┘  └──────────┘  └──────────────────┘ │
├──────────────────────────────────────────────────────────────────┤
│                    Tool Layer (MCP-compatible)                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐ │
│  │  Static  │  │ Dynamic  │  │   API    │  │   Deobfuscation  │ │
│  │ Analysis │  │ Analysis │  │ Analysis │  │   & Unpacking    │ │
│  └──────────┘  └──────────┘  └──────────┘  └──────────────────┘ │
├──────────────────────────────────────────────────────────────────┤
│                    Storage & Persistence                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐ │
│  │  SQLite  │  │ ChromaDB │  │  Redis   │  │   FileStore      │ │
│  │(findings,│  │(vectors) │  │(sessions)│  │  (artifacts,     │ │
│  │ sessions)│  │          │  │          │  │   reports)       │ │
│  └──────────┘  └──────────┘  └──────────┘  └──────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

---

## Component Design

### 1. Agentic Orchestrator

The orchestrator is the brain. It receives high-level goals and decomposes
them into tool calls across static, dynamic, and API domains — in one
session, with one memory.

**Planner**: Takes user goal + available tool descriptions + session memory →
produces a step-by-step analysis plan that spans all three analysis domains.
Uses Claude Opus for complex multi-domain planning, DeepSeek R1 for
reasoning-heavy single-step analysis.

**Executor**: Translates plan steps into concrete tool invocations. Handles
retries, error recovery, and context passing between steps. When the reviewer
injects a new step (e.g., "static found crypto → now hook it with Frida"),
the executor seamlessly switches domains.

**Reviewer**: After each tool execution, reviews the output. If the result is
insufficient or raises new questions, it injects additional steps into the
plan — including cross-domain steps. For example, after static analysis finds
a `Cipher.doFinal()` call, the reviewer can inject: "Hook this method with
Frida, capture the key material, then verify with proxy capture."

**Session Memory**: Maintains a working context across the session that
persists to disk. Summarizes previous findings, tracks hypotheses, manages
key code locations. Enables session resume — "continue analysis from
yesterday" without losing context.

### 2. AI Model Router + Cost Estimator

Routes tasks to the optimal model based on task type, cost, and capability.
This is not just multi-model — it's cost-aware multi-model routing.

| Task Type                  | Primary Model   | Fallback       | Est. Cost/Task |
|----------------------------|-----------------|----------------|----------------|
| Complex planning           | Claude Opus     | DeepSeek R1    | $0.08-0.15     |
| Code summarization         | DeepSeek R1     | Claude Sonnet  | $0.02-0.05     |
| Pattern recognition        | DeepSeek R1     | Local model    | $0.01-0.03     |
| Vulnerability assessment   | Claude Opus     | DeepSeek R1    | $0.10-0.20     |
| Deobfuscation reasoning    | DeepSeek R1     | Claude Opus    | $0.05-0.15     |
| Documentation generation   | Claude Sonnet   | Local model    | $0.01-0.03     |
| Sensitive code review      | Local model     | —              | $0.00          |
| Embedding / semantic search| Nomic Embed     | —              | $0.00          |

**Cost Estimator**: Before executing a plan, the router estimates the total
cost based on expected token usage per step × model pricing. The user sees
an estimate before work begins. The router can be configured with cost
thresholds — "use DeepSeek whenever it's adequate, escalate to Claude only
for vulnerability assessment."

### 3. Context Manager (Flagship Feature)

This is the highest-leverage component in the entire platform. The context
window bottleneck is the single biggest unsolved problem in AI-assisted RE —
mrphrazer's own evaluation confirms it. ReverserX tackles it systematically.

**Chunking Engine**: Splits decompiled code into semantic units:
- Java/Kotlin: class-level and method-level chunks
- Smali: method-level chunks with instruction count metadata
- Native (.so): function-level chunks from Ghidra/objdump
- API captures: endpoint-level chunks from HAR parsing

**Relevance Ranking**: Each chunk is scored against the current analysis goal
using a composite score: keyword match + semantic similarity (via embeddings)
+ call-graph distance from known-interesting nodes + recency bonus.

**Token Budget Enforcer**: Fits as many top-ranked chunks as possible within the
configured budget (default: 60K tokens, leaving ~20K for system prompt +
conversation + response). Lower-ranked chunks are summarized rather than
included verbatim.

**Semantic Retrieval (ChromaDB)**: All chunks are embedded at ingest time.
The orchestrator can query: "find code that handles JWT validation" without
knowing class names, method names, or keywords. This is critical for
obfuscated code where string search fails.

**Hierarchical Summarization**: For very large codebases (50K+ methods):
- Level 1: Summarize each method (1-2 sentences)
- Level 2: Summarize each class (paragraph)
- Level 3: Summarize each package (few paragraphs)
- The orchestrator can "zoom in" on any level by requesting full code

### 4. Tool Layer

Each tool follows an MCP-compatible interface: `{name, description,
input_schema, execute()}`. The AI models receive tool descriptions and can
invoke them via function calling. Tools are organized into four domains:

#### 4a. Static Analysis Tools

```
jadx_decompile(apk_path) → {java_sources, manifest, resources, certificates}
  - Wraps JADX CLI, parses output into structured format
  - Extracts: AndroidManifest.xml, all Java sources, native libs, assets
  - Returns file tree with metadata for the Context Manager to index

jadx_search(pattern, sources_dir) → [matches with context]
  - Full-text and regex search across decompiled sources
  - Returns file:line references with surrounding context
  - Results are ranked by relevance for context injection

manifest_analyze(apk_path) → {permissions, components, attack_surface}
  - Parses AndroidManifest.xml into structured data
  - Flags dangerous permission combinations
  - Maps exported components (attack surface)

native_analyze(so_path) → {imports, exports, strings, sections}
  - objdump/readelf analysis of .so files
  - FLIRT-style library function signature matching
  - Section analysis for packing/obfuscation detection

call_graph_trace(method_fqn) → {callers, callees, depth}
  - Builds cross-reference graph from decompiled code
  - Traces data flow through method chains
  - Cross-language: Java → JNI → native ARM

ghidra_deep_analyze(binary_path) → {functions, types, xrefs, decompiled}
  - Headless Ghidra analysis for native binaries
  - Type recovery, struct synthesis
  - P-Code access for deobfuscation tools
```

#### 4b. Dynamic Analysis Tools

```
adb_connect(device_serial) → connection_state
adb_shell(command) → stdout
adb_list_devices() → [devices]

frida_attach(package_name) → session
frida_hook(hook_type, class, method) → hook_id
  - hook_types: hook_encryption, hook_ssl_pinning, hook_intents, trace_class
  - Bundled scripts for common patterns
  - Custom script injection supported

frida_enum_classes(package, filter) → [class_names]
  - Runtime class enumeration
  - Obfuscated class discovery via pattern matching

logcat_monitor(package, filter, duration) → [log_entries]
network_capture(package, duration) → pcap_file

frida_smart_hook(finding) → session
  NEW: The orchestrator, after reviewing static findings, can auto-generate
  a targeted Frida script. Example: static analysis found Cipher.doFinal()
  in com.example.crypto.EncryptionManager → auto-generates script hooking
  that specific class+method with key material capture.
```

#### 4c. API Analysis Tools

```
proxy_start(port) → proxy_url
proxy_capture(flow_file, filters) → [requests]
api_endpoint_map(har_file) → [structured_endpoints]
  - Auto-normalizes paths (UUIDs → {uuid}, IDs → {id})
  - Groups by host, auth requirement, response codes
  - Produces OpenAPI-like schema

api_replay(method, url, headers, body) → response
api_fuzz(url_template, method) → [responses]
  - Auto-fuzz with common payloads
  - Flags anomalies (5xx, error messages, SQL errors)

api_analyze_auth(har_file) → auth_flow_diagram
  - Traces authentication flow from captured traffic
  - Identifies token types, refresh patterns, OAuth flows
```

#### 4d. Deobfuscation & Unpacking Tools (NEW — differentiating feature)

```
detect_obfuscation(apk_path) → {type, confidence, evidence}
  - Detects: ProGuard, DexGuard, Allatori, StringFog, custom
  - Heuristics: class name patterns, control flow complexity,
    string encryption presence, reflection usage density
  - Returns structured report with per-class confidence scores

detect_packer(apk_path) → {packer, confidence, indicators}
  - Detects: Jiagu, Bangcle, 360, Tencent, Alibaba, UPX
  - DEX header analysis, native lib signatures, manifest markers
  - Guides user to appropriate unpacking strategy

detect_cff(smali_or_java) → {present, state_variable, case_count}
  - Control flow flattening detection in Smali/DEX
  - Identifies the state variable and dispatcher structure
  - Provides pattern reference for AI deobfuscation reasoning

deobfuscate_strings(apk_path) → {decrypted_strings, method}
  - Static string decryption emulation
  - Common algorithms: XOR, AES-ECB, RC4, custom
  - Attempts to recover string table without runtime execution

deobfuscate_reason(task_description, code_context) → analysis
  AI-POWERED: Uses DeepSeek R1 to reason about obfuscated code
  - Takes detected obfuscation type + obfuscated code → produces
    deobfuscated analysis
  - Has access to symbolic simplification tools (z3 integration planned)
  - Inspired by Kong's agentic deobfuscation loop, but for mobile
```

#### 4e. Cross-Platform Call Graph (NEW — differentiating feature)

```
cross_language_trace(entry_point) → unified_call_graph
  - Java/Kotlin → JNI → native ARM call graph
  - Resolves dynamically registered JNI methods
  - Maps encrypted/obfuscated JNI method names
  - Produces single unified view across language boundaries
```

### 5. Storage & Persistence Layer

**SQLite**: Persistent store for analysis results, tool outputs, findings,
hypotheses, and session state. Enables session resume — the orchestrator can
restore its full state from a previous run.

**ChromaDB**: Vector embeddings of decompiled code chunks, API responses, and
strings. Enables semantic search and relevance ranking. Integrated with the
Context Manager for every analysis session.

**Redis**: Transient state — active Frida sessions, proxy captures, analysis
queue. Fast key-value for the agent loop's working memory.

**File Store**: Raw artifacts — APKs, decompiled sources, PCAPs, HAR files,
Frida scripts, deobfuscation output. Organized by project/target. Supports
session resume via artifact path tracking.

**Session Persistence**: Every session is serializable — findings, hypotheses,
tool call history, plan state, and context manager state. "Continue analysis
from yesterday" is a first-class feature, not an afterthought. The SQLite
database tracks project metadata, findings, tool runs, and session summaries.

---

## Agentic Loop — Step-by-Step Flow

```
1. User: "Find how this APK encrypts its API requests"

2. Cost Estimator:
   → Estimated: $0.35-$0.60 total
   → Routing plan: planning=Claude Opus, code_analysis=DeepSeek R1,
     summarization=Claude Sonnet
   → User confirms or adjusts

3. Planner (Claude Opus):
   → Plan:
     a. [static] Decompile APK with JADX
     b. [static] Detect obfuscation type
     c. [static] Search for crypto keywords (Cipher, AES, SecretKeySpec)
     d. [static] Analyze identified encryption methods with DeepSeek R1
     e. [static] If native methods found, analyze .so with Ghidra
     f. [dynamic] Hook identified encryption methods with Frida
     g. [api] Set up proxy, capture actual traffic
     h. [api] Map API endpoints, identify encrypted fields
     i. [cross-ref] Match captured encrypted data against code findings
     j. [report] Document the full encryption flow with evidence

4. Executor runs each step:
   → tool_call: jadx_decompile("target.apk")
   → tool_call: detect_obfuscation("target.apk")
      → "ProGuard detected. Class names shortened, no string encryption."
   → Context Manager indexes all decompiled code into ChromaDB
   → tool_call: jadx_search(pattern="Cipher|encrypt|AES|SecretKeySpec")
   → Reviewer: "Found 3 candidate methods in com.example.crypto.*. Flagging."
   → tool_call: native_analyze("./libs/libencrypt.so")
      → "Native library exports: encrypt_data(), decrypt_data(), generate_key()"
   → Reviewer injects: "Trace JNI calls from Java crypto to native encrypt_data()"
   → tool_call: cross_language_trace("com.example.crypto.EncryptionManager.encrypt")
      → Unified call graph shows: CryptoManager.encrypt() → JNI → libencrypt.encrypt_data()

5. Reviewer adjusts plan dynamically:
   → "Static found native encryption. Plan now includes:
      - Frida hook on CryptoManager.encrypt() to capture arguments
      - Frida hook on libencrypt.encrypt_data() to capture key material
      - Proxy capture of actual API traffic
      - Cross-reference to prove the cipher"

6. Dynamic phase:
   → tool_call: frida_hook("hook_encryption", class="com.example.crypto.*")
   → User triggers the app action
   → Frida captures: AES key = "0123456789abcdef", IV from SecureRandom
   → tool_call: network_capture(package="com.example.app", duration=30)
   → tool_call: api_endpoint_map("capture.har")
      → "POST /api/data — body is base64, decoded is AES ciphertext"

7. Cross-reference (DeepSeek R1):
   → "AES/CBC/PKCS5Padding confirmed via Frida hook.
      Key: 0123456789abcdef (hardcoded in libencrypt.so:0x4a20).
      IV: randomly generated per request, prepended to ciphertext.
      API: POST /api/data, body = base64(IV + AES-CBC(plaintext, key)).
      Weakness: static key, no key derivation, no cert pinning."

8. Final output: Structured report with:
   - Encryption flow diagram (Mermaid)
   - Code locations with line numbers
   - Frida hook output (key capture evidence)
   - Proxy capture showing encrypted traffic
   - Vulnerability assessment (static key, hardcoded in native lib)
   - Cost summary: $0.42 total across 13 tool calls
```

---

## What Makes This Different — Summary

| Feature | Everyone Else | ReverserX |
|---|---|---|
| Architecture | MCP wrapper — needs Claude Code/Desktop | Standalone — own orchestrator, own loop |
| Model routing | Single model or manual config | Cost-aware multi-model per task type |
| Context management | Dump raw code, pray | Chunking + ranking + ChromaDB + token budget |
| Analysis domains | Static OR dynamic OR API (one per tool) | Static → dynamic → API in one session |
| Deobfuscation | Kong: binary-only, no mobile | Mobile deobfuscation detection + AI reasoning |
| Session persistence | None (or artifact export only) | Full SQLite session resume |
| Cost awareness | None (Kong tracks, doesn't route) | Pre-plan estimate + budget-optimized routing |
| Report generation | LLM-generated text | Structured report with evidence links, Mermaid diagrams |

---

## Project Structure

```
reverserx/
├── pyproject.toml
├── README.md
├── ARCHITECTURE.md
│
├── reverserx/
│   ├── __init__.py
│   ├── main.py                         # Entry point
│   │
│   ├── agent/                          # Agentic orchestrator (standalone)
│   │   ├── __init__.py
│   │   ├── orchestrator.py             # Main loop: plan → execute → review
│   │   ├── planner.py                  # Multi-domain task decomposition
│   │   ├── executor.py                 # Tool invocation with retry/context
│   │   ├── reviewer.py                 # Output review + cross-domain injection
│   │   └── memory.py                   # Session persistence + hypothesis tracking
│   │
│   ├── ai/                             # AI model integration
│   │   ├── __init__.py
│   │   ├── router.py                   # Cost-aware multi-model routing
│   │   ├── cost_estimator.py           # Pre-plan token + cost estimation
│   │   ├── providers/
│   │   │   ├── __init__.py
│   │   │   ├── deepseek.py             # DeepSeek R1 (reasoning)
│   │   │   ├── claude.py               # Claude Opus + Sonnet (Anthropic)
│   │   │   ├── ollama.py               # Local models (privacy)
│   │   │   └── base.py                 # Abstract provider interface
│   │   ├── prompts/                    # Specialized prompt templates
│   │   │   ├── __init__.py
│   │   │   ├── reverse_engineer.py     # General RE prompts
│   │   │   ├── deobfuscation.py        # Obfuscation reasoning prompts
│   │   │   ├── vulnerability.py        # Vulnerability assessment prompts
│   │   │   └── api_analysis.py         # API reverse engineering prompts
│   │   └── context.py                  # Context Manager (flagship)
│   │       - Chunking engine
│   │       - Relevance ranking
│   │       - Token budget enforcer
│   │       - Hierarchical summarizer
│   │
│   ├── tools/                          # MCP-compatible tool layer
│   │   ├── __init__.py
│   │   ├── registry.py                 # Tool registry + function schema generation
│   │   ├── base.py                     # Tool interface definition
│   │   │
│   │   ├── static/                     # Static analysis tools
│   │   │   ├── __init__.py
│   │   │   ├── jadx.py                 # JADX decompilation wrapper
│   │   │   ├── search.py               # Code search + manifest + strings
│   │   │   └── native.py               # Native library analysis (objdump/readelf)
│   │   │
│   │   ├── dynamic/                    # Dynamic analysis tools
│   │   │   ├── __init__.py
│   │   │   ├── adb.py                  # ADB bridge (connect, shell, list)
│   │   │   ├── frida_manager.py        # Frida session + hook management
│   │   │   ├── frida_scripts/          # Bundled Frida hooking scripts
│   │   │   │   ├── hook_encryption.js  # Cipher, MessageDigest, Mac, SecretKeySpec
│   │   │   │   ├── hook_ssl_pinning.js # OkHttp, TrustKit, WebView bypass
│   │   │   │   ├── hook_intents.js     # Intent creation + dispatch capture
│   │   │   │   └── trace_class.js      # Universal class method tracer
│   │   │   ├── logcat.py               # Logcat monitor with filtering
│   │   │   └── network.py              # Network capture via tcpdump
│   │   │
│   │   ├── api/                        # API analysis tools
│   │   │   ├── __init__.py
│   │   │   ├── proxy.py                # mitmproxy wrapper
│   │   │   ├── endpoint_mapper.py      # HAR → structured API map
│   │   │   └── replayer.py             # Request replay + fuzzing
│   │   │
│   │   ├── binary/                     # Binary analysis tools
│   │   │   ├── __init__.py
│   │   │   ├── ghidra.py               # Headless Ghidra integration
│   │   │   └── strings.py              # Multi-encoding string extraction
│   │   │
│   │   └── deobfuscation/              # Deobfuscation tools (NEW)
│   │       ├── __init__.py
│   │       ├── detector.py             # Obfuscation type detection
│   │       ├── packer_detect.py         # APK packer identification
│   │       ├── cff_detect.py           # Control flow flattening (Smali)
│   │       ├── string_decrypt.py       # Static string decryption
│   │       └── cross_trace.py          # Java↔JNI↔Native call graph
│   │
│   ├── storage/                        # Persistence layer
│   │   ├── __init__.py
│   │   ├── database.py                 # SQLite: projects, findings, sessions
│   │   ├── vectors.py                  # ChromaDB: semantic code search
│   │   └── files.py                    # Artifact file management
│   │
│   ├── reporting/                      # Report generation (NEW)
│   │   ├── __init__.py
│   │   ├── markdown.py                 # Markdown report with evidence links
│   │   ├── html.py                     # Interactive HTML report
│   │   └── evidence.py                 # Evidence linking (code ↔ hook ↔ capture)
│   │
│   ├── config/                         # Configuration
│   │   ├── __init__.py
│   │   ├── settings.py                 # YAML/env-based config
│   │   └── model_pricing.toml          # Live model pricing for cost estimator
│   │
│   └── utils/                          # Shared utilities
│       ├── __init__.py
│       ├── subprocess.py               # Robust subprocess management
│       └── platform.py                 # Platform detection + tool availability
│
├── scripts/                            # Standalone helper scripts
│   ├── setup_frida_server.sh
│   ├── setup_proxy_cert.sh
│   └── pull_apk.sh
│
└── tests/
    ├── test_agent/
    ├── test_tools/
    ├── test_ai/
    └── test_deobfuscation/
```

---

## New Modules to Build (Priority Order)

### Phase 1 — Immediate (highest differentiation)

1. **`ai/context.py` — Context Manager (fully built out)**
   Chunking, relevance ranking, token budget enforcement, ChromaDB semantic
   retrieval, hierarchical summarization. This is the flagship feature that
   nobody else has. Every analysis session starts by indexing decompiled
   code through this pipeline.

2. **`tools/deobfuscation/detector.py` — Obfuscation Detection**
   Detect ProGuard, DexGuard, Allatori, StringFog, custom obfuscation in
   APKs. Class name entropy analysis, control flow complexity metrics,
   string encryption detection. First-of-its-kind for mobile.

3. **`ai/router.py` + `ai/cost_estimator.py` — Cost-Aware Router**
   Extend the existing router with pricing data per model, pre-plan cost
   estimates, and cost-optimized routing rules. Bug bounty hunters care
   about this.

### Phase 2 — Medium-term

4. **`tools/deobfuscation/packer_detect.py` — Packer Detection**
   Jiagu, Bangcle, 360, Tencent, Alibaba, UPX detection. DEX header
   analysis, native lib signatures, manifest markers.

5. **`tools/deobfuscation/cross_trace.py` — Cross-Language Call Graph**
   Java/Kotlin → JNI → native ARM. Dynamically registered JNI resolution.
   Unified view across language boundaries.

6. **`reporting/` — Structured Report Generation**
   Markdown reports with evidence links (code location → hook output →
   proxy capture). Mermaid diagrams for encryption/auth flows. HTML
   interactive reports for bug bounty submissions.

### Phase 3 — Long-term

7. **`agent/memory.py` — Full Session Resume**
   SQLite-persisted session state. "Continue analysis from yesterday" with
   full context restoration including ChromaDB index references.

8. **`tools/deobfuscation/string_decrypt.py` — Static String Decryption**
   Emulate common string decryption algorithms (XOR, AES-ECB, RC4) to
   recover string table without runtime execution.

---

## Key Design Decisions

### Why standalone, not MCP?
MCP tools give you tools. ReverserX gives you an agent that knows how to use them.
Every existing project requires Claude Code or Claude Desktop. ReverserX ships
its own planner, executor, reviewer, and memory — it works headless, as a CLI,
or as an interactive shell without any external agent framework.

### Why Python?
- Largest ecosystem for security tools (Frida, mitmproxy, Ghidra bindings)
- Best AI/LLM library support (anthropic, openai)
- Rapid prototyping for a personal research tool
- Easy subprocess management for external tools (JADX, ADB, objdump)

### Why multi-model?
- DeepSeek R1 excels at reasoning and code pattern analysis
- Claude Opus excels at planning and nuanced security assessment
- Claude Sonnet is cost-effective for summarization and documentation
- Local models (Ollama) for sensitive code that shouldn't leave the machine
- Cost optimization: route simple tasks to cheaper models, save Opus for what matters

### Why context management is the bet?
The context window is the fundamental bottleneck in AI-assisted RE — every
researcher building these tools confirms it. A purpose-built context manager
that chunks, ranks, budgets, and semantically retrieves decompiled code is the
highest-leverage feature anyone can build in this space. It's what makes
deep analysis possible rather than just triage.

### Why deobfuscation for mobile?
Kong proved that AI-powered deobfuscation works for native binaries (5
heuristics, z3 symbolic tools, agentic loop). But nobody has ported these
ideas to Android. Detecting ProGuard vs DexGuard, identifying control flow
flattening in Smali, and reasoning about string encryption with AI — this is
a green field.

---

## External Dependencies

| Dependency       | Purpose                          | Installation                |
|------------------|----------------------------------|-----------------------------|
| JADX             | APK → Java decompilation        | Download jadx CLI           |
| ADB              | Android device communication     | Android SDK Platform Tools  |
| Frida            | Runtime instrumentation          | pip install frida-tools     |
| mitmproxy        | HTTP/HTTPS interception          | pip install mitmproxy       |
| Ghidra           | Native binary analysis (opt)     | Download Ghidra             |
| ChromaDB         | Vector embeddings                | pip install chromadb        |
| Anthropic SDK    | Claude API                       | pip install anthropic       |
| OpenAI SDK       | DeepSeek API (compatible)        | pip install openai          |
| z3-solver        | Symbolic analysis (deobfuscation)| pip install z3-solver       |
| Smali            | Smali manipulation               | bundled with apktool        |

---

## Security & Ethics Boundaries

This tool is designed for **authorized security research only**. Built-in safeguards:

1. **Target validation**: Prompts user to confirm they have authorization before
   connecting to any device or network endpoint
2. **Audit logging**: Every action is logged with timestamps for responsible disclosure
3. **Scope enforcement**: Project-level scope definition (IPs, domains, packages)
   that gates dynamic analysis
4. **No auto-exploit**: The tool analyzes and documents but does not automatically
   exploit vulnerabilities — the researcher is always in the loop
5. **Local model option**: Sensitive/proprietary code can be analyzed with local
   Ollama models only, preventing code from leaving the machine. Critical for
   internal security reviews and NDAs.
