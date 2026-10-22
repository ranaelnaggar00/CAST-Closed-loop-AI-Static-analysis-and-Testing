# Skill: rtl-sec-focused-area

**Invocation:** `/rtl-sec-focused-area`

## Purpose

Focused-area RTL security audit. Deep semantic area discovery → per-leaf threat model → parallel specialist researchers → adversarial verification → dedup → report.

Run entirely in the main Claude loop using the Agent tool. No workflow engine.

---

## Arguments

```
/rtl-sec-focused-area <scope> [area=<plain-english-area>] [out=<output-dir>] [spec=<path-to-spec-pdf>]
```

- `scope`  — absolute path to RTL directory (required)
- `area`   — plain-English focus area, e.g. "zstd decompression". Omit to audit all.
- `out`    — output directory (default: `<scope>/../focused-area-out`)
- `spec`   — path to microarchitecture PDF (optional; enables spec-CHECK injection)
- `discover` — if present, print area tree and selected leaves then stop

---

## Execution protocol

Read this entire skill before taking any action. Execute each phase in order.
Use the Agent tool for all sub-tasks. Run independent agents in parallel (single message, multiple Agent tool calls).
Never use the Workflow tool.

### Progress reporting rules

After **every phase completes**, print a progress banner to the user in this format:
```
━━━ [PHASE X complete] ──────────────────────────────────
  Files:    <covered>/<security-relevant> files read so far
  Leaves:   <audited>/<total> leaves complete
  Sightings:<raw> raw | <verified> verified | <canonical> canonical
  Next:     <one-line description of next phase>
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

Within Phase 2 (researchers), print a mid-phase update after **each leaf completes** (not after each individual researcher — wait for all 6 researchers for a leaf to finish, then print):
```
  ✓ Leaf <leaf_path> — <N> raw sightings, <covered>/<total> files read
    Researchers done: Arith=<✓|✗> FSM=<✓|✗> JobBnd=<✓|✗> OutGate=<✓|✗> Integration=<✓|✗> Conv=<✓|✗>
```

Within Phase 4 (verification), print after every 10 verifications complete:
```
  Verifying: <N>/<total> done — <tp> TRUE_POSITIVE so far
```

Print the terminal summary at the very end regardless of whether any phase failed.

---

### PHASE 0 — Manifest

Run one Agent:
- `find <scope> -type f \( -name "*.sv" -o -name "*.svh" -o -name "*.vh" -o -name "*.v" \) | sort`
- Filter out: `rf1w1r`, `ram1w`, `ram2w`, `generic_1r1w_ram`, `dsa_genram`, `/ctech/`, `/megen/`, `_tb.sv`, `_tb.v`
- Result: `secFiles[]` — the security-relevant file list
- Log: `Phase 0: N security-relevant files (M total)`

---

### PHASE 0.4 — Spec Decomposition (skip if no spec)

If `spec` provided:

**Agent A — SpecExtractor:** Read the spec PDF (all pages). Extract every security-relevant requirement as a numbered CHECK in this format:
```
SPEC_CHECK_START
id: CHECK-NNN
section: <section number and title>
category: arithmetic_bounds|reset_completeness|fsm_completeness|output_gating|job_isolation|lifecycle_gating|error_handling|algorithm_selection
severity_hint: CRITICAL|HIGH|MEDIUM|LOW
check_text: <verbatim or close paraphrase>
rationale: <one sentence: why security-relevant>
keywords: [signal_name_1, signal_name_2, ...]
SPEC_CHECK_END
```

Parse all CHECKs into `specChecks[]`.

**Agents B (parallel batches of 30 CHECKs) — RtlMapper:** For each CHECK, score RTL files by keyword overlap. Return:
```
CHECK_MAP_START
id: CHECK-NNN
candidates:
  - file: <abs_path>
    score: HIGH|MEDIUM|LOW
    matched_keywords: [kw1, kw2]
    reason: <one sentence>
CHECK_MAP_END
```

Build `specToRtl{}`: check_id → candidate files.
Write `<out>/SPEC-CHECKS.json` and `<out>/SPEC-TO-RTL.json`.

---

### PHASE 0.4b — Synthetic Conformance Checks (no-spec fallback)

Run this phase **only when no `spec` was provided**. It synthesises a lightweight set of protocol-agnostic CHECKs from the RTL structure itself, injected into researcher prompts exactly like real spec CHECKs from Phase 0.4.

Run one Agent — **ConformanceSynthesizer:**

> You are analysing RTL files to generate protocol-agnostic conformance checks — things the RTL *must* do that are often missing even when there is no formal spec.
>
> For each file in the list below, read it and identify every place where:
>
> a. **Field extraction without bounds** — a field is read from external input (signal from a trust-boundary port) and stored in a register, but no check validates it against a maximum or an enumerated set of legal values. Generate one CHECK per field.
>
> b. **Reserved-value handling** — an enum or type field is decoded via case/if-else, but reserved / undefined values have no explicit error assignment (fall to default, DONE, or are silently ignored). Generate one CHECK per field.
>
> c. **Consumed-bytes / offset accounting** — a consumed-byte or bit-offset counter is incremented, but one or more contributing fields from the same protocol struct are not added to it. Generate one CHECK per counter.
>
> d. **Error-code constant vs. protocol spec** — a parameter/constant named `*_ERROR*`, `*_ERR*`, `*_CODE*` is defined; flag it for cross-check against the system spec or any documented error-code table. Generate one CHECK per constant.
>
> Return each as:
> ```
> SPEC_CHECK_START
> id: SYNTH-NNN
> section: synthetic / no-spec
> category: arithmetic_bounds|fsm_completeness|error_handling|algorithm_selection
> severity_hint: CRITICAL|HIGH|MEDIUM|LOW
> check_text: <what must be true>
> rationale: <one sentence: why security-relevant>
> keywords: [signal_name_1, signal_name_2, ...]
> SPEC_CHECK_END
> ```
>
> FILES: `<all secFiles from Phase 0 — limit to 60 files: prioritise EXTERNAL trust_boundary first>`

Parse all `SYNTH-NNN` blocks into `specChecks[]`. Feed them into Phase 0.7 and Phase 2 researcher prompts under `SPEC CHECKs FOR THIS LEAF` exactly as real spec CHECKs would be. Label them `(synthetic)` so researchers know the spec source is inferred, not authoritative.

Log: `Phase 0.4b: N synthetic checks generated (no spec provided)`

---

### PHASE 0.5 — Deep Semantic Area Discovery

Split `secFiles` into batches of 8. Run all batches in parallel (one Agent per batch).

Each agent prompt:
> You are performing a deep semantic read of RTL files to build a behavioral model for security-focused area classification.
> For each file: open with Read tool. For EACH MODULE answer:
> a. PIPELINE ROLE: what does this module compute?
> b. DATA FLOWS: external inputs and outputs (name key signals)
> c. FSM STATES: list every state enum; what input class drives each transition?
> d. KEY INVARIANTS: conditions that must always hold
> e. TRUST BOUNDARY: EXTERNAL (attacker-controlled inputs) or INTERNAL? Name attacker-controlled ports.
> f. HARD-RESET-ONLY REGS: registers cleared only by hard reset, not soft/job-boundary
> g. SECURITY OBSERVATIONS: counters on attacker-supplied sizes, commented-out errors, missing defaults
>
> Return per file:
> ```
> FILE_META_START
> path: <absolute path>
> modules: [name1, name2]
> pipeline_role: <1-2 sentences>
> data_flows: inputs=[p1, p2] outputs=[p3, p4]
> fsm_states: [s1, s2] transitions=[input_class → state]
> key_invariants: [inv1, inv2]
> trust_boundary: EXTERNAL|INTERNAL attacker_ports=[port_name]
> hard_reset_only_regs: [reg1, reg2]
> security_observations: <brief freeform>
> semantic_area: <L1/L2/L3 path based on what module actually does>
> FILE_META_END
> ```
>
> FILES: <batch list>

Parse all `FILE_META_START...FILE_META_END` blocks into `fileMeta[]`.

**AreaTreeBuilder Agent** — Build the area tree from `fileMeta`. Prompt:

> Build a hierarchical semantic area tree from RTL behavioral metadata.
> Rules: L1=coarse domain, L2=subdomain, L3=pipeline stage. Every file in exactly one leaf. Leaf size 3-20 files.
> Add `trust_boundary_files` and `hard_reset_only_concern` per leaf.
> Return valid JSON: `{ "area_tree": { "<L1>": { "<L2>": { "<L3>": { "files": [...], "modules": [...], "description": "...", "trust_boundary_files": [...], "hard_reset_only_concern": true|false, "key_invariants_summary": "..." } } } } }`
>
> **IMPORTANT:** The user wants to audit: "<area>". Ensure that area appears prominently.
>
> BEHAVIORAL METADATA (<N> files):
> <metaSummary — LIMIT TO 30 FILES MAX, prioritize EXTERNAL trust_boundary first, then non-empty security_observations. One line per file: `path | modules | pipeline_role | trust_boundary | semantic_area`. Do NOT include fsm_states/invariants/observations in this summary — those are too verbose.>

Parse JSON. If parse fails, use flat fallback: one leaf `all/default/all_files` with all secFiles.

Enumerate all leaves from the tree into `allLeaves[]`.

---

### PHASE 0.6 — Area Filter

If `area` specified, select `targetLeaves` using 3 passes:

**Pass 1** — path token match: any leaf whose path contains a token from `area` (split on spaces/punctuation, min 3 chars)

**Pass 2** — description+module text match: any leaf not in Pass 1 whose description or module list contains an area token

**Pass 3** — one LLM Agent for remaining undecided leaves:
> Decide if each leaf is semantically part of "<area>". Be INCLUSIVE.
> Return: `path: <leaf_path> | verdict: INCLUDE|EXCLUDE | reason: <≤8 words>`

`targetLeaves` = union of all three passes. If empty, use all leaves.

**Batch execution — cap at 20 leaves per pass:** If `targetLeaves` has more than 20 entries, sort by `trust_boundary_files` count descending and split into batches of 20. Run Phase 0.7 → Phase 2 → Phase 3 → Phase 4 → Phase 5 as a complete pipeline for batch 1, then repeat the full pipeline for each subsequent batch. Accumulate `allSightings[]`, `coveredFiles[]`, and `canonical[]` across batches before Report Generation. Print a batch header before each pass:
```
━━━ [BATCH N/M — leaves X-Y of Z] ──────────────────────────
  Leaves this batch: <leaf paths>
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```
Phase 5 dedup and Report Generation run once after all batches complete, across the full accumulated sighting set.

Log selected leaves and pass breakdown.

**Integration Anchor step** — after selecting `targetLeaves`, always add the following files to `secFiles[]` and assign them to a synthetic leaf `_Integration/Parameters` (appended to `targetLeaves` unless already covered, does not count against the 15-leaf cap):

- Every file matching `*params*.v*`, `*params*.vh`, `*defines*.vh`, `*config*.vh`, `*_pkg.sv` anywhere under `<scope>` — these hold error-code constants and global parameters.
- The single top-level integration file that instantiates the most target-leaf submodules (determined by grep for module names from `targetLeaves[*].modules`). If more than one file ties, take both.

Run one Agent — **IntegrationReader** — on the `_Integration/Parameters` files with the same FILE_META prompt as Phase 0.5. Append its output to `fileMeta[]`. The `_Integration/Parameters` leaf participates in Phase 2 with all 6 researcher roles (90+6 = 96 total agents). Its threat model focuses on: parameter constant correctness, error-code tables, top-level output-gating, and cross-module signal truncation.

If `discover` flag: print full tree + selected leaves, stop.

---

### PHASE 0.7 — Per-Leaf Threat Model

For each target leaf, run one Agent in parallel. **Cap prompt to ~1500 chars** for the semantic context section: include at most 10 files, prioritize EXTERNAL trust_boundary, one entry per file: `path | pipeline_role | trust_boundary | key_invariants`.

Prompt per leaf:
> Build a hardware security threat model for leaf: <leaf.path>
> Description: <leaf.description>
> Files: <leaf.files>
>
> SEMANTIC CONTEXT (top files by security relevance):
> <truncated context>
>
> SPEC CHECKs FOR THIS LEAF (if any from Phase 0.4 mapped to these files):
> <check list>
>
> Return:
> ```
> THREAT_MODEL_START
> leaf: <path>
> assets: [name, location, sensitivity, why]
> adversary_capabilities: [port, module, attacker_can, relies_on_invariant]
> trust_boundaries: ingress/egress
> invariant_violations: [invariant, worst_case, enabling_capability]
> spec_findings: [check_id, verdict: SATISFIES|CONTRADICTS|UNVERIFIABLE, rtl_observation]
> prioritized_concerns: (rank 1-8: title, invariant_at_risk, attacker_capability, spec_check_id, focus_files)
> THREAT_MODEL_END
> ```

Parse into `threatModelMap{}`. Write `<out>/threat_models/<leaf>_THREAT-MODEL.md` (parallel write agents).

---

### PHASE 2 — Parallel Researchers Per Leaf

For each target leaf, spawn 6 researcher Agents in parallel. All leaves run concurrently.

Each researcher receives:
- Their specific role focus (see below)
- The leaf's threat model (from Phase 0.7)
- The spec CHECKs mapped to this leaf (from Phase 0.4)
- FILE_LIST: all files in the leaf
- READING CONTRACT, INVESTIGATION PATTERNS, FILE_ACKNOWLEDGMENT, OUTPUT_FORMAT (see Appendix)

**6 roles:**

1. **ArithmeticSafety** — counters/accumulators on external inputs (width truncation), unsigned subtractions (A-B where B>A), shift amounts from external fields, comparison direction errors, array index range checks
2. **FSMCompleteness** — enumerate every FSM state × every input class; missing error transitions; stuck states; case without default
3. **JobBoundary** — registers cleared only by hard reset but holding per-job data; flags/FIFOs/history persisting across job boundaries
4. **OutputGating** — when any error fires, are ALL output-valid/DMA-write signals gated? Trace every error signal to every output-valid consumer. Commented-out error assignments.
5. **IntegrationThreat** — trace security-critical signals (error_abort, output_valid, lifecycle_enable) across module boundaries; floating error outputs; signal width mismatches at boundaries
6. **Conventional** — sequential top-to-bottom read; describe what each module does; note constants, commented code, TODOs, arithmetic on external inputs, case without default

Parse sightings from each output using `===SIGHTING-START===...===SIGHTING-END===` blocks.
Parse covered files from `===COVERAGE-START===...===COVERAGE-END===` blocks.

Build per-leaf result: `{ leaf, findings[], coveredFiles[], researchOutputs[], roleNames[] }`

---

### PHASE 3 — Coverage Gate

For each leaf: diff `leaf.files` against `coveredFiles`. If uncovered files remain, run gap-fill agents (batches of 8, up to 2 rounds) reading uncovered files and reporting sightings.

---

### PHASE 4 — Adversarial Verification

Collect all findings across leaves. If more than 100, sort by confidence (descending) and cap at 100.

Run one verifier Agent per finding in parallel (batched at 16 concurrent max by running multiple parallel() rounds if needed):

> You are a skeptical hardware security reviewer. Determine TRUE_POSITIVE or FALSE_POSITIVE.
> 1. Read the RTL file at the reported line — verify directly.
> 2. Trace who can drive this logic.
> 3. Hunt for protections: lifecycle gates, fuse bits, reset signals, upstream checks, unreachable code.
> 4. For each protection found: can it be bypassed?
>
> VERDICT: TRUE_POSITIVE (confidence: N/10) — reason
> or
> VERDICT: FALSE_POSITIVE (confidence: N/10) — reason
>
> SIGHTING: <raw sighting block>

Keep only TRUE_POSITIVE verdicts as `verified[]`.

---

### PHASE 5 — Dedup

**Structural pre-filter:** remove duplicates with same file + category + line ±10.

If ≥2 remain, run one dedup Agent:
> Deduplicate hardware security Sightings. Mark DUPLICATE when: same root cause, same file/line within 30, one is downstream consequence of another.
> Output: `index=N is_duplicate=true|false canonical=M reasoning="..."`

Remove duplicates. Sort by severity (CRITICAL→HIGH→MEDIUM→LOW) then verdict_confidence.

Result: `canonical[]`

---

### REPORT GENERATION

Run 4 write Agents in parallel:

1. **SIGHTINGS-REPORT.md** — header with scan metadata, severity summary table, per-leaf coverage table, one section per canonical sighting with: severity, title, file, line, attack_surface, code_evidence, analysis, impact, exploit_steps, preconditions, possible_code_fix, adversarial verification verdict
2. **SIGHTINGS-REPORT.json** — structured JSON with all sightings
3. **COVERAGE-METRICS.md** — per-leaf: files total/covered/%, raw sightings, canonical
4. **SPEC-COVERAGE.md** — per-CHECK: VIOLATED/SATISFIED/UNVERIFIABLE/NOT_REACHED (only if spec provided)

Also write **AREA-TREE.json** and **AREA-INVENTORY.md**.

---

### Terminal summary

```
RTL focused-area audit complete.
  Scope:     <scope>
  Area:      <area or "(all)">
  Leaves:    <N> audited
  Files:     <covered>/<security-relevant> (<pct>%)
  Sightings: <raw> raw → <verified> verified → <canonical> canonical
  Severity:  CRITICAL=N HIGH=N MEDIUM=N LOW=N
  Output:    <out>
```

---

## Appendix — Shared prompt fragments

### READING CONTRACT
```
You MUST open every file in your FILE_LIST using the Read tool before reporting any Sightings.
Do not infer from filenames. Do not skip files because they appear uninteresting.
Within each file, analyze every module, task, and function — port declarations, internal state,
always_ff blocks, always_comb blocks, and instantiated submodules.
EXHAUSTIVENESS RULE: Do NOT stop at the first Sighting. Complete all assigned files first.
```

### INVESTIGATION PATTERNS
```
ARITHMETIC SAFETY
- Unsigned subtractions: identify every A - B where B can exceed A.
- Counter widths: N-bit counter fed by M-bit input (M > N) silently truncates.
- Shift amounts from external input — is B bounded?
- Comparison direction: verify < vs <= and signed vs unsigned.

STATE MACHINE COMPLETENESS
- Enumerate every FSM state. For each state, enumerate every input class.
  Is there an explicit error transition for each illegal input?
- Stuck states (reachable only through errors, no clean exit)?

JOB-BOUNDARY ISOLATION
- Which reset signal clears each register? Hard reset only = potential leak across jobs.

OUTPUT AND COMPLETION GATING
- When any error fires, are ALL output-valid and DMA-write signals gated?

DISABLED AND INCOMPLETE CHECKS
- Grep for commented-out error assignments: // ... = 1, /* ... error
- Signals assigned to zero unconditionally near error logic.

DO NOT REPORT: pure functionality/performance issues, testbench-only issues,
generic lint warnings without bypass scenario, side-channel claims without
secret-dependent signal + observation path, best-practice observations without realizable impact.

SEVERITY: CRITICAL=unprivileged/catastrophic/no-preconditions,
HIGH=reachable from production with 1-2 conditions,
MEDIUM=requires elevated access or specific state,
LOW=lab conditions/multiple hard preconditions/narrow impact
```

### FILE_ACKNOWLEDGMENT
```
===COVERAGE-START===
researcher_role: {your role name}
files_read:
  - path: {ABSOLUTE path starting with /}
    modules_analyzed: [module_name_1]
    always_blocks_analyzed: {count}
files_skipped:
  - {absolute path} -- reason: {why}
spec_checks_verified:   [CHECK-001, CHECK-007, ...]
spec_checks_violated:   [CHECK-003, ...]
spec_checks_unverified: [CHECK-005, ...]
===COVERAGE-END===
```

### OUTPUT_FORMAT
```
Every issue is a SIGHTING. Never use: vulnerability, bug, exploit, defect, flaw.

===SIGHTING-START===
file: {primary source file — absolute path}
line: {primary line number}
category: {e.g. "unsigned underflow (CWE-191)"}
severity: CRITICAL|HIGH|MEDIUM|LOW
confidence: {0.0-1.0}
title: {under 12 words}
attack_surface: {1-3 sentences}
impact: {2-3 sentences}
code_evidence: {verbatim ~20 lines, exact indentation}
analysis: {root cause, violated invariant, exact failure condition}
exploit_steps: {numbered concrete steps}
preconditions:
  - {one per line}
possible_code_fix: {RTL pseudocode for every file and location}
===SIGHTING-END===

If nothing found: "No Sightings found in assigned files."
Never emit empty Sighting blocks.
```

---

## Example invocations

```
/rtl-sec-focused-area /path/to/rtl/iaa_ttl_main area="zstd decompression" out=/tmp/audit-run1
/rtl-sec-focused-area /path/to/rtl area="huffman decoding" spec=/path/to/spec.pdf
/rtl-sec-focused-area /path/to/rtl discover area="crypto key lifecycle"
```
