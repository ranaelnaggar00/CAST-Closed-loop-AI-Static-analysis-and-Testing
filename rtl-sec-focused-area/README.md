# rtl-sec-focused-area

A Claude Code skill for deep, focused-area RTL security auditing. Given an RTL directory and a plain-English focus area, it autonomously discovers the relevant design domain, builds per-module threat models, deploys six specialist researchers per pipeline stage, adversarially verifies every finding, and produces a structured report — all within a single Claude conversation using parallel Agent calls.

---

## Invocation

```
/rtl-sec-focused-area <scope> [area=<plain-english-area>] [out=<output-dir>] [spec=<path-to-pdf>]
```

| Argument | Required | Description |
|---|---|---|
| `scope` | Yes | Absolute path to RTL directory |
| `area` | No | Plain-English focus area, e.g. `"zstd decompression"` |
| `out` | No | Output directory (default: `<scope>/../focused-area-out`) |
| `spec` | No | Path to microarchitecture / protocol spec PDF |
| `discover` | No | Flag: print area tree and selected leaves, then stop |

---

## Skill Structure

The skill executes ten phases in sequence. Phases within each batch run their sub-agents concurrently.

```
Phase 0      Manifest
Phase 0.4    Spec Decomposition          (only if spec= provided)
Phase 0.4b   Synthetic Conformance Checks (only if spec= NOT provided)
Phase 0.5    Deep Semantic Area Discovery
Phase 0.6    Area Filter + Integration Anchor
Phase 0.7    Per-Leaf Threat Models
Phase 2      Parallel Researchers (6 roles × N leaves)
Phase 3      Coverage Gate
Phase 4      Adversarial Verification
Phase 5      Dedup
             Report Generation
```

### Phase 0 — Manifest

Enumerates all `.sv`, `.svh`, `.vh`, `.v` files under `scope`. Filters out RAM macros, technology cells, and testbenches. Produces `secFiles[]` — the security-relevant file list.

### Phase 0.4 — Spec Decomposition *(spec= provided)*

A `SpecExtractor` agent reads the full spec PDF and extracts every security-relevant requirement as a structured `CHECK` block (id, section, category, severity hint, keywords). A parallel fleet of `RtlMapper` agents then scores every RTL file against each CHECK by keyword overlap. The resulting `specToRtl{}` map injects spec traceability into every downstream phase.

### Phase 0.4b — Synthetic Conformance Checks *(no spec provided)*

When no spec is supplied, a `ConformanceSynthesizer` agent reads up to 60 trust-boundary files and generates protocol-agnostic `SYNTH-NNN` checks covering four structural patterns that commonly hide real issues regardless of the underlying protocol:

- **Field extraction without bounds** — an attacker-controlled field is stored without a maximum-value check
- **Reserved-value handling** — an enum type field has no explicit error path for undefined values
- **Consumed-bytes accounting gaps** — a byte-offset counter omits one or more contributing struct fields
- **Error-code constants** — named error parameters flagged for cross-check against any documented table

These synthetic checks are injected into researcher prompts identically to real spec CHECKs, labelled `(synthetic)` to distinguish their inferred origin.

### Phase 0.5 — Deep Semantic Area Discovery

All `secFiles` are split into batches of 8 and read in parallel. Each agent answers seven structured questions per module: pipeline role, data flows, FSM state enumeration, key invariants, trust-boundary classification, hard-reset-only registers, and security observations. The resulting `FILE_META` records are fed to an `AreaTreeBuilder` agent that constructs a three-level hierarchy (L1 domain / L2 subdomain / L3 pipeline stage), placing every file in exactly one leaf with 3–20 files per leaf.

### Phase 0.6 — Area Filter + Integration Anchor

Three passes select `targetLeaves` from the full tree:
1. Path token match against the `area` argument
2. Description and module-name text match
3. LLM inclusion/exclusion vote for undecided leaves

If `targetLeaves` exceeds 20 entries the set is sorted by `trust_boundary_files` count (highest risk first) and split into batches of 20. Each batch runs the full Phase 0.7 → Phase 5 pipeline independently; sightings are accumulated across batches before report generation.

**Integration Anchor:** After leaf selection, a synthetic `_Integration/Parameters` leaf is always appended (exempt from the batch cap) containing every `*params*`, `*defines*`, `*config*`, `*_pkg*` file in scope plus the top-level integration file that instantiates the most target-leaf modules. This ensures error-code constants and cross-module wiring are never excluded by area filtering.

### Phase 0.7 — Per-Leaf Threat Models

One agent per leaf (all concurrent) builds a structured threat model: assets, adversary capabilities, trust boundaries, invariant violations, spec-check verdicts, and a priority-ranked list of concerns. Threat models are written to `<out>/threat_models/` and used to focus Phase 2 researchers.

### Phase 2 — Parallel Researchers

For every leaf, six specialist agents run concurrently, each reading every file in the leaf against a distinct security lens:

| Role | Focus |
|---|---|
| **ArithmeticSafety** | Width truncation, unsigned underflows, shift-amount bounds, index range checks |
| **FSMCompleteness** | Every state × every input class; missing error transitions; stuck states; case-without-default |
| **JobBoundary** | Registers cleared only by hard reset; state persisting across job/descriptor boundaries |
| **OutputGating** | Error-to-output-valid signal traces; commented-out error assignments; post-error data emission |
| **IntegrationThreat** | Cross-module signal integrity; width mismatches at boundaries; floating error outputs |
| **Conventional** | Sequential top-to-bottom read; constants, commented code, TODOs, opaque arithmetic |

Every researcher must read every file before reporting (READING CONTRACT) and emit a structured COVERAGE block listing files read, modules analysed, and spec checks verified/violated.

### Phase 3 — Coverage Gate

Per-leaf diff of `leaf.files` against researcher-reported `coveredFiles`. Any uncovered files trigger gap-fill agents (batches of 8, up to two rounds) that read and report on the missed files.

### Phase 4 — Adversarial Verification

Every raw sighting (capped at 100 per batch) receives a dedicated verifier agent that must: read the file at the reported line, trace who drives the logic, hunt for lifecycle gates / fuse bits / reset guards / upstream checks, and determine whether each found protection can be bypassed. Only `TRUE_POSITIVE` verdicts survive.

### Phase 5 — Dedup

Structural pre-filter removes same-file + same-category + line-±10 duplicates. A dedup agent then marks sightings sharing the same root cause, file/line within 30, or a downstream-consequence relationship. Survivors are sorted CRITICAL → HIGH → MEDIUM → LOW then by confidence.

### Report Generation

Five output files written in parallel:

| File | Contents |
|---|---|
| `SIGHTINGS-REPORT.md` | Full human-readable report: metadata, severity table, per-leaf coverage, one section per sighting with code evidence, exploit steps, and fix |
| `SIGHTINGS-REPORT.json` | Machine-readable structured sightings |
| `COVERAGE-METRICS.md` | Per-leaf file coverage %, raw/canonical sighting counts, researcher role breakdown |
| `AREA-TREE.json` | Full hierarchical area tree |
| `AREA-INVENTORY.md` | Per-leaf file lists, trust-boundary classification, canonical sighting index |

---

## How the Design Ensures Coverage and Depth

**Coverage** is addressed at three levels:

1. *File coverage* — the READING CONTRACT forces every agent to open every assigned file with the `Read` tool before reporting anything. The Coverage Gate (Phase 3) diffs assigned files against reported files and re-dispatches any gaps, providing a hard guarantee that no file is silently skipped.

2. *Semantic coverage* — six orthogonal researcher roles mean each file is analysed from six independent perspectives in the same pass. A sighting missed by ArithmeticSafety (because it looks like a logic issue) is picked up by FSMCompleteness or Conventional. Role diversity removes the blind spots inherent in any single analytical lens.

3. *Integration coverage* — the Integration Anchor step ensures top-level wiring files and parameter-definition headers are always in scope, regardless of how the area filter classified the target domain.

**Depth** is enforced by:

- *Threat-model priming* — each researcher receives the leaf's threat model before reading any file. This focuses attention on the highest-risk invariants and attacker capabilities rather than producing generic observations.
- *Spec / synthetic check injection* — whether a real spec or synthesised conformance checks are available, researchers are given explicit "must-be-true" statements to verify or refute, raising the bar above opportunistic pattern matching.
- *Adversarial verification* — every surviving sighting is re-examined by a sceptical verifier that actively searches for protections and bypass conditions. This eliminates plausible-but-wrong findings and forces the evidence bar higher than a single-pass read.

---

## Results on Intel IAA ZSTD Decompressor RTL

The skill was run against the IAA TTL ZSTD June 2023 RTL snapshot (278 total files, 193 security-relevant) with `area="zstd decompression"` and no spec PDF.

### By the numbers

| Metric | Value |
|---|---|
| Security-relevant files | 193 |
| Target leaves audited | 15 |
| Phase 2 agents | 90 (6 roles × 15 leaves) |
| Raw sightings | ~280 |
| Submitted to adversarial verification | 100 |
| TRUE_POSITIVE verdicts | 65 |
| After dedup | **62 canonical** |
| CRITICAL | 12 |
| HIGH | 45 |
| MEDIUM | 5 |
| File coverage | 100% (all 193 files read) |
| Actual cost (Sonnet 4.6) | ~$55 (dominated by output tokens; ~85% of input served from prompt cache) |

### Recall against 72 tracked GitHub issues

The 72 issues represent a ground-truth set of confirmed bugs filed against the same RTL snapshot by a combination of AI-assisted fuzzing, manual review, and simulation campaigns.

| Category | Count | % of 72 |
|---|---|---|
| Directly covered by a canonical sighting | 35 | **48.6%** |
| Partially covered (same mechanism, different manifestation) | 20 | **27.8%** |
| Not covered | 17 | **23.6%** |
| **Total recall (direct + partial)** | **55** | **76.4%** |

### Analysis of misses

Of the 17 uncovered issues, post-hoc investigation found that **10 of 17 are confirmed present in the June 2023 RTL** — meaning they are genuine audit gaps, not issues that were already fixed. The remaining 7 were either already fixed in the snapshot, were cosmetic dead-code observations outside the skill's severity threshold, or were re-confirmed as false positives by direct RTL reading.

The 10 genuine gaps fall into four structural categories:

**No spec provided (4 issues).** Issues that require knowing what a protocol field's legal value range is, or what a consumed-byte counter must include, are invisible to pure RTL reading. Without an authoritative reference, a researcher cannot flag "field X is omitted from counter Y" because the omission is only visible against the protocol definition. Phase 0.4b (synthetic conformance checks) was added to close this gap for the no-spec case.

**Integration files excluded by area filter (2 issues).** Error-code constants and top-level output-gating logic live in integration and parameter files that the area filter correctly deprioritised in favour of higher-trust ZSTD internal leaves. These files were in `secFiles[]` but assigned to a leaf outside the 15-leaf target set. The Integration Anchor step was added to permanently include these files regardless of area filtering.

**Adversarial verifier false negatives (2 issues).** Two sightings involving interacting bugs — where neither bug is exploitable in isolation but the combination is — were marked FALSE_POSITIVE by the verifier. Each bug individually had a plausible non-exploitable explanation; the cross-condition was not checked. This is a known limitation of single-sighting verification; cross-sighting correlation is not currently in scope.

**Researcher missed subtle patterns in fully-covered files (4 issues).** Four issues were in files that were fully read by the correct researcher role, yet the specific pattern went unreported. In each case the researcher found other sightings in the same file — the missed pattern was either structurally similar to a nearby correct finding (masking effect) or required recognising an absent action in an opcode-specific branch rather than a present incorrect one. These represent the irreducible residual of any single-pass analysis.

### Net impact of skill improvements

The two changes added after this run — Phase 0.4b (synthetic conformance checks) and the Integration Anchor — are estimated to close 6 of the 10 genuine gaps. The remaining 4 (verifier false negatives and subtle per-file misses) require either cross-sighting correlation in Phase 4 or a second independent researcher pass, both of which are planned.

---

## Output Directory Structure

```
<out>/
  SIGHTINGS-REPORT.md
  SIGHTINGS-REPORT.json
  COVERAGE-METRICS.md
  AREA-TREE.json
  AREA-INVENTORY.md
  threat_models/
    <Leaf_Name>_THREAT-MODEL.md   (one per target leaf)
```
