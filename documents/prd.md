# Product Requirements Document: Counterintelligence Honeypot Diagnostic Agent Skill

## 1. Document Overview and Strategic Objective

| Document Attribute | Specification |
|---|---|
| Skill Identifier | `executive-honeypot-detector` |
| Document Version | 1.1.0 |
| License | Apache License, Version 2.0 (`LICENSE`) |
| Target Harness | Standard `SKILL.md`-compatible agent harnesses and runtime environments supporting local Python CLI execution |
| Functional Category | Executive Protection, Counterintelligence (CI), Insider Threat Prevention, Behavioral Risk Diagnostics |
| Primary Audience | Corporate Leadership, Senior Executives, Board Members, Chief Security Officers (CSOs), Corporate General Counsel |

### 1.1 Executive Objective
This skill provides a modular, conversational diagnostic capability enabling senior corporate executives and security stakeholders to evaluate whether a new romantic relationship exhibits indicators of targeted human intelligence (HUMINT) exploitation, corporate espionage, commercial romance fraud, or organic benign dynamics. The skill pairs an adaptive, psychologically informed conversational workflow in `SKILL.md` with deterministic Python risk-modeling modules in `scripts/` that evaluate 32 discrete counterintelligence indicators through a calibrated Bayesian Threat Matrix and produce discreet, non-escalatory mitigation protocols.

---

## 2. User Stories and Scope

### 2.1 Target Personas and User Stories

| Persona | Technical Profile | User Story | Acceptance Criterion |
|---|---|---|---|
| Senior Executive / Board Member | Non-technical; experiencing cognitive dissonance between romantic interest and operational caution | As a senior executive who met a new partner during international travel, I want a discreet, non-judgmental assessment so I can evaluate potential espionage risk without alerting my partner or triggering premature panic. | Adaptive interview covers all relevant risk tiers without accusatory phrasing, produces a plain-language threat classification, and provides passive verification steps. |
| Chief Security Officer (CSO) / Threat Analyst | Technical; responsible for insider threat and executive protection triage | As a CSO reviewing an anonymized diagnostic brief, I want transparent Bayesian indicator attributions and log-likelihood drivers so I can prioritize mobile device audits and protective escalation. | Diagnostic report outputs reproducible posterior probabilities across three threat tiers, itemized active/negated indicators, and coverage blind spots. |
| Corporate General Counsel | Legal/compliance; responsible for liability, privilege, and privacy boundaries | As General Counsel, I want strict assurance that the skill retains zero real identity data, performs no offensive surveillance, and carries an explicit legal disclaimer. | All session inputs undergo automated OPSEC redaction, ephemeral session files are overwritten and deleted upon report synthesis, and no external network queries occur. |

### 2.2 Explicit Scope Boundaries

| In-Scope Capabilities | Out-of-Scope Capabilities |
|---|---|
| Multi-turn adaptive counterintelligence diagnostic interviewing | Offensive surveillance, covert tracking, or private investigative field work |
| Hybrid extraction of 32 discrete CI and commercial fraud indicators with negation handling | Active cyber reconnaissance, scraping, or background database lookups |
| Quantitative Bayesian posterior scoring across three threat classifications | Phone interception, live handset malware scanning, or network packet capture |
| Automated OPSEC redaction of emails, phone numbers, and configured sensitive terms | Permanent storage of executive identities, real partner names, or corporate secrets |
| Non-confrontational defensive playbooks and passive Canary Protocol scripts | Certified legal advice, law enforcement reporting automation, or psychological therapy |
| Local CLI and harness-agnostic JSON/Markdown report synthesis | Outbound third-party API integrations or cloud telemetry transmission |

---

## 3. Threat Vector and Psychological Foundations

Clandestine intelligence services and corporate espionage contractors exploit romantic and emotional trust channels to bypass technical security perimeters. The diagnostic logic operationalizes five canonical stages of clandestine exploitation alongside commercial romance-fraud patterns.

### 3.1 Clandestine Exploitation Stages

| Operational Stage | Clandestine Tradecraft Mechanism | Target Vulnerability Exploited | Observable Indicators |
|---|---|---|---|
| Stage 1: Spotting and Targeting | Collection of public itineraries, flight schedules, speaking engagements, and personal vulnerabilities (divorce, professional setbacks, status pressure). | Professional isolation, desire for validation, travel fatigue. | Unprompted introduction at transient business travel venues (international hotel lounges, private clubs, industry symposiums). |
| Stage 2: Engineered Approach | Contact staged to appear coincidental, organic, and driven by serendipitous chemistry. | Illusion of fate, romantic optimism, confirmation bias. | Immediate alignment on obscure hobbies or niche literature; subtle pre-existing familiarity with executive context; weak travel justification. |
| Stage 3: Intimacy Acceleration | Accelerated relationship pacing and fabricated vulnerability disclosures designed to trigger reciprocity. | Reciprocity norm, trust acceleration, weakened emotional boundaries. | Premature declarations of exclusivity; rapid pressure for shared residence or travel; avoidance of executive's established social network. |
| Stage 4: Covert Elicitation | Non-interrogative extraction using flattery, feigned technical ignorance, or provocative inaccuracies. | Professional pride, urge to correct misconceptions, cathartic venting. | Persistent steering toward M&A activity, board governance, reorganizations, proprietary technical roadmaps, or confidential project codes. |
| Stage 5: Compromise and Access | Direct hardware proximity, compromised peripherals, credential observation, or extortion leverage. | Reputational anxiety, lowered physical guard in private quarters. | Unsupervised proximity to corporate smartphones or laptops, USB/charging cable requests, credential inquisitiveness, unattended luggage or gifts. |

---

## 4. Technical Architecture

The skill enforces a separation between conversational orchestration (handled by the host LLM reading `SKILL.md` and `references/*.md`) and deterministic scoring, state control, and OPSEC sanitization (executed locally by `scripts/honeypot_cli.py`).

### 4.1 System Component and Sequence Flow

```text
+-----------------------------------------------------------------------------+
|                         Host Agent Harness Runtime                          |
|                                                                             |
|  [User Narrative] ---> SKILL.md Orchestrator <--- references/*.md           |
|                              |                                              |
|                              | 1. Extracts optional structured observations |
|                              | 2. Invokes CLI via local shell tool          |
+------------------------------+----------------------------------------------+
                               |
                               v
+-----------------------------------------------------------------------------+
|                     scripts/honeypot_cli.py (Unified CLI)                   |
|                                                                             |
|  +-----------------------+     +-----------------------------------------+  |
|  | scripts/sanitizer.py  |---->| scripts/taxonomy_engine.py              |  |
|  | - Redacts PII/emails  |     | - Loads 32 indicators from assets/      |  |
|  | - Scrubs entity terms |     | - Span-aware positive/negation matching |  |
|  | - Enforces path rules |     | - Merges structured LLM observations    |  |
|  +-----------------------+     +--------------------+--------------------+  |
|                                                     |                       |
|                                                     v                       |
|  +-----------------------+     +-----------------------------------------+  |
|  | scripts/              |<----| scripts/bayesian_scorer.py              |  |
|  | interview_engine.py   |     | - Multi-hypothesis log-likelihood update|  |
|  | - Tracks 6 domains    |     | - Intra-tier correlation damping        |  |
|  | - Prevents repeats    |     | - Normalized Tier 1/2/3 posteriors      |  |
|  | - Selects next probe  |     | - Per-indicator attribution ranking     |  |
|  +-----------+-----------+     +-----------------------------------------+  |
|              |                                                              |
|              v                                                              |
|  +-----------------------------------------------------------------------+  |
|  | scripts/report_generator.py                                           |  |
|  | - Renders assets/report_template.md + JSON report                     |  |
|  | - Tailors passive Canary Protocol to inferred elicitation domain      |  |
|  | - Optionally invokes secure_purge_file() on ephemeral session file    |  |
|  +-----------------------------------------------------------------------+  |
+------------------------------+----------------------------------------------+
                               |
                               v
+-----------------------------------------------------------------------------+
|                         Declarative Assets (assets/)                        |
|  - indicators_taxonomy.json (32 weighted CI/Fraud indicators + priors)      |
|  - probes_and_countermeasures.json (Probes, dynamic rules, playbooks)       |
|  - report_template.md (Structured Markdown executive brief template)        |
|  - schemas/session_schema.json & schemas/report_schema.json                 |
+-----------------------------------------------------------------------------+
```

### 4.2 Repository File Inventory

| Path | Responsibility | Implementation Contract |
|---|---|---|
| `LICENSE` | Apache License, Version 2.0 terms | Governing open-source license |
| `SKILL.md` | Agent orchestration, YAML metadata, psychological posture rules, and CLI workflow | Relative path links; progressive disclosure to `references/` |
| `README.md` | Setup, local CLI instructions, directory tree, and non-technical user guide | Relative paths from project root |
| `requirements.txt` | Test and frontmatter validation dependencies (`PyYAML`, `pytest`) | Core `scripts/` use Python 3.10+ standard library only |
| `documents/prd.md` | Architecture, requirements, scoring model, and error handling specifications | Authoritative design reference |
| `scripts/__init__.py` | Project root discovery, environment configuration, and typed exception classes | Honors `HONEYPOT_SKILL_ASSETS_DIR` and `HONEYPOT_SKILL_LOG_LEVEL` |
| `scripts/sanitizer.py` | OPSEC regex scrubbing, custom blocklist masking, safe path enforcement, secure file wiping | Redacts emails, phones, SSNs, cards, IPs, tokenized URLs, and sensitive terms |
| `scripts/taxonomy_engine.py` | Declarative loader, 32-indicator validator, span-aware regex + observation matcher, cross-turn Canary domain resolver | Validates exact count (32), probability bounds `(0, 1)`, and dynamic follow-up triggers |
| `scripts/bayesian_scorer.py` | Quantitative multi-hypothesis Bayesian Threat Matrix with intra-tier damping | Guarantees normalized posteriors summing to `1.0` and deterministic explainability |
| `scripts/interview_engine.py` | Adaptive state-gate engine managing inception, probing, synthesis readiness, and pause/resume | Prevents duplicate probe IDs; escalates high-risk tiers immediately |
| `scripts/report_generator.py` | Executive Markdown and JSON report formatter plus passive Canary script builder | Structured Markdown and JSON output with mandatory legal disclaimer |
| `scripts/honeypot_cli.py` | Unified command-line interface exposing `validate-taxonomy`, `init-session`, `analyze-turn`, `score`, `generate-report`, and `purge-session` | Standard exit codes: `0` success, `1` runtime failure, `2` input validation error |
| `tests/` | Unit tests, end-to-end CLI scenario tests, synthetic fixtures, and repository structural checks | Runs via `python3 -m pytest -v tests/` with exit code `0` |

---

## 5. Functional Requirements

### 5.1 Data Inputs and Validation Rules

| Input Type | Source | Validation Rules |
|---|---|---|
| Executive Narrative Turn | CLI `--narrative` string or `--narrative-file` UTF-8 text | Must be non-empty after whitespace trimming; maximum length 20,000 characters; sanitized immediately before pattern analysis or logging. |
| Structured Observations | Optional `--observations-json` JSON array | Each item must contain valid `id` (present in the 32-indicator catalog), `status` in `{"present", "absent", "unknown"}`, and optional `confidence` float in `(0.0, 1.0]`. |
| Session State | `--session-json` string or `--session-file` path | Must match `assets/schemas/session_schema.json`; required keys `schema_version`, `session_id`, `stage`, `risk_profile`, `indicators`, `asked_probe_ids`, `covered_tiers`. |
| Sensitive Terms List | Optional `--sensitive-terms` strings during `init-session` | Stored only as normalized redaction matchers in ephemeral session state and masked in all stored excerpts and rendered reports. |
| Risk Profile | `--risk-profile` enum: `standard` or `high_exposure` | Determines Bayesian baseline prior probabilities; defaults to `standard`. |

### 5.2 Core Functional Specifications

| Requirement ID | Module | Specification |
|---|---|---|
| `FR-01` | `interview_engine.py` | Dynamically select the next highest-value follow-up probe based on newly triggered indicators and uncovered tiers without repeating previously asked probes. |
| `FR-02` | `taxonomy_engine.py` | Evaluate narratives and structured observations against exactly 32 discrete indicators spanning Approach Vector (6), Legend and Verification (6), Information Elicitation (6), Intimacy Acceleration (5), Technical Proximity (5), and Financial Fraud (4), suppressing positive regex matches whose spans are enclosed within matched negation phrases. |
| `FR-03` | `SKILL.md` / `interview_playbook.md` | Enforce an analytical, non-judgmental, discreet conversational posture that avoids confrontation or interrogation bias. |
| `FR-04` | `bayesian_scorer.py` | Compute normalized posterior probabilities across `tier_1_benign`, `tier_2_commercial_fraud`, and `tier_3_ci_honeypot` with intra-tier correlation damping (`1 / sqrt(m)` log-likelihood exponent for the `m`-th indicator in a single tier). |
| `FR-05` | `report_generator.py` | Generate structured JSON and Markdown diagnostic briefs detailing threat tier classification, Bayesian probabilities, per-tier risk indices, active/negated indicators, unassessed blind spots, and countermeasures. |
| `FR-06` | `report_generator.py` | Supply domain-tailored, non-damaging passive Canary Protocol verification scripts matched to the inferred corporate elicitation domain (`ma_strategy`, `technical_roadmap`, `board_governance`, `procurement_supply_chain`, `general_operations`), preserving earlier explicit domain matches across subsequent turns. |
| `FR-07` | `sanitizer.py` / `honeypot_cli.py` | Redact sensitive tokens prior to state persistence or logging, and support immediate zero-fill deletion of ephemeral session files via `purge-session` or `generate-report --purge-session`. |

### 5.3 Adaptive Interview Engine and Tradecraft Branching

```text
                             [Executive Narrative]
                                       |
                       +---------------+---------------+
                       |                               |
             [Indicator Identified]          [No Indicator Detected]
                       |                               |
        +--------------+--------------+                v
        |                             |        Advance to Next
  [High-Risk CI / Tech]       [Approach / Legend]  Uncovered Tier
        |                             |
        v                             v
Trigger Elicitation &          Trigger Legend &
Device Proximity Probe         Verification Probe
```

| Diagnostic Domain | Assessment Focus | Trigger Condition | Escalated Follow-Up Focus |
|---|---|---|---|
| `tier_1_approach` | Meeting genesis, venue typology, itinerary overlap | High-value transient venue or publicized travel alignment | Public schedule visibility and partner presence justification |
| `tier_2_legend` | Cover career verifiability and social anchor history | Shallow remote cover career or thin digital/corporate history | Verifiable long-term associates, family contact, institutional footprint |
| `tier_3_elicitation` | Non-interrogative extraction of corporate intelligence | Interest in M&A, board politics, or technical roadmaps | Flattery, feigned ignorance, provocative inaccuracies, entity naming |
| `tier_4_intimacy` | Pacing compression and social isolation behaviors | Premature exclusivity, fast cohabitation pressure, isolation attempts | Baseline pacing comparison and advisor/family distancing patterns |
| `tier_5_technical` | Physical device proximity and peripheral introduction | Unmonitored device access, USB charging requests, credential interest | Corporate MDM status, passcodes, unattended luggage or gifts |
| `tier_6_financial` | Romance-fraud differentiation via monetary extraction | Wealth claims paired with liquidity crises, wires, or crypto asks | Financial request specifics and third-party verification gaps |

### 5.4 Dynamic Follow-Up Rules by Pattern Match

| Observed Pattern Sample | Underlying Tradecraft Vector | System Automated Action |
|---|---|---|
| Unexpected meeting at an overseas conference hotel lounge | Targeted spotting in a high-collection transient venue | Queue itinerary publicity (`AV-02`) and venue justification (`AV-06`) probes |
| Independent art logistics / remote opaque consulting career | Shallow, low-verifiability commercial legend | Queue institutional registration (`LV-02`) and long-term associate (`LV-03`) probes |
| Encourages venting on board disputes or technical roadmaps | Exploitation of ego validation and professional catharsis | Queue elicitation tactic probes (`IE-03`, `IE-04`, `IE-06`) |
| Asks to charge phone on corporate laptop or picks up device | Physical data exfiltration or compromised peripheral vector | Queue technical proximity audit (`TP-01`, `TP-03`) and MDM containment guidance |
| Urgent wire transfer, customs crisis, or crypto investment pitch | Commercial romance fraud rather than state espionage | Queue financial firewall screening (`FF-02`, `FF-03`) to separate Tier 2 from Tier 3 |

### 5.5 Threat Classification Framework and Outputs

| Threat Classification | Key Indicators and Posterior Criteria | Risk Interpretation | Prescribed Executive Posture |
|---|---|---|---|
| `tier_1_benign` (Benign / Organic Relationship) | Highest posterior probability with verifiable multi-year history, zero proprietary elicitation, normal pacing, balanced reciprocity | Negligible espionage or fraud probability | Reassure executive; maintain routine executive security hygiene |
| `tier_2_commercial_fraud` (Commercial Fraud / Romance Scam) | Highest posterior driven by opaque wealth claims, rapid affection, urgent financial/crypto/gift requests, minimal corporate IP probing | Financial opportunism or organized consumer fraud | Establish complete financial firewall; freeze asset exposure; conduct independent verification |
| `tier_3_ci_honeypot` (Advanced CI Threat / Honeypot) | Highest posterior driven by cross-tier convergence across transient engineered approach, thin legend, covert elicitation, and device proximity | Probable foreign intelligence asset or corporate espionage operative | Maintain calm behavioral continuity; deploy passive Canary Protocol; audit MDM/credentials; brief CSO and General Counsel under privilege |

Assessment Confidence Rule: When fewer than 3 of the 5 core counterintelligence tiers have been evaluated, the output JSON sets `confidence.insufficient_data = true` and labels the classification as preliminary alongside enumerated blind spots.

---

## 6. Non-Functional Requirements

| Category | Requirement Specification |
|---|---|
| Performance Latency | Every `scripts/honeypot_cli.py` command executes locally in under 200 milliseconds on standard hardware for narratives up to 20,000 characters. |
| Execution Isolation | All Python scripts run entirely offline using the Python 3.10+ standard library with zero external API calls, telemetry, or network sockets. |
| Data Privacy and OPSEC | No real partner names, contact details, or corporate identifiers persist in logs or permanent storage. Session files store only sanitized indicator states and redacted excerpts, and are securely wiped upon `--purge-session`. |
| Synthetic Test Data Hygiene | Automated tests and fixtures (`tests/fixtures/synthetic_scenarios.json`) use exclusively synthetic placeholder records, reserved `.invalid` domains, documentation IP ranges, and fictitious telephone ranges with zero real personal data. |
| Portability | All paths resolve relative to the skill root or configurable environment variables (`HONEYPOT_SKILL_ASSETS_DIR`, `HONEYPOT_SKILL_LOG_LEVEL`). |
| Extensibility | Adding or recalibrating indicators, likelihoods, probes, or Canary templates requires editing only declarative JSON files in `assets/` followed by `validate-taxonomy`. |

---

## 7. Error Handling and Edge Cases Matrix

| Failure Condition or Edge Case | Detection Point | System Behavior | CLI Exit Code |
|---|---|---|---|
| Empty, whitespace-only, or oversized (>20 KB) narrative | `sanitizer.validate_narrative` | Rejects turn with explicit JSON error object; leaves session state unmodified | `2` |
| Corrupted or non-JSON `--session-file` or `--session-json` | `interview_engine.load_session_*` | Fails safely with structured `SessionError` message; never overwrites existing file | `2` |
| Missing or schema-invalid `assets/*.json` file | `taxonomy_engine.load_and_validate_assets` | Halts execution with descriptive `TaxonomyError` identifying missing file or invalid key | `1` |
| Invalid indicator ID or out-of-range confidence (`<=0` or `>1`) in `--observations-json` | `taxonomy_engine.validate_structured_observations` | Rejects payload with `ValidationError` listing the offending field and allowed bounds | `2` |
| Sensitive tokens detected in narrative (email, phone, SSN, card, IP, tokenized URL, configured term) | `sanitizer.sanitize_text` | Deterministically replaces sensitive tokens with `[REDACTED_*]`, increments `redaction_count`, logs count only, and continues safely | `0` |
| Positive regex phrase enclosed in a negation phrase (e.g., `"never asked for money"`) | `taxonomy_engine._has_unnegated_positive_match` | Suppresses enclosed positive match and evaluates indicator cleanly as `absent` | `0` |
| Conflicting unnegated signals across or within turns | `taxonomy_engine.extract_indicators` | Explicit structured observations override regex heuristics; flags `conflict_flagged = true` for analyst visibility | `0` |
| Zero indicators matched across a narrative turn | `interview_engine.process_turn` | Marks preceding probe tier as covered and advances cleanly to the next uncovered baseline probe without looping | `0` |
| Early report generation with fewer than 3 tiers assessed | `bayesian_scorer` / `report_generator` | Generates report normally with `insufficient_data: true`, `confidence.level = "low"`, and explicit blind-spot warnings | `0` |
| Path traversal (`..`) or directory passed to `--session-file` or `--output-*` | `sanitizer.validate_safe_path` | Rejects unsafe path with `ValidationError`; writes nothing to disk | `2` |
| `purge-session` called on an already deleted or missing path | `sanitizer.secure_purge_file` | Returns structured `SessionError` indicating file not found without an unhandled traceback | `2` |
