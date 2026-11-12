# Counterintelligence Honeypot Diagnostic Agent Skill (`executive-honeypot-detector`)

## 1. Overview

The Counterintelligence Honeypot Diagnostic Agent Skill is a modular, harness-agnostic Agent Skill for corporate executives, board members, Chief Security Officers (CSOs), and executive protection teams. It evaluates whether a new romantic relationship exhibits behavioral and operational indicators consistent with:

- **Tier 1: Benign / Organic Relationship** (verifiable background, organic meeting genesis, balanced reciprocity)
- **Tier 2: Commercial Fraud / Romance Scam** (financial opportunism, opaque wealth claims, urgent monetary solicitation without corporate IP targeting)
- **Tier 3: Advanced CI Threat / Honeypot** (targeted approach, shallow cover legend, covert elicitation of corporate secrets, physical device proximity)

### Capabilities and Architecture
Targeted human intelligence (HUMINT) exploitation bypasses technical security perimeters by leveraging interpersonal trust. This skill operationalizes counterintelligence tradecraft into a structured diagnostic workflow:

- **Adaptive Multi-Turn Interview Engine (`scripts/interview_engine.py`)**: Replaces static checklists by tracking coverage across six diagnostic domains and escalating dynamically when high-risk indicators appear.
- **32-Indicator Tradecraft Taxonomy (`assets/indicators_taxonomy.json`)**: Maps narratives and structured observations against 32 weighted counterintelligence and romance-fraud indicators with span-aware negation handling.
- **Damped Bayesian Threat Matrix (`scripts/bayesian_scorer.py`)**: Computes reproducible, normalized posterior probabilities with intra-tier correlation damping and per-indicator log-likelihood attribution.
- **OPSEC Redaction and Ephemeral Sessions (`scripts/sanitizer.py`)**: Redacts emails, telephone numbers, SSNs, card numbers, IP addresses, tokenized URLs, and configured entity names prior to ephemeral storage or reporting, and supports zero-byte overwrite deletion of temporary session files.
- **Non-Escalatory Defensive Protocols (`scripts/report_generator.py`)**: Generates structured JSON and Markdown diagnostic reports, MDM/credential containment steps, privileged CSO escalation guidance, and domain-tailored passive Canary Protocol scripts.

For detailed architectural diagrams, mathematical specifications, and error-handling contracts, see `documents/prd.md`.

---

## 2. Project Structure

All paths are relative to the project root directory:

```text
.
├── LICENSE                                 # Apache License, Version 2.0
├── README.md                               # Setup, CLI usage, and end-user guide
├── SKILL.md                                # Agent skill metadata and orchestration workflow
├── requirements.txt                        # Test and YAML validation dependencies
├── assets/
│   ├── indicators_taxonomy.json            # 32 weighted CI and fraud indicators + priors
│   ├── probes_and_countermeasures.json     # Adaptive probes, dynamic rules, Canary playbooks
│   ├── report_template.md                  # Markdown executive diagnostic report template
│   └── schemas/
│       ├── report_schema.json              # Final diagnostic report JSON schema
│       └── session_schema.json             # Ephemeral session JSON schema
├── documents/
│   └── prd.md                              # Product Requirements Document
├── references/
│   ├── defensive_protocols.md              # Containment, Canary Protocol, and escalation manual
│   ├── interview_playbook.md               # Psychological framing and adaptive pacing rules
│   └── tradecraft_taxonomy.md              # Detailed reference for all 32 indicators
├── scripts/
│   ├── __init__.py                         # Relative path resolution, logging, typed exceptions
│   ├── bayesian_scorer.py                  # Damped multi-hypothesis Bayesian Threat Matrix
│   ├── honeypot_cli.py                     # Unified CLI entrypoint
│   ├── interview_engine.py                 # Adaptive state machine and probe selector
│   ├── report_generator.py                 # Executive Markdown/JSON brief generator
│   ├── sanitizer.py                        # OPSEC redaction, path checks, secure file purge
│   └── taxonomy_engine.py                  # Taxonomy validator and hybrid indicator extractor
└── tests/
    ├── __init__.py                         # Test package marker
    ├── fixtures/
    │   └── synthetic_scenarios.json        # Synthetic multi-turn test scenarios
    ├── test_compliance_audit.py            # Layout, frontmatter, and relative path checks
    ├── test_system_cli.py                  # End-to-end CLI smoke and scenario tests
    ├── test_unit_bayesian.py               # Bayesian normalization and damping unit tests
    ├── test_unit_interview.py              # State machine and probe selection unit tests
    ├── test_unit_report.py                 # Report rendering and Canary tailoring unit tests
    ├── test_unit_sanitizer.py              # Sanitization and secure purge unit tests
    └── test_unit_taxonomy.py               # 32-indicator loading and extraction unit tests
```

---

## 3. Prerequisites

- **Operating System:** Linux, macOS, or Windows with standard terminal access.
- **Python Version:** Python 3.10 or later (`python3 --version`).
- **Runtime Dependencies:** All core modules in `scripts/` use only the Python 3.10+ standard library.
- **Test and Validation Dependencies:** Listed in `requirements.txt` (`PyYAML` and `pytest`).

### Virtual Environment Setup

Run the following commands from the project root directory:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
```

Optional environment variables:
- `HONEYPOT_SKILL_ASSETS_DIR`: Override path to the declarative `assets/` directory (defaults to `./assets`).
- `HONEYPOT_SKILL_LOG_LEVEL`: Set stderr logging verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`; defaults to `WARNING`).

---

## 4. Local Execution

All commands execute locally and offline from the project root directory with zero outbound network calls.

### 4.1 Validate Declarative Assets
Confirm that all 32 indicators, conditional likelihoods, prior profiles, probes, and dynamic rules are consistent:

```bash
python3 scripts/honeypot_cli.py validate-taxonomy
```

Expected output: JSON object with `"status": "ok"` and `"indicator_count": 32`, exiting with code `0`.

### 4.2 Run a Diagnostic Session via CLI

The examples below store temporary session artifacts inside `scratch/`, which is excluded from version tracking by `.gitignore`:

1. **Initialize an ephemeral session** (optionally registering sensitive terms to redact):
   ```bash
   python3 scripts/honeypot_cli.py init-session \
     --risk-profile high_exposure \
     --sensitive-terms "Partner-Placeholder" "Apex Synthetic Corp" \
     --session-file scratch/ephemeral_diag.json
   ```

2. **Analyze executive narrative turns** (with optional structured indicator observations):
   ```bash
   python3 scripts/honeypot_cli.py analyze-turn \
     --session-file scratch/ephemeral_diag.json \
     --narrative "We met unexpectedly at a hotel bar during an overseas aerospace conference in Geneva where my keynote schedule was publicized online." \
     --observations-json '[{"id": "AV-01", "status": "present", "confidence": 0.90}, {"id": "AV-02", "status": "present", "confidence": 0.90}]'
   ```
   Inspect `next_probe.question` and repeat `analyze-turn` until `ready_for_synthesis` returns `true`.

3. **Run standalone Bayesian scoring** directly on structured observations:
   ```bash
   python3 scripts/honeypot_cli.py score \
     --observations-json '[{"id": "AV-01", "status": "present", "confidence": 0.9}, {"id": "LV-02", "status": "present", "confidence": 0.9}, {"id": "IE-01", "status": "present", "confidence": 0.95}, {"id": "TP-02", "status": "present", "confidence": 0.95}]'
   ```

4. **Generate the final executive report and securely purge the ephemeral session file**:
   ```bash
   python3 scripts/honeypot_cli.py generate-report \
     --session-file scratch/ephemeral_diag.json \
     --output-md scratch/diagnostic_report.md \
     --output-json scratch/diagnostic_report.json \
     --purge-session
   ```
   The `--purge-session` flag overwrites `scratch/ephemeral_diag.json` with zero bytes and deletes it immediately after generating the report.

### 4.3 Execute the Automated Test Suite
Run all unit, CLI system, synthetic scenario, and repository integrity tests from the project root directory:

```bash
python3 -m pytest -v tests/
```

The test suite uses synthetic placeholder fixtures in `tests/fixtures/synthetic_scenarios.json` and exits with code `0` when all checks pass.

---

## 5. Non-Technical User Guide (Agent Harness Usage)

This section explains how a non-technical executive or security advisor loads and runs the skill inside any agent harness supporting the standard `SKILL.md` format.

### Step 1: Load the Skill Folder
1. Copy the skill directory (`SKILL.md`, `scripts/`, `assets/`, and `references/`) into your agent harness's configured skills folder.
2. Confirm that local Python 3.10+ execution is permitted by the harness.
3. Open a private chat session. The harness discovers the skill automatically from the metadata header in `SKILL.md`.

### Step 2: Start the Assessment in Plain Language
Describe your situation naturally without typing real partner names, phone numbers, email addresses, or confidential company names.

**Real-World Example A (Business Travel Encounter):**
> "I recently started seeing someone I met while speaking at a biotech symposium abroad. A couple of their questions about our upcoming pipeline felt oddly specific. Can you walk me through a confidential counterintelligence risk diagnostic?"

**Real-World Example B (Online Financial Request):**
> "Someone I connected with online two weeks ago has already talked about long-term commitment and just asked for help covering a sudden customs hold on an inheritance shipment. Can you help me assess whether this looks like espionage, romance fraud, or something benign?"

### Step 3: Answer One Focused Question at a Time
The agent runs `scripts/honeypot_cli.py` behind the scenes and guides the conversation calmly without presenting a long checklist:

- **Turn 1 (Opening Question):** The agent reassures confidentiality and asks how and where you first met, who initiated contact, and what stood out.
- **Adaptive Follow-Ups (Turns 2-5):** Based on your replies, the agent asks targeted follow-up questions across career verifiability, work-related curiosity, relationship pacing, physical access to corporate phones or laptops, and any financial requests. Already-covered topics are skipped automatically.
- **Pause and Resume:** You can pause the conversation at any time or ask for an interim summary before finishing every topic.

### Step 4: Review the Diagnostic Report and Next Steps
When enough dimensions have been covered (or when you ask to wrap up), the agent purges temporary session files and displays a structured report containing:

1. **Executive Risk Summary**: Primary threat tier (`Tier 1: Benign / Organic Relationship`, `Tier 2: Commercial Fraud / Romance Scam`, or `Tier 3: Advanced CI Threat / Honeypot`), confidence level, and composite risk score (0-100).
2. **Bayesian Threat Matrix Posteriors**: Exact probability percentages across all three risk tiers.
3. **Diagnostic Dimension Breakdown**: Table summarizing all six assessment tiers, active signals, reassuring benign signals, and any unassessed blind spots.
4. **Prescribed Defensive Countermeasures**:
   - **Tier 1 (Benign):** Reassurance and standard corporate confidentiality reminders.
   - **Tier 2 (Commercial Fraud):** Immediate financial firewall, asset freeze, and independent identity verification steps.
   - **Tier 3 (Advanced CI Threat):** Calm behavioral continuity (do not confront the partner unilaterally), discreet corporate device inspection and password rotation, and privileged consultation with the Chief Security Officer (CSO) and Corporate General Counsel.
5. **Passive Behavioral Verification (Canary Protocol)**: For elevated CI findings, a harmless, non-damaging script to coordinate with corporate security if ongoing collection is suspected.
6. **Legal and Operational Security Disclaimer**: Clarification that the report models behavioral risk and does not replace certified legal counsel or licensed investigation.

---

## 6. License

This project is licensed under the Apache License, Version 2.0. See the [LICENSE](LICENSE) file in the project root for full terms and conditions.
