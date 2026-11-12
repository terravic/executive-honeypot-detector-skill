# Executive Counterintelligence Risk Diagnostic Report

**Session Reference:** `{session_id}`
**Assessment Timestamp (UTC):** `{generated_at}`
**Risk Prior Profile:** `{risk_profile}`
**OPSEC Redactions Applied:** `{redaction_count}`

---

## 1. Executive Risk Summary

| Metric | Value |
|---|---|
| Primary Classification | **{classification_label}** |
| Classification Confidence | `{confidence_level}` ({coverage_percent}% core CI tier coverage) |
| Composite Threat Index | `{composite_risk_score} / 100.0` |
| Active Indicators Detected | `{present_count} / 32` |
| Disconfirming (Benign) Indicators | `{absent_count} / 32` |

{confidence_warning}

### Executive Posture Assessment
{posture_summary}

---

## 2. Bayesian Threat Matrix Posteriors

| Threat Classification | Posterior Probability | Interpretation |
|---|---|---|
| Tier 1: Benign / Organic Relationship | `{p_benign_pct}%` | Standard interpersonal dynamics; negligible espionage or fraud likelihood |
| Tier 2: Commercial Fraud / Romance Scam | `{p_fraud_pct}%` | Financial opportunism or structured consumer romance fraud |
| Tier 3: Advanced CI Threat / Honeypot | `{p_ci_pct}%` | Targeted human intelligence (HUMINT) or corporate espionage collection |

---

## 3. Diagnostic Dimension Breakdown

| Diagnostic Tier | Coverage Status | Tier Risk Index (0-100) | Active Indicators | Disconfirming Indicators |
|---|---|---|---|---|
{tier_breakdown_rows}

### Unassessed Blind Spots
{blind_spots_section}

---

## 4. Key Indicator Evidence and Attribution

{indicator_evidence_section}

---

## 5. Prescribed Defensive Countermeasures

{countermeasures_section}

---

## 6. Passive Behavioral Verification (Canary Protocol)

{canary_section}

---

## 7. Operational Security and Legal Disclaimer

{legal_disclaimer}
