# Counterintelligence and Romance-Fraud Tradecraft Taxonomy Reference

This reference documents all 32 discrete diagnostic indicators cataloged in `assets/indicators_taxonomy.json`. Host agents use this guide to map subtle conversational admissions into structured `--observations-json` entries alongside the deterministic pattern matcher.

---

## 1. Cross-Hypothesis Discrimination Logic

A critical analytical objective is avoiding false conflation between three distinct phenomena:

1. **Tier 1: Benign / Organic Relationship**: Verifiable multi-year institutional footprint, organic introduction via trusted social or local anchors, normal relationship pacing, and zero proprietary corporate elicitation or financial pressure.
2. **Tier 2: Commercial Fraud / Romance Scam**: Driven by financial extraction (`FF-01` through `FF-04`), fabricated crises, opaque wealth claims, and rapid emotional intimacy (`IA-01`, `IA-03`, `IA-05`), typically with negligible interest in corporate governance, technical IP, or physical corporate hardware (`IE-*`, `TP-*` remain absent).
3. **Tier 3: Advanced CI Threat / Honeypot**: Driven by cross-tier convergence across targeted approach (`AV-01` through `AV-06`), low-verifiability cover legends (`LV-01` through `LV-06`), non-interrogative corporate elicitation (`IE-01` through `IE-06`), and physical/technical device proximity (`TP-01` through `TP-05`).

Always submit **absent** observations when the executive explicitly provides strong disconfirming evidence (for example, meeting verifiable lifelong family members or confirming strict zero physical access to corporate devices). Absent observations materially shift the Bayesian Threat Matrix toward `tier_1_benign` or separate fraud from espionage.

---

## 2. Complete 32-Indicator Reference Catalog

### Tier 1: Approach Vector (`tier_1_approach`)

| ID | Indicator | Hostile Tradecraft Signal | Benign Discriminator |
|---|---|---|---|
| `AV-01` | High-Value Transient Venue Contact | First contact at an international hotel lounge, overseas summit, or private transit club during business travel. | Introduction at a local community group, alumni association, or through a trusted mutual friend. |
| `AV-02` | Publicized Itinerary Overlap | Executive speaking schedule, city, or hotel venue was publicly posted prior to contact. | Unannounced private trip or last-minute itinerary change unknown publicly. |
| `AV-03` | Engineered Serendipity and Niche Alignment | Immediate uncanny alignment on obscure hobbies, rare books, or specialized personal interests. | Ordinary small talk or gradual discovery of common everyday interests. |
| `AV-04` | Pre-Existing Familiarity with Executive Context | Subtle prior awareness of executive's career history, recent divorce, or corporate transition before disclosure. | Genuine lack of prior knowledge regarding executive title or industry niche. |
| `AV-05` | Unprompted Partner-Initiated Contact | Partner initiated conversation or outreach unprompted using a smooth pretext. | Executive initiated contact or trusted mutual peer made formal introduction. |
| `AV-06` | Implausible Venue Presence Justification | Partner lacked a verifiable registration, employer anchor, or logical reason for attending the venue. | Verifiable conference badge, local residence, or established corporate sponsor. |

### Tier 2: Legend and Verification (`tier_2_legend`)

| ID | Indicator | Hostile Tradecraft Signal | Benign Discriminator |
|---|---|---|---|
| `LV-01` | Shallow Low-Verifiability Cover Career | Claims high-mobility opaque roles (international art logistics, private client advisory, import/export, family office). | Verifiable employment at an established public firm, university, hospital, or registered practice. |
| `LV-02` | Zero Verifiable Institutional Footprint | Claimed firm or consultancy has no physical office, corporate registry filing, or institutional record. | Confirmable office location, corporate directory listing, and multi-year public record. |
| `LV-03` | Absence of Verifiable Long-Term Associates or Family | Executive has met zero childhood friends, former coworkers, or family members despite ongoing relationship. | In-person introductions to verifiable relatives, college peers, or long-time colleagues. |
| `LV-04` | Thin or Freshly Fabricated Digital History | Online professional or social history is newly created, barren, or anomalous for claimed seniority. | Multi-year organic digital record matching biographical timeline. |
| `LV-05` | Inconsistent Biographical Timeline Details | Shifting dates, residences, graduation years, or linguistic claims that fail basic cross-checking. | Chronologically consistent life history across separate conversations. |
| `LV-06` | Reluctance to Meet Executive's Social Circle | Repeated excuses avoiding dinners with executive's trusted peers, adult children, or close colleagues. | Natural willingness to integrate into ordinary social gatherings. |

### Tier 3: Information Elicitation (`tier_3_elicitation`)

| ID | Indicator | Hostile Tradecraft Signal | Benign Discriminator |
|---|---|---|---|
| `IE-01` | Steering Toward M&A, Governance, or Reorganizations | Persistent redirection of personal time toward unannounced deals, board disputes, or executive restructuring. | Casual polite work interest that moves naturally back to personal topics. |
| `IE-02` | Technical Roadmap or Proprietary IP Probing | Focused questioning on confidential product architectures, R&D timelines, defense contracts, or clinical trials. | High-level layperson curiosity without follow-up probing on sensitive specifics. |
| `IE-03` | Flattery and Cathartic Venting Exploitation | Strategic admiration encouraging executive to decompress by venting workplace grievances and leadership conflicts. | Empathetic listening that does not steer toward sensitive operational particulars. |
| `IE-04` | Feigned Ignorance to Prompt Detailed Explanations | Pretends technical naivety to draw out step-by-step proprietary explanations. | Ordinary clarifying questions without persistent drilling into restricted mechanisms. |
| `IE-05` | Provocative or Inaccurate Statements Triggering Correction | Drops subtly wrong assertions about executive's firm or competitors to trigger corrective disclosure. | Absence of leading or contrarian baiting around confidential corporate claims. |
| `IE-06` | Specific Entity, Project Code, or Personnel Queries | Presses for exact project codenames, target company valuations, vendor names, or dissenting board members. | Keeps discussions strictly abstract and respects non-disclosure boundaries. |

### Tier 4: Intimacy Acceleration (`tier_4_intimacy`)

| ID | Indicator | Hostile Tradecraft Signal | Benign Discriminator |
|---|---|---|---|
| `IA-01` | Premature Declarations of Love or Exclusivity | Rapid love-bombing, soulmate rhetoric, or exclusivity demands within days or early weeks. | Measured relationship progression unfolding across several months. |
| `IA-02` | Pressure for Rapid Cohabitation or Private Travel | Early push to share residences, hold apartment keys, or accompany isolated international trips. | Respect for independent living spaces and gradual shared travel planning. |
| `IA-03` | Artificial Reciprocal Vulnerability Disclosure | Theatrical early trauma or secret sharing designed to obligate reciprocal executive candor. | Balanced, proportional mutual openness developing gradually over time. |
| `IA-04` | Isolation from Trusted Advisors or Family | Attempts to create distrust toward executive's family, friends, legal counsel, or security detail. | Supportive attitude toward executive's existing advisory and family network. |
| `IA-05` | Emotional Leverage or Guilt-Inducing Urgency | Withdrawal, ultimatums, or implied reputational embarrassment used to override executive hesitation. | Respectful acceptance of personal and professional boundaries. |

### Tier 5: Technical Proximity (`tier_5_technical`)

| ID | Indicator | Hostile Tradecraft Signal | Benign Discriminator |
|---|---|---|---|
| `TP-01` | Unmonitored Physical Access to Corporate Devices | Handled or remained unsupervised around executive's corporate smartphone, laptop, or briefcase. | Corporate endpoints remained continuously secured, locked, and supervised. |
| `TP-02` | Peripheral, USB, or Charging Cable Connection Requests | Requested to charge phone on corporate laptop, insert USB media, or gifted electronic cables/hubs. | Zero requests to connect external hardware or transfer media via corporate devices. |
| `TP-03` | Inquisitiveness Toward Passcodes, MFA, or Credentials | Shoulder-surfed PINs/passwords or queried corporate Wi-Fi credentials, VPN access, or hardware tokens. | Zero interest in passcodes, badges, or authentication mechanisms. |
| `TP-04` | Unattended Electronic Gifts or Luggage in Private Quarters | Asked to store luggage or introduced smart speakers, digital frames, or desk electronics into private spaces. | Ordinary non-electronic gifts and normal personal belongings hygiene. |
| `TP-05` | Workspace Access or Photography in Secure Areas | Sought private after-hours office tours or photographed desks, whiteboards, or displays. | Never accessed restricted office floors or photographed work environments. |

### Tier 6: Commercial and Financial Exploitation (`tier_6_financial`)

| ID | Indicator | Hostile Tradecraft Signal | Benign Discriminator |
|---|---|---|---|
| `FF-01` | Unverifiable Private Wealth or Inheritance Claims | Claims opaque offshore trusts, inherited holdings, or luxury deals that clash with sudden cash shortages. | Transparent, ordinary lifestyle consistent with verifiable earnings. |
| `FF-02` | Fabricated Urgent Liquidity, Medical, or Customs Crisis | Sudden blocked account, customs release fee, or stranded travel emergency demanding rapid cash. | Normal independent financial self-sufficiency without engineered emergencies. |
| `FF-03` | Requests for Wire Transfers, Loans, or Crypto Investments | Direct solicitation for wires, bridge loans, escrow funds, or third-party cryptocurrency trading schemes. | Zero monetary borrowing or investment pitches. |
| `FF-04` | Demands for High-Value Liquid Gifts or Account Access | Escalating expectations for luxury watches, jewelry, co-signed leases, or joint credit/bank access. | Balanced expense sharing and absence of financial entanglement pressure. |

---

## 3. Structured Observation Extraction Guidelines

When calling `scripts/honeypot_cli.py analyze-turn`, pass `--observations-json` whenever the executive's phrasing expresses a semantic indicator that may not match exact literal keywords:

```json
[
  {
    "id": "LV-02",
    "status": "absent",
    "confidence": 0.90,
    "evidence": "Verified 12-year tenure at regional hospital public directory."
  },
  {
    "id": "IE-04",
    "status": "present",
    "confidence": 0.85,
    "evidence": "Repeatedly asks executive to simplify proprietary chip fabrication yield hurdles."
  }
]
```

Confidence calibration guidance:
- `0.90 - 1.00`: Direct, unambiguous first-hand confirmation or explicit refutation by the executive.
- `0.65 - 0.85`: Strong circumstantial behavioral pattern clearly described in the narrative.
- `0.40 - 0.60`: Ambiguous or partial impression requiring follow-up confirmation.
