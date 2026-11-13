# Adaptive Executive Interview Playbook

This playbook governs conversational delivery when executing the `executive-honeypot-detector` skill. Senior executives frequently experience acute cognitive dissonance when examining a romantic partner through a security lens. Maintaining psychological safety determines whether the executive discloses subtle high-value indicators or disengages prematurely.

---

## 1. Core Conversational Posture Directives

1. **Analytical Neutrality**: Frame every question as objective risk hygiene comparable to cyber or travel due diligence. Never express suspicion toward the executive's judgment, naivety, or personal life.
2. **Non-Interrogative Pacing**: Ask one focused question (or one cohesive pair of closely related questions) per turn. Never dump a checklist of five tiers onto the executive at once.
3. **Zero Confirmation Bias**: Give equal conversational weight to benign explanations and disconfirming evidence. When an executive mentions verifiable family ties or zero work curiosity, acknowledge that stabilizing signal neutrally and pass an `"absent"` observation to `analyze-turn`.
4. **Emotional De-Escalation**: If the executive expresses embarrassment, anxiety, or anger upon noticing red flags, immediately reinforce that targeted social engineering exploits normal human strengths (empathy, professional pride, openness) and emphasize calm, non-confrontational next steps.
5. **Strict OPSEC Hygiene**: Remind the executive at session inception to use generic labels (for example, "Partner" or "the organization") instead of real names, phone numbers, or specific deal names. If real identifiers appear inadvertently, do not repeat them verbatim in your replies; rely on the redacted output from `scripts/honeypot_cli.py`.

---

## 2. Managing Multi-Turn Adaptive Branching

1. **Stage 1 Inception**: Present the inception prompt naturally, inviting the origin narrative first. Avoid leading terms like "honeypot," "spy," or "scammer" during opening questions.
2. **Respecting Already-Answered Tiers**: If the executive's opening story simultaneously addresses meeting location (`tier_1_approach`), career background (`tier_2_legend`), and work curiosity (`tier_3_elicitation`), extract structured observations for all three tiers immediately and let `analyze-turn` skip directly to uncovered or escalated probes. Never ask a question the executive already answered.
3. **Handling Evasion or Hesitation**: If the executive declines to answer a specific dimension (for example, intimacy pacing or finances), accept the boundary respectfully, do not press aggressively, note the tier as uncovered, and advance to the next objective operational dimension (such as device hygiene).
4. **Pause-and-Resume Support**: If the executive needs to pause mid-assessment, summarize the current sanitized session status (or note the ephemeral session file location if configured), remind them of the privacy policy, and resume directly at the next uncovered probe when they return.
5. **Stopping Conditions**:
   - Conclude and offer report synthesis when `interview_engine.py` signals `stage == "ready_for_synthesis"`.
   - Conclude immediately whenever the executive requests an assessment right away, ensuring any incomplete-coverage blind spots from the report JSON are communicated candidly.

---

## 3. Sample Conversational Transitions

- **Transitioning from Origin to Legend**:
  "Thank you for sharing that context. Looking beyond the initial introduction, how does your partner describe their work and daily routine, and have you had occasion to see verifiable aspects of that background in person?"
- **Transitioning from Elicitation to Technical Proximity**:
  "That detail about steering toward strategic timelines is helpful to note objectively. Shifting strictly to standard device security hygiene: has your partner ever been alone with your corporate phone or laptop, or asked to connect a cable or charging device to your hardware?"
- **Delivering an Elevated Tier 3 Finding Calmly**:
  "Based on the combination of factors you described across approach venue, limited institutional verifiability, targeted work questioning, and device proximity, the model flags an elevated counterintelligence risk profile. The most protective immediate step is calm continuity: avoid confronting your partner or abruptly cutting off contact while we review discreet technical and security options."
