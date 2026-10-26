# /human-writer

Rewrite a passage of text to remove the statistical signatures of AI-generated writing identified by StoryScope (arXiv 2604.03136), while preserving the original meaning, argument, and voice.

---

## When to invoke

The user pastes or points at a block of text — fiction, essays, reports, anything — and asks for it to sound less AI-generated, more human, less polished, or more like a real writer wrote it.

---

## What to do

Work through the text in two passes.

### Pass 1 — Diagnose

Before rewriting, silently scan the input for the signals below. Note which are present. Do not list them to the user unless they ask; just use the diagnosis to decide what to change.

### Pass 2 — Rewrite

Apply only the fixes that are actually needed. Do not add complexity for its own sake. Do not change the core meaning, the argument, or any facts. If the input is already doing something well (e.g. it already has an ambiguous ending), leave it alone.

---

## The 24 signals to check and fix

### Theme & meaning

**S1 — Thematic over-explanation**
The narrator states the moral explicitly ("this story is about…", "perhaps that is the nature of…").
Fix: Cut the statement. Let the events carry it. If the moral must appear, put it in a character's mouth as an incomplete thought, not as narrator verdict.

**S2 — Narratorial thematic commentary**
The narrator steps back from the scene to philosophise.
Fix: Remove or collapse into a character's internal voice. Make it contingent and uncertain ("She wondered if—" not "This is the nature of—").

**S3 — Philosophical dialogue**
Characters voice the theme as a debate.
Fix: Break the abstraction into something specific and concrete. Replace "Do you think grief ever truly leaves us?" with a line that does the same work through a particular image or memory.

---

### Plot & structure

**S4 — No subplots / single throughline**
One character, one problem, clean resolution.
Fix: In fiction: introduce a second pressure, even briefly — a side character with a competing need, a subplot that brushes the main story without resolving. In non-fiction: acknowledge a counter-argument or a complication that isn't fully resolved.

**S5 — Tight causal chain**
Every sentence leads neatly to the next.
Fix: Break one link. Add a beat that comes from somewhere unexpected, a consequence that arrives late, or an effect without an obvious cause visible yet.

**S6 — Protagonist-driven resolution**
The ending is the protagonist deciding or realising something.
Fix: Mix in external fate, luck, or another person's action. Or leave the resolution incomplete — the protagonist acts, but whether it worked is unconfirmed.

**S7 — Internal/acceptance resolution**
The character makes peace with the situation.
Fix: Let something remain unresolved or ungained. Acceptance and a remaining wound can coexist. Don't tie the knot.

**S8 — Flat event escalation**
All moments carry equal narrative weight.
Fix: Vary intensity deliberately. Drop one beat to near-silence before the thing that matters. Let one event land harder than the prose has prepared you for.

---

### Time & chronology

**S9 — Strict linear chronology**
Story runs A → B → C with no disruption.
Fix: Displace one moment in time. Open later, then circle back. Or insert a memory that arrives mid-scene without announcement.

**S10 — No delayed disclosure**
Information arrives in the order it was generated.
Fix: Withhold one piece of context. Let the reader be briefly disoriented. Deliver it a paragraph or page later than feels natural.

**S11 — Shallow post-twist recontextualisation**
A surprise is stated but the earlier scenes weren't built to reward re-reading.
Fix: Plant one small detail early that the ending casts in a different light. It doesn't need to be a twist — just one line that means something different on a second read.

---

### Emotion & character

**S12 — All embodied emotion, no direct labels**
Every emotion is conveyed through physical sensation or metaphor. No one is just *sad* or *furious*.
Fix: Use at least one direct label, flat and unadorned. "She was furious." Simple naming can hit harder than any metaphor.

**S13 — Heavy olfactory detail**
Smell appears as the default emotional anchor.
Fix: If smell is present, ask whether it's earning its place. If it's there because it *feels literary*, cut it or replace with something more precise to the scene.

**S14 — Morally unambiguous protagonist**
The main character is sympathetic, learns, is forgiven.
Fix: Give them one motivation or action that isn't rehabilitated by the end. Let them want something slightly shameful. Let them be right and wrong at the same time.

**S15 — External character introduction**
Characters arrive as physical descriptions.
Fix: Introduce through action, through another character's reaction, or through a line of dialogue. Let the reader infer the body rather than receiving a catalogue.

---

### Setting

**S16 — Setting mirrors inner state**
Storm during crisis. Sunshine at the resolution.
Fix: Introduce one moment of counter-emotional setting. Let it be bright outside when she gets the bad news. Let the mundane persist despite the catastrophe.

**S17 — Uniformly bleak or uniformly comfortable atmosphere**
The setting's emotional register never changes.
Fix: Break it once. Even a single incongruous detail — something funny, something beautiful in an ugly moment — signals a real world rather than a painted backdrop.

---

### Reader & narrator relationship

**S18 — No fourth-wall acknowledgement**
The text never admits it is a text.
Fix: In fiction, one moment of direct reader address can suffice ("You know this feeling") — use sparingly. In non-fiction, acknowledge the writer's position or uncertainty once ("I'm not sure this holds, but—").

**S19 — No direct reader address**
The text never says "you."
Fix: Use it once, at a moment of genuine intimacy or implication. Not as a tic — as a choice.

---

### Intertextuality

**S20 — Vague allusions only**
References to literary tradition without names.
Fix: If a reference is present, name the thing. "Like all great tragedies" → "Like Raskolnikov." Or drop the allusion entirely if it's just decoration.

**S21 — No mix of explicit and implicit echoes**
The text either names everything or names nothing.
Fix: Let one reference be named and one be implied. The contrast signals range.

---

### Voice & diversity

**S22 — Predictable safety across all dimensions simultaneously**
The text is linear AND simple AND tidy AND embodied AND setting-mirrors-emotion — the co-occurrence is the tell, not any single feature.
Fix: This is the meta-fix. After correcting individual signals, read the full passage again. If it still feels coordinated and safe, break one more thing — add one rough edge, one unresolved beat, one sentence that doesn't quite fit the tone of the rest. Real writing has friction.

**S23 — Rare locations / constrained world**
The narrative stays in one or two spaces.
Fix: In fiction, let one scene happen somewhere unexpected or incongruous. In non-fiction, bring in one example from outside the obvious domain.

**S24 — Low narrative diversity / everything resolves**
No loose threads, no subplots abandoned, no questions left open.
Fix: End with at least one thing unaddressed. Not a cliffhanger — just an acknowledgement that not everything fits.

---

## What not to do

- Do not add complexity that changes the meaning.
- Do not make the text worse to make it seem "more human." Roughness should come from specificity, not sloppiness.
- Do not apply every fix to every text. Diagnose first; fix what's actually present.
- Do not change facts, arguments, or the user's own named examples.
- Do not over-correct into affected quirkiness. The goal is less predictable, not deliberately odd.
- Do not mention StoryScope, arXiv, or AI detection in the output.

---

## Output format

Return only the rewritten text — no preamble, no explanation, no list of changes made — unless the user explicitly asks what was changed.

If the user asks what was changed, provide a brief bullet list of the signals found and what was done about each.
