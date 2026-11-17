# Presenter notes

Suggested talking points for the Group 34 *AI Red-Teaming* deck (18 slides).
The deck's own speaker notes are empty, so this is a starting point to edit.
Timings are suggestions except the demo, which the deck sets at 5-7 minutes.

## Before you start
- Open two terminals in the repo root. Run `python demo/assistant.py` once to
  confirm it works.
- Keep a saved copy as a fallback: `python demo/assistant.py --no-color > demo_output.txt`
- Optional: `ollama serve` running in one window if you will show the local model.

## Slide by slide

| # | Slide | Key message | Say |
|---|---|---|---|
| 1 | Title | Authorized, controlled demo | Introduce the team. Everything shown is fictional and authorized. |
| 2 | Definition | Test the system, not just the model | Input, system, evidence. The goal is to find consequential failure paths before real attackers do. |
| 3 | Scope | New trust boundaries | A model can behave well while the app around it exposes data or grants too much agency. |
| 4 | Method | Traditional testing meets AI behaviour | Keep the security fundamentals (authorization, evidence, reproducibility, retest). Add semantic, multi-turn, repeat-across-versions testing. |
| 5 | Five classes | A starting matrix, not a taxonomy | Injection, jailbreak, leakage, poisoning, excessive agency. They overlap; they are test lenses. *(Probes in `demo/scan.py` follow these five.)* |
| 6 | Lifecycle | Scope, model, plan, record, fix, retest | Every test ends with evidence that a control works. *(`scan.py --output` and `--compare` are this loop.)* |
| 7 | Prompt injection | Instructions can arrive through data | Direct vs. indirect. The test is source labelling and access control, not prompt wording. |
| 8 | Jailbreaks | Evaluate outcomes, not clever wording | Record refusal quality, leakage, consistency, and whether tools were called. |
| 9 | Leakage | A prompt rule is not an access control | Authorize before data reaches generation. Minimize context, authorize every retrieval, redact outputs. |
| 10 | Agents | The model proposes; code authorizes | Each tool is its own trust boundary. Reads: allowlist. Writes: approval gate. Calls: scoped token. Log it. |
| 11 | Research | The data path matters | Greshake et al. 2023: documented demonstration, used to build hypotheses, not to say every product is vulnerable. |
| 12 | Demo intro | What it is and is not | Not a real LLM. Deterministic, offline, fictional data. Reproducible and safe for a classroom. |
| 13 | Vulnerable | Watch it fail | Run the vulnerable mode. Three `LEAK` lines are the findings. |
| 14 | Mitigated | Fix the path, then retest | Same cases, secure mode. Deny, untrusted/ignore. Retest equals evidence. |
| 15 | Tooling | Coverage, not authority | PyRIT, garak, OWASP, ATLAS help create and organize tests; humans decide scope and acceptable risk. |
| 16 | Reporting | Score the impact, not the cleverness | A finding must be reproducible and prioritizable. Never put real secrets in a report. |
| 17 | Defenses and ethics | Layer controls, keep scope bounded | No single prompt, filter, or model update is a complete boundary. |
| 18 | Close | Three takeaways | Boundaries define impact; authorization belongs in code; a finding is stronger when the same test passes after the fix. |

## Demo script (slides 12-14, about 5-7 minutes)

1. **Frame it (30 s).** "This is deterministic branching over fictional data, not
   a real model. It lets us reproduce control behaviour exactly."
2. **Vulnerable mode (1-2 min).**
   `python demo/assistant.py --mode vulnerable`
   Point out: A answers normally; B, C and D print the fictional code. Case C is
   the important one: the user asked an innocent question and the *document*
   attacked.
3. **Secure mode and the table (2 min).**
   `python demo/assistant.py`
   Walk the before/after table. Say what changed: authorization outside the
   model, minimal retrieval, documents treated as untrusted.
4. **Show the evidence (1 min).**
   `python demo/assistant.py --audit` or `--report` for the finding records.
5. **Close the loop (30 s).** "Same cases, same scope, different result. That is
   the retest."

### Optional extras if time allows
- **Broader coverage:** `python demo/scan.py` shows attack success per failure
  class and how many normal questions still work.
- **Real model:** `python demo/local_model_demo.py --interactive` lets the audience
  type an attack and watch both designs react. See `demo/README.md`.
- **Retest on screen:** `python demo/scan.py --output baseline.json`, then
  `python demo/scan.py --compare baseline.json` prints `no differences`.

## Likely questions

- **Is this a real attack on an LLM?** No. It is a deterministic simulation of a
  design flaw. Real systems need the same controls.
- **Couldn't an attacker just reword the prompt?** Rewording can fool a model. It
  cannot change the session role the gate checks. The scanner includes reworded
  and obfuscated probes, and the secure column stays at zero.
- **Why does the vulnerable column not reach 100%?** The stand-in only reacts to a
  fixed list of cue words, so obfuscated probes slip past it by construction. A
  real model behaves differently, which is why the local-model mode exists.
- **Does the fix make the assistant useless?** The benign row shows normal
  questions still get answered.
- **Why not just use garak or PyRIT?** They are the right tools for real
  engagements. This repo teaches the concepts offline and safely; it is not a
  replacement for them.

## If something goes wrong
- Demo will not run: show `demo_output.txt`, then explain each section.
- Local model is slow or down: skip it. The deterministic demo is the deck's demo.
- Questions you cannot answer: say so, and note it as a follow-up. Nothing in the
  demo depends on a claim you have not verified.
