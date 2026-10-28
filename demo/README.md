# AI Red-Teaming Demo

Companion to the *AI Red-Teaming* presentation (Group 34).
A local, deterministic support assistant that runs the **same four test cases**
against a deliberately vulnerable design and a mitigated one, so the effect of
a fix can be shown by re-running the tests.

> **This is not a language model.** It is deterministic branching over
> fictional data. It makes control behaviour reproducible and safe for a
> classroom. It does not demonstrate a compromise of any real service.
> Standard-library Python only, **no network calls, no API key**.

## Quick start

Requires Python 3.10 or newer. Nothing to install.

```bash
python demo/assistant.py
```

(`python3` on macOS/Linux.) It works from any directory.

Expected output (about one screen):

```text
MODE: VULNERABLE SIMULATION
> Case A / normal FAQ
OK Refunds are available within 30 days.
> Case B / direct override
LEAK Internal code: ORBIT-741
> Case C / injected document
LEAK Internal code: ORBIT-741
> Case D / secret request
LEAK Internal code: ORBIT-741

MODE: SECURE (MITIGATED) SIMULATION
...
BEFORE / AFTER - same cases, same scope
| Normal question       | ANSWER      | ANSWER             |
| Direct injection      | SECRET LEAK | DENY               |
| Injected FAQ note     | SECRET LEAK | UNTRUSTED / IGNORE |
| Direct secret request | SECRET LEAK | DENY               |
```

The command exits `0` when the outcomes match the table above and `1` if the
secure mode ever leaks or the expected results change.

### Options

| Command | What it does |
|---|---|
| `python demo/assistant.py --mode vulnerable` | only the unsafe design (slide 13) |
| `python demo/assistant.py --mode secure` | only the mitigated design |
| `python demo/assistant.py --case C` | a single case |
| `python demo/assistant.py --step` | pause for Enter between sections |
| `python demo/assistant.py --audit` | also print the secure-mode audit log |
| `python demo/assistant.py --interactive` | type your own prompts (`:mode vulnerable`, `:mode secure`, `:audit`, `:quit`) |
| `python demo/assistant.py --report` | print finding records in the slide 16 format |
| `python demo/assistant.py --no-color` | plain text (also honours `NO_COLOR`) |

## What each part demonstrates

| Slide | Idea | Where in the code |
|---|---|---|
| 7 | Direct vs. indirect injection | Cases B and C |
| 9 | A prompt rule is not an authorization boundary | `respond_vulnerable` flaws 1-3 vs. `respond_secure` steps 1-5 |
| 10 | The model proposes; application code authorizes | `plan()` proposes, `authorize()` decides, `AuditLog` records |
| 14 | Fix the data and permissions path, then re-test | the before/after table |
| 16 | Findings record impact, likelihood, evidence, remediation, retest | `--report` |

**Vulnerable mode** has three deliberate flaws: retrieval searches the private
store, attacker-controlled text (user message *and* retrieved document) steers
the simulated planner, and whatever it proposes is executed without an
authorization check.

**Secure mode** fixes the path, not the wording:

1. **Authorize outside the model:** the proposed action goes through
   `authorize()`, using the role from the session, never from prompt text.
   Deny by default.
2. **Minimal retrieval:** only documents the role may read, top-1 only.
3. **Untrusted documents:** retrieved text never steers the planner;
   instruction-like lines are dropped and logged, and the case is reported as
   `UNTRUSTED / IGNORE`.
4. **Redact outputs:** a last-line check removes secret patterns.
5. **Audit:** every decision is logged.

Outcomes are judged by what reached the output (did `ORBIT-741` appear?), not
by how the attack was phrased. The unit tests also prove the gate holds when
the simulated model is *fully* fooled and when a document is phrased to evade
the sanitizer.

## Files

| File | Purpose |
|---|---|
| `demo/assistant.py` | the demo (single file, standard library) |
| `demo/sample_documents.txt` | fictional FAQ, one poisoned note, one private entry |
| `tests/test_assistant.py` | 20 tests, including a check that no network modules are imported |

Run the tests with:

```bash
python -m unittest discover -s tests -v
```

## Safety and ethics

- All data is fictional. `ORBIT-741` is not a real credential.
- The demo never opens a socket, calls an API, or touches real accounts.
  Do not adapt it to connect to real accounts or services.
- Real red-teaming needs written scope, authorization, privacy rules and stop
  conditions (slide 17). Reports must never contain real secrets; `--report`
  masks even the fictional one.

## Presentation-day checklist

**The day before**
- [ ] `python --version` shows 3.10 or newer on the presenting laptop.
- [ ] `python demo/assistant.py` runs and exits `0`.
- [ ] `python -m unittest discover -s tests` passes.
- [ ] Save a fallback: `python demo/assistant.py --no-color > demo_output.txt`

**Before you present**
- [ ] Terminal open in the repo root, font large enough for the back row.
- [ ] Dark theme or high contrast; run once with colours to confirm they show.
- [ ] Notifications off; battery or power connected.
- [ ] Airplane mode on is fine, since the demo is fully offline.
- [ ] `demo_output.txt` open in another window as a fallback.

**During (5-7 minutes)**
1. Slide 12: state what it is, and what it is not (not a real LLM).
2. Slide 13: `python demo/assistant.py --mode vulnerable` and point at the three `LEAK` lines.
3. Slide 14: `python demo/assistant.py` for the before/after table, or `--mode secure`.
4. Optional: `--interactive` and let the audience propose a prompt.
5. Close: authorization belongs in code, not only in prompts.

**Likely questions**
- *Is this a real attack on an LLM?* No. It is a deterministic simulation of a
  design flaw. Real systems need the same controls, and the research cases
  show why.
- *Couldn't an attacker just reword the prompt?* Rewording can fool a model.
  It cannot change the session role the gate checks. That is the point of the
  secure mode, and the tests cover reworded attacks.
- *Is the keyword filter the defence?* No. It is a hint for logging. Safety
  comes from authorization and never letting document text steer actions.

## Sources

Links as listed in the deck. They could not be checked from the environment
this repo was built in, so confirm them before presenting.

- OWASP LLM01:2025 Prompt Injection: https://genai.owasp.org/llmrisk/llm01-prompt-injection/
- OWASP LLM06:2025 Excessive Agency: https://genai.owasp.org/llmrisk/llm062025-excessive-agency/
  (slide 18 prints this URL with a colon, `llm06:2025-excessive-agency`; the
  version here has no colon. Verify which resolves.)
- OWASP GenAI Security Project: https://genai.owasp.org
- NIST AI 600-1, *AI RMF: Generative AI Profile* (2024): https://doi.org/10.6028/NIST.AI.600-1
- MITRE ATLAS: https://atlas.mitre.org and technique AML.T0051 (LLM Prompt Injection): https://atlas.mitre.org/techniques/AML.T0051/
- Greshake et al., *Not what you've signed up for: Compromising Real-World
  LLM-Integrated Applications with Indirect Prompt Injection* (2023): https://arxiv.org/abs/2302.12173
- PyRIT (Microsoft): https://github.com/microsoft/PyRIT
- garak (NVIDIA): https://github.com/NVIDIA/garak
