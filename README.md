# Adversarial AI & AI Red-Teaming

Group 34 project: a presentation on authorized AI red-teaming and a small,
safe, offline demo that shows why authorization belongs in code, not only in
prompts.

**Team:** Pruthvi Gangapure (12413969), Prathamesh Yewale (12415034),
Yash Waghmare (12410801), Chetan Thakur (12413081)

```bash
python demo/assistant.py          # the four-case live demo
python demo/scan.py               # 29 probes across the five failure classes
python -m unittest discover -s tests
```

Also included: an optional local-model mode (`demo/local_model_demo.py`) and
[presenter notes](docs/PRESENTER_NOTES.md).

See [`demo/README.md`](demo/README.md) for usage, what the demo proves, the
presentation-day checklist, and sources.
