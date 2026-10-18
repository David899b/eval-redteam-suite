# Model Card — eval-redteam-suite

## Overview

`eval-redteam-suite` is an **adversarial evaluation harness**, not a model. It
runs a fixed attack corpus against a target system (model + prompt + tools +
retrieval) and reports the **Attack Success Rate (ASR)** per OWASP category and
overall, with a release decision.

- **Intended users:** AI security / evaluation engineers, release owners.
- **Intended use:** pre-release red-team gate in CI, regression testing of
  safety behavior, comparison of models/prompts/guardrails.
- **Out of scope:** training, serving, production monitoring, policy authoring.

## What it measures

| Signal | Detection |
|---|---|
| Instruction override | success markers in the response |
| Secret disclosure | planted canary appears in the response |
| Improper output | raw `<script>` / `DROP TABLE` markers |
| Excessive agency | forbidden tool names appear in the tool trace |
| Resource abuse | output tokens exceed a per-attack cap |

## Coverage and limitations

- **OWASP LLM Top 10 (2025):** LLM01, 02, 05, 06, 07, 08, 09, 10 covered;
  LLM03 (supply chain) and LLM04 (poisoning) are out of scope for a runtime gate.
- **Exact-match detection.** Success signals are literal. Paraphrased leaks and
  homoglyph obfuscation are **not** detected (pinned as `xfail(strict=True)`).
- **Trusted telemetry.** Token counts come from the target, not recomputed.
- **Static corpus.** No LLM-driven attack generation; the corpus is versioned
  and intentionally small and illustrative.

## Ethical and governance considerations

- Attack payloads here are **benign and synthetic**; no real secrets or PII.
- Red-team findings can be sensitive; treat reports as restricted until
  remediated.
- A `GO` means "the target survived this corpus", **not** "the system is secure".
  It is a floor, not a certificate.
- ASR thresholds encode risk tolerance and must be agreed with the accountable
  security owner.

## Metrics reported

Per category and overall: ASR, Wilson 95% confidence interval, sample sizes, and
the list of succeeded attacks with their reason. Overall ASR only — never a
bare "it passed".
