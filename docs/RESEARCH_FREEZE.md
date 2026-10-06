# October 2026 research freeze checklist

The R&D phase is complete when this checklist is satisfied. It is deliberately
separate from the final thesis-writing checklist.

## Evidence

- [x] Raw local sweep and every repeated study have been reconciled with the prose.
- [x] Every success has compile, runtime, and benign-path evidence.
- [x] Failed, inconclusive, and environment-limited attempts remain visible.
- [x] Every repeated run uses a distinct experiment/model/run artifact path.
- [x] The research ledger records evidence tier and exact source files.

## Repeated patch-generation study

- [x] Three independent runs completed for each selected local model.
- [x] The same vulnerable commit, Docker deployment, and validation sequence were used.
- [x] No failed live generation was silently replaced by a template result.
- [x] Hosted calls, if used, stay within the US$50 ceiling.
- [x] Ambiguous failures were re-run only to classify the failure cause.

## Demonstration

- [x] Vulnerable free5GC behaviour is shown.
- [x] Generated patch and compilation are shown.
- [x] All four handler fixes and benign behaviour are shown.
- [x] The failed small-model patch is shown being rejected.
- [x] A clean reproduction from documented setup succeeds.

## Freeze rule

After the final freeze commit, only factual corrections are allowed. New
vulnerability classes, platforms, fuzzing, and full-core-network deployment
are outside this R&D completion target.
