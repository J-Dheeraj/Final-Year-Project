# Supervisor briefing: AI-assisted vulnerability confirmation and patch validation

## Research problem

The project evaluates whether an AI-assisted security pipeline can dynamically confirm known vulnerability behavior and reject or validate generated patches using executable evidence.

## System contribution

The pipeline connects advisory intake, exploit reproduction, live model assistance, patch generation, compilation, runtime validation, benign-path checks, and adversarial bypass probing. Results are categorized by the actual access mechanism: Ollama, Claude/AIxTech, Codex CLI, and OpenAI API.

## Experimental design

The main catalogue contains six reproduced CVEs. Supporting experiments cover OpenEMR and the real upstream free5GC UDR case. The OpenAI API sweep used 23 available model IDs, per-model token/runtime/cost instrumentation, and preserved model/API failures. The free5GC repeatability study ran GPT-5, GPT-4.1 Mini, GPT-5.2, and GPT-5.6 Luna three times each against the same pinned source and four-handler Docker validation sequence.

## Strongest result

The OpenAI free5GC sweep produced 18/23 runtime-confirmed patches across all four UDR handlers. The repeatability study confirmed all three GPT-4.1 Mini runs, two of three GPT-5 runs, and two of three GPT-5.6 Luna runs.

## Negative result

Five of 23 OpenAI free5GC patches failed compilation, and GPT-5.2 failed in all three repeat runs. OpenEMR patch generation produced 16/23 fully working gates. OpenAI bypass probing found zero genuine bypasses for the catalogue, OpenEMR, and free5GC.

## Limitations

Most catalogue CVEs are controlled reproductions rather than proof that the corresponding released packages are exploitable. The free5GC deployment validates the UDR component and its dependencies, not the entire 5G core network. Model availability, API policy refusals, Docker/network failures, and estimated pricing can affect results. The repeatability sample is targeted and small, not a statistically powered model ranking.

## Recommended next work

Freeze the evidence repository, run the documented clean reproduction, present the demonstration, and treat broader vulnerability classes or platforms as post-R&D work.
