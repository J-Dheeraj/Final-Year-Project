# Independent XSS browser validation

The original catalogue XSS oracle is retained as `raw_oracle_positive` for
audit, but it is not the public bypass result. Historical XSS-positive
proposals from the Ollama, Claude CLI, AIxTech, and OpenAI reports were
replayed against the patched target and loaded in headless Chrome with dialog
and JavaScript-error instrumentation.

The replay report is
`reports/reachability/catalog_xss_browser_replay.json`. Its
`browser_genuine_bypass` field is the result used in summaries. A marker
comment or escaped `onerror=`/`javascript:` text cannot produce a positive
classification. The current replay found **0 genuine browser executions**.

Run it with:

```text
python browser_xss_replay.py
python apply_browser_xss_results.py
```

The deliberately vulnerable control and escaped regression cases are covered
by the same execution signals; only a browser-observed dialog or script error
can classify a genuine bypass.
