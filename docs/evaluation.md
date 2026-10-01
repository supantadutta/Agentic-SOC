# Evaluation methodology

**Research question.** Can a resource-constrained agentic SOC improve alert triage,
correlation and response efficiency while keeping infrastructure and LLM costs low?

## Arms

| Arm | How it runs |
|---|---|
| Baseline SOC | Wazuh rules + human analyst. An incident is "flagged" when a rule of level ≥ `--baseline-level` (default 10) fires; every alert of level ≥ 7 needs human triage. Human triage/response times are measured in the lab and merged from a CSV. |
| Agentic SOC — heuristic | The full pipeline with the deterministic `HeuristicProvider` (zero LLM cost). |
| Agentic SOC — local | `--provider ollama` |
| Agentic SOC — cloud | `--provider cloud` (Claude API) |
| Agentic SOC — hybrid | `--provider hybrid` (local first, cloud when uncertain or severe) |

```bash
python -m evaluation.run_evaluation --provider heuristic --out results/heuristic
python -m evaluation.run_evaluation --provider ollama    --out results/ollama
python -m evaluation.run_evaluation --provider cloud     --out results/cloud
python -m evaluation.run_evaluation --provider hybrid    --out results/hybrid
# with measured human timings and simulated approvals (exercises the playbooks in dry run):
python -m evaluation.run_evaluation --provider ollama --out results/ollama-approve \
    --simulate-analyst approve --human-baseline evaluation/human_baseline_template.csv
```

Each run writes `metrics.json`, `scenarios.csv` and `report.md` (the blueprint §24 table).
To compare policy thresholds, pass `--policy <file>`.

## Scenarios (blueprint §22)

| Scenario | Chain | ATT&CK | Expected actions |
|---|---|---|---|
| `phishing_powershell_download` | Phishing → PowerShell → download → execution | T1566.001, T1059.001, T1105, T1204.002, T1071.001 | ISOLATE_HOST, BLOCK_IP, COLLECT_EVIDENCE |
| `credential_attack_lateral_movement` | Credential attack → valid account → lateral movement | T1110.001, T1078, T1021.002 | DISABLE_USER, ISOLATE_HOST, BLOCK_IP |
| `suspicious_powershell_outbound` | Suspicious PowerShell → command execution → outbound connection | T1059.001, T1059.003, T1071.001 | ISOLATE_HOST, BLOCK_IP, COLLECT_EVIDENCE |
| `scan_enumeration_exploit` | Port scan → service enumeration → exploitation attempt | T1046, T1595, T1190 | BLOCK_IP, COLLECT_EVIDENCE |
| `malicious_file_execution_c2` | Malicious file → execution → network communication | T1204.002, T1059.004, T1071 | ISOLATE_HOST, BLOCK_IP, COLLECT_EVIDENCE |
| 4 benign scenarios | Admin PowerShell, mistyped SSH password, package update, Defender scheduled task | — | NONE, MONITOR |

The bundled scenarios ([`evaluation/scenarios.py`](../evaluation/scenarios.py)) are
**synthetic** Wazuh alerts, which makes runs deterministic and repeatable. For the study itself:

1. Run each chain against the isolated lab from Kali, using your own scripts or the
   corresponding [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) tests for the
   listed techniques. Run attacks only against systems you own or are explicitly authorized to
   test, and revert VM snapshots between runs.
2. Export the resulting Wazuh alerts from the indexer as scenario JSON
   (`python -m evaluation.scenarios <dir>` shows the format) with ground-truth labels.
3. Replay them with `--scenarios <dir>` across all arms, several times each.

## Metrics

| Metric | Definition |
|---|---|
| True / false positives / negatives | Per scenario: the primary incident is flagged if classified `malicious` or `suspicious` |
| Correct classifications | Malicious scenarios classified `malicious`; benign ones `benign` |
| Correct actions | Final recommended action is in the scenario's expected set |
| Triage time | Pipeline time until the first triage decision (median over scenarios) |
| Response time | Time until a playbook ran (auto or simulated approval) |
| Analyst interventions | Agentic: approval/review requests. Baseline: alerts of level ≥ 7 |
| LLM cost / token usage | Sum over decisions; cost from [`config/llm_pricing.yaml`](../config/llm_pricing.yaml) |
| Automation success rate | Playbook runs ending `success`/`dry_run` ÷ runs executed |
| Audit chain validity | Every incident's hash chain verifies |

## Cost model (blueprint §25)

```bash
python -m evaluation.cost_model --config config/cost_model.yaml --results results/cloud/metrics.json
```

`Total = hardware + storage + electricity + cloud/API + backup + maintenance`;
`AI cost/alert` comes from the evaluation; `monthly AI cost = alerts/month × AI cost/alert`.
Replace every value in [`config/cost_model.yaml`](../config/cost_model.yaml) with measurements
(wall-power meter, tariff, actual alert volume after the Wazuh level filter).

## Threats to validity (report these)

* The heuristic arm was written alongside the bundled synthetic scenarios. Its scores on them
  say nothing about real-world accuracy. Use it as the zero-cost reference arm.
* Synthetic alerts are cleaner than real telemetry. Base conclusions on alerts captured from the
  lab, and include noisy benign activity (patching, admin scripts, scanners you run on purpose).
* Few scenarios mean wide confidence intervals. Repeat runs, report variance, and note that LLM
  outputs can vary between runs even at low temperature.
* Policy thresholds and the risk formula are parameters. Report sensitivity to them rather than a
  single setting.
* Measure human baseline times with more than one analyst and a fixed procedure.
