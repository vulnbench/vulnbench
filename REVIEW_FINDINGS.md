# VulnBench Audit Findings (2026-07-23)

Result of a 91-agent adversarial review (six dimension reviewers, per-finding
verification, completeness critique). **81 findings confirmed, 0 refuted.**
Severity: critical = invalidates or biases published numbers; major = materially
weakens defensibility or fairness; minor = polish.

Counts: 26 critical / 38 major / 17 minor. By category: fairness 16, judge-validity 16, docs 15, correctness 12, statistics 12, dataset 10.

Fixes shipped alongside this audit are marked **[FIXED]**; items requiring a
re-run, a data rebuild, or an owner decision are marked **[ACTION REQUIRED]**.
The mapping was assigned during remediation — see the Remediation Status
section at the end for the full disposition table.

## Critical findings

### C1. Harness/API failures scored as model failures: empty patches contaminate up to 100% of a model's instances
*Category: correctness · Location: `results/full_openai_gpt-5.4.json:1`*

Two small detail fixes, neither material: (1) run1_openrouter_moonshotai_kimi-k2.6.json has 161 empties at exactly 4096 completion tokens (163 of 164 at >=4096), not 163 at exactly 4096. (2) gpt-5.4's 1268 full-run empties all have exactly 361 completion tokens — a single uniform systematic failure mode (reasoning-only/extraction failure), not heterogeneous transport-level empties. Also a scoping caveat: "only Anthropic runs were failure-free" holds for the published old-suite full-1650 leaderboard, but in the new suite claude-fable-5 has 181/600 empty (156 at cap), so the problem is not strictly vendor-partitioned there.

**Evidence:** Computed per file: full_openai_gpt-5.4.json empty=1268/1650 (0 at cap = transport-level empties), full_stepfun_step-3.5-flash:free.json empty=1646 with 1640 at completion_tokens>=4096, full_anthropic_claude-opus-4.6.json empty=0. run1_openrouter_moonshotai_kimi-k2.6.json: 163/164 empties at exactly 4096 completion tokens. Conditional-on-nonempty full ranking: codex 26.99%, gpt-5.2 25.06%, opus-4.6 16.55%, gpt-5.4 14.66%, kimi-k2.5 12.33%, sonnet 12.18%.

**Recommended fix:** Treat empty/truncated responses as harness errors: retry with a larger completion budget (or reasoning excluded), report error rate as a separate column, and either exclude errored instances from the denominator or rerun until error rate is <1-2% for every model before publishing rankings.

### C2. GLM-5.2 best3 file re-scored under a more lenient rule than its own stored runs, and than the documented pass criterion
*Category: correctness · Location: `results/best3_z-ai_glm-5.2.json:1`*

Claim is fully correct for GLM-5.2, but the issue is wider: the pass_on_tie re-score (commit 03e9aae, "Update report voting rule for split judges") was applied to 10 fixed-harness model files in results/merged_harness_fix_20260620/ (deepseek-v4-pro 8 sub-0.5 passes, kimi-k2.5 6, qwen3.5-35b-a3b 7, gpt-5.5 5, kimi-k2.6 5, glm-5.1 3, qwen3.5-27b 3, glm-5.2 2, minimax-m2.7 2, kimi-k2.7-code 1), while the remaining leaderboard rows were scored by a single opus-4.8 judge with no tie handling — the published leaderboard therefore mixes two judging regimes, and pass-tie rows count instances with score < 0.5 as passes in violation of README.md:130. The tie rule is disclosed in the report copy ("A split two-judge vote passes when either judge votes pass") but is inconsistent with both the README criterion and the run1/2/3 files stored beside best3.

**Evidence:** Computed: 200/200 identical model_patch between best3 and run1; run1 aggregate total_passed=8, best3 total_passed=18; example instance vulnbench-CVE-2025-43761 run1 judge_verdict=fail ('Consensus by majority vote') vs best3 judge_verdict=pass ('Consensus by pass-tie vote'), same judge votes 'pass:1,fail:1'. Passes with score<0.5: [('vulnbench-CVE-2025-64495', 0.4), ('vulnbench-CVE-2023-45311', 0.45)].

**Recommended fix:** Regenerate best3_z-ai_glm-5.2.json and its runs under the single standard judge; enforce passed == (verdict=='pass' and score>=0.5) as a validation assertion when writing reports.

### C3. Gold 'fix' patches with no code fix (release/changelog/version-bump commits) in published sets
*Category: dataset · Location: `src/version_finder.py:568`*

Counts are classifier-dependent and the claim's figures are the conservative end. Curated 200 set: at least the 9 listed CVEs, but a broader classifier also flags CVE-2021-32050, CVE-2021-42057, CVE-2022-29257, and CVE-2024-29409 (all version-bump/submodule-bump-only golds), giving 9-13 (4.5-6.5%). Full 1650 set: 129-158 meta-only golds (7.8-9.6%) depending on code-extension list, plus ~22 test-only. Judge crossover on full_anthropic_claude-opus-4.6.json holds under either set: 29.7% pass (47/158) on meta-only golds vs 15.1% (226/1492) on the rest with the broader classifier, vs the claimed 30.2%/15.4% with the narrower one. All other details (unused owner_repo parameter at version_finder.py:122, tag-commit fallback at 568-585, size-only gold filter at benchmark_generator.py:175, and the quoted gold diffs) are exact.

**Evidence:** 200-set non-code golds: CVE-2025-55675 gold = a CHANGELOG date edit ('-### 5.0.0 (Tue May 27...)/+### 5.0.0 (Wed Jun 18...)'); CVE-2025-1300 gold = docs/README.md edit; CVE-2017-16897 gold = deletion of SECURITY-NOTICE.md; CVE-2025-68115 (parse-server) gold = changelogs/CHANGELOG_release.md + package.json 8.6.0->8.6.1 bump; CVE-2026-1245, CVE-2025-43761, CVE-2026-22696 = pure version bumps; CVE-2022-29229 = package-lock.json only. Full list (200 set): ['CVE-2025-43761','CVE-2025-68115','CVE-2026-22696','CVE-2025-55675','CVE-2025-1300','CVE-2022-29229','CVE-2017-16897','CVE-2025-53012','CVE-2026-1245']. Judge crossover computed from results/full_anthropic_claude-opus-4.6.json: pass on meta-on…

**Recommended fix:** Add a gold-validity gate to benchmark_stage: reject instances whose gold diff touches no source-code file (extend passes_size_filter with a code-file check); prefer GHSA/NVD-listed fix commits and verify the commit's repo matches github_repo_url in _extract_commit_from_refs; drop or re-source the 9 curated and ~150 full instances and republish numbers.

### C4. Unsanitized 1,650-instance answer key (pre-redaction checkpoint) is git-tracked next to the test set
*Category: dataset · Location: `data/benchmark/checkpoints/benchmark_instances.json:1`*

All core numbers confirmed exactly (0 vs 209 '[redacted]'; 258 raw SHAs and 754 URLs in checkpoint descriptions vs 0/0 sanitized; 1650/1650 descriptions differ; 15,357,076 bytes tracked since f518462; example CVE-2026-27576 matches verbatim). Two ancillary counts are regex-dependent: loose github commit-URL matches are 183 in the checkpoint (claim said 181) and 67 residual in vulnbench_full.json (claim said 24). Additional supporting fact: each checkpoint record also contains the gold_patch field alongside the unsanitized prompt.

**Evidence:** Computed from the tracked files: benchmark_instances.json has 0 occurrences of '[redacted]' vs 209 in vulnbench_full.json; 181 github.com/.../commit/<sha> URLs (loose regex; 93 with a strict quote-bounded regex) vs 24 residual in vulnbench_full.json; 258 of 1,650 instances carry raw 40-hex fix-commit SHAs in task_prompt.vulnerability_description and 754 carry live URLs, vs 0 and 0 in vulnbench_full.json; all 1,650 descriptions differ from their sanitized counterparts (instance_ids match 1650/1650). Concrete example, instance vulnbench-CVE-2026-27576 — checkpoint description ends: "## Fix Commit(s)\n- `732e53151e8fbdfc0501182ddb0e900878bdc1e3`\n- `ebcf19746f5c500a41817e03abecadea8655654a`\n- …

**Recommended fix:** Remove data/benchmark/checkpoints/ from the repo and purge it from git history (git filter-repo / BFG) before any public push — deleting in a new commit is insufficient since history remains clonable. Regenerate checkpoints locally and add data/benchmark/checkpoints/ to .gitignore. If build reproducibility is needed, publish only the sanitized artifacts plus the deterministic builder scripts.

### C5. 'Models receive vulnerable source context' claim is false for the large majority of instances
*Category: docs · Location: `docs/index.html:1`*

Claim is correct with small detail fixes: the cited file is benchmark/run_eval.py (not repo-root run_eval.py), and the empty-context path is both lines 711-713 (download failure) and 721-722 (no matched files). "Max 4480" was gpt-5.5's max; fable-5's max is 6745 (both consistent with the 6000-char SOURCE_CONTEXT_CHAR_LIMIT). Strengthened evidence: only 45/200 instances have any filename in the advisory text matchable by DESCRIPTION_FILE_RE, so under the default file_hint_mode="description" at most 22.5% of instances could ever receive source context; observed large-prompt counts (~36-38 per run) match this cap. Additionally, run1_openrouter_openai_gpt-5.3-codex.json (evaluated 2026-03-19, identical recorded config include_source=true/file_hint_mode=description) shows median prompt_tokens 832 with 124/200 >= 600 — source availability silently varied across runs, confirming per-instance inclusion is unrecorded and unverifiable from the artifacts.

**Evidence:** Computed: run1_openrouter_anthropic_claude-fable-5.json prompt_tokens 140/200 under 600, median 429; deepseek-v3.2 192/200 under 600, median 229. Dataset: 0/200 instances have non-empty task_prompt['source_context']. run_eval.py:711-713 'source_dir = download_source(...); if not source_dir: return ""'. docs/index.html hero text and README.md:120 '--include-source is enabled by default'.

**Recommended fix:** Persist per-instance source_context_included, source_files list, and source_chars; fail loudly (or mark the instance) when download_source returns nothing; and correct the README/docs methodology text to state the measured share of instances that actually received source context.

### C6. Published leaderboard mixes incompatible judging protocols across rows
*Category: fairness · Location: `results/merged_harness_fix_20260620/merged_leaderboard.json:1`*

Claim is accurate as stated. One refinement: the direction of bias is mixed rather than uniformly favoring the leader — under a uniform Opus-only protocol GPT-5.5 would drop to 56/200 (widening the gap to ~9.5 points), but the leader's row was never run with the retry-hardened adapter, so no cross-row comparison is apples-to-apples. Also, the merge rule itself (keep prior unless material improvement, per merged_leaderboard.json material_update_rule) takes the better of two protocols per model, an additional per-row selection bias.

**Evidence:** merged_leaderboard.json rows: claude-fable-5 src=prior_baseline rate=0.375; gpt-5.5 src=fixed_harness rate=0.33. Prior best3 files: results/best3_anthropic_claude-fable-5.json metadata judge_models=['openrouter/anthropic/claude-opus-4.8'] only; results/best3_openai_gpt-5.3-codex.json judged by 'openrouter/anthropic/claude-opus-4-6' (yet another judge version). Fixed-harness files: judge_models=[opus-4.8, gpt-5.5]. For merged best3_openai_gpt-5.5.json per-judge votes: both-pass=28, gpt-only=10, opus-only=28 → OR=66, Opus-only=56, AND=28. docs/index.html states 'GPT-5.5 ranks second at 33.0%, showing a 4.5-point gap from the leader.'

**Recommended fix:** Re-run all leaderboard rows under one frozen protocol (same judge panel, same voting rule, same adapter retry config, same judge model versions) before publishing a single ranked table. If mixed rows must be shown, split them into separate tables and never compute cross-protocol gaps or ranks.

### C7. 4096-token cap shared with reasoning truncates most generations for reasoning-heavy models
*Category: fairness · Location: `benchmark/run_eval.py:922`*

Two minor corrections that strengthen the finding: Gemini 3.5 Flash's non-diff output count is 497/600 (not 491), and Gemini shows 0/600 at the >=4096 threshold only because its provider truncates at 4092 tokens — 557/600 of its results sit at >=4090, so the >=4096 counting method understates its truncation rate. All other counts in the claim are exact.

**Evidence:** Computed over results/run[123]_openrouter_*.json: completion_tokens>=4096 counts above. Sample from run1_openrouter_google_gemini-3.5-flash.json (vulnbench-CVE-2024-43795, 4092 tokens): model_patch begins 'Wait, let's search for "login.html" in the OpenC3 repository...' — judge reasoning: 'contains no actual code changes—only confused musings'. Adapter fallback uses reasoning_content as answer text (litellm_adapter.py _response_text/used_reasoning_content).

**Recommended fix:** Raise the completion budget substantially (e.g., 16-32k) or set a separate reasoning.max_tokens so the answer budget is uniform across models; record finish_reason per result; report a per-model 'truncated generation' rate alongside pass rate and exclude or separately annotate truncation-caused failures in the WHY analysis.

### C8. Published leaderboard mixes three incompatible judge/harness regimes in one ranking
*Category: fairness · Location: `results/merged_harness_fix_20260620/merged_leaderboard.json:1`*

Judge regimes across the 37 published rows are: 14 rows judged single-judge by claude-opus-4-6, 13 rows single-judge by claude-opus-4.8, and 10 rows by the two-judge panel (opus-4.8 + gpt-5.5) under pass_on_tie (not 16/11/10 as claimed). In the merged GPT-5.5 file there are 38 split (1-1) votes, all counted as pass under the tie rule; 12 of those already passed in the rerun's own scoring, so 26 rows flipped fail->pass, converting the rerun's total_passed=40 into the published 66/200. Additionally, docs/index.html's methodology text describes the split-vote-passes rule as if it applied uniformly, when only 10 of 37 rows were scored that way, and the leaderboard table renders no per-row source/judge column despite the page saying 'Judge: see row metadata'.

**Evidence:** Manifest: consensus_voting_rule='pass_on_tie'; source counts {prior_baseline: 27, fixed_harness: 6, fixed_harness_new_model: 4}. run_eval.py:450: consensus_verdict = "pass" if pass_votes >= fail_votes else "fail". Merged best3_openai_gpt-5.5.json: total_passed=66 vs rerun original total_passed=40; 26/26 'pass:1,fail:1' rows have passed=true, e.g. vulnbench-CVE-2026-21892: 'Judge votes: claude-opus-4.8: pass (0.9000), gpt-5.5: fail (0.5000)' -> pass.

**Recommended fix:** Re-judge all 37 rows under one frozen judge configuration (one judge model+version, or the same panel with majority-not-tie rule) before publishing a combined leaderboard. If mixed rows must remain temporarily, render the per-row 'source'/judge column in the HTML table (leaderboard_html currently drops row.source) and add a visible comparability warning.

### C9. Leaderboard top ranks scored solely by same-vendor judge; Opus 4.8 judges itself; cross-judge data shows Anthropic-largest leniency gap
*Category: fairness · Location: `benchmark/run_eval.py:68`*

Leaderboard ranks are #1 Claude Fable 5 (37.5%), #2 GPT-5.5 (33.0%), #3 Claude Opus 4.8 (29.5%) — not #1/#2 both Anthropic. Both Anthropic rows (ranks 1 and 3) were scored solely by the Anthropic Opus 4.8 judge; the Opus 4.8 row is literal self-evaluation. The 2-judge panel was applied to other rows (e.g. GPT-5.5's published 33.0% uses the pass_on_tie 2-judge protocol) but never validly to Anthropic rows: Fable 5's panel rerun was 100% generation-errored (fixed_passed=0/200 in merged_leaderboard.json), and Opus 4.8 was never rerun. Cross-judge stats recomputed from rerun_fixes_2judge run files (excluding errored/empty patches, both judges present, n=5,255): anthropic n=544 Opus 17.8% vs GPT-5.5 7.0% (ratio 2.55; 70 opus-only vs 11 gpt-only); openai n=609, 33.8% vs 22.8% (ratio 1.48). The claimed 1.76/1.10 ratios and n=454/456 do not reproduce; the actual gap is larger. Caveat: Opus is more lenient for every vendor (deepseek 2.40, minimax 2.38), so the data shows Anthropic-largest leniency but not uniquely same-vendor bias. Additional issue: the leaderboard mixes judging protocols across rows while docs/index.html describes only the two-judge rule.

**Evidence:** run_eval.py:68 `JUDGE_MODEL = "openrouter/anthropic/claude-opus-4.8"`. Metadata: best3_anthropic_claude-fable-5.json judge_model='openrouter/anthropic/claude-opus-4.8' (single, no judge_models list); best3_anthropic_claude-opus-4.8.json model='openrouter/anthropic/claude-opus-4.8', judge='openrouter/anthropic/claude-opus-4.8'. Computed from results/rerun_fixes_2judge_20260613_232410/run*: vendor=anthropic n=454 opus_pass=0.148 gpt_pass=0.084 (ratio 1.76); vendor=openai n=456 opus_pass=0.336 gpt_pass=0.305 (ratio 1.10). docs/index.html: 'Claude Fable 5 ... 37.5% ... prior baseline' rank 1, 'Claude Opus 4.8 ... 29.5%' rank 2.

**Recommended fix:** Score every leaderboard row with the same fixed cross-vendor panel (at least Opus + GPT + one neutral third judge for tie-breaks), exclude or downweight a judge when scoring its own vendor's models, and publish per-judge votes plus a same-vendor sensitivity analysis. Re-run the Anthropic rows under the panel before publishing rankings.

### C10. max_tokens=4096 + provider-default hidden reasoning zeroes out reasoning-heavy models (30-100% of instances)
*Category: fairness · Location: `benchmark/run_eval.py:923`*

Two detail corrections, neither changing the verdict: (1) Moonshot/kimi-k2.6 is not strictly 'hard-capped at 4096 total' — its overall mean completion_tokens is 5,304-5,885 and its empty instances average 4,081-4,582, so some reasoning tokens escape the cap, but content still returns empty at roughly the cap. (2) Not all empty patches suite-wide are cap-truncation: qwen3.5-27b and qwen3.5-35b-a3b runs 2-3 show 200/200 empties at 0 completion tokens (provider/routing failure — a separate harness reliability issue), and minimax-m2.5/m2.7 and gemini-3.1-pro empties occur well below the cap; however, for every model the claim names the empties cluster at/above 4096, consistent with the reasoning-consumes-budget mechanism. Additional fact strengthening the claim: even the top-ranked model, claude-fable-5, lost 59-63/200 instances per run to empty patches at mean ~3,600-3,750 completion tokens, and litellm_adapter.py:30-34 shows the authors recognized and fixed this exact failure mode for glm-5.2 only.

**Evidence:** Computed from results: run1_openrouter_openai_gpt-5.5.json: 127/200 empty patches, mean completion_tokens 4037; run1_openrouter_moonshotai_kimi-k2.6.json: 164 empty, mean CT 4081; run1_openrouter_stepfun_step-3.5-flash:free.json: 200/200 empty at exactly 4096 mean CT in all 3 runs (pass_rate 0.0 published); run2_openrouter_x-ai_grok-build-0.1.json: empties average 255,998 completion tokens; run1/2/3 claude-opus-4.8: 0 empty. Adapter sends only temperature/max_tokens with empty reasoning config for all non-glm-5.2 models (litellm_adapter.py:326-349).

**Recommended fix:** Either set an explicit, provider-normalized budget (e.g. max_tokens large enough for reasoning + answer, or reasoning.max_tokens + separate answer budget via OpenRouter's reasoning config) identically for every model, or detect finish_reason=='length'/empty-content-at-cap and mark the instance as a harness truncation rather than a scored 0. Publish per-model effective token budgets alongside scores.

### C11. Old-harness rows are dominated by 4096-token truncation scored as model failure
*Category: fairness · Location: `benchmark/adapters/litellm_adapter.py:168`*

Confirmed with two corrections. (1) The run1 numbers quoted are accurate, but the published leaderboard uses best-of-3 files: for several flagship examples the board row is less affected than run1 suggests (deepseek-v3.2 board row 0 empty, qwen3.7-max 3, grok-4.1-fast 1; gpt-5.5 and kimi-k2.6 were replaced by fixed-harness reruns). The defect nonetheless persists in published prior_baseline rows: claude-fable-5 (ranked #1) 59/200 empty patches with 51 at >=4000 completion tokens (stable ~60 across all 3 runs), minimax-m3 77/200 (all at cap), gpt-5.2 45/200 (44 at cap), glm-5 46/200, gemini-3.1-pro-preview 63/200, step-3.7-flash 192/200. (2) The mechanism is broader than 4096 truncation: some models' empties (deepseek-v3.2 run1: 165 empty at median ~881 tokens, 0 at cap; gpt-5.3-codex 1/111 at cap; minimax-m2.5 0/115) are low-token empty-content responses with extreme run-to-run variance (165→0→0), i.e. a provider/harness instability also scored as model failure. Both mechanisms are zero-scored via run_eval.py:265-271 "Empty or no patch produced.", and best-of-3 selection silently launders the variance instead of surfacing it. The GLM-5.2-only reasoning-disable accommodation (litellm_adapter.py:30-34) and the 27 prior_baseline rows are confirmed exactly as claimed; the fixed-harness rerun kept max_tokens=4096.

**Evidence:** litellm_adapter.py:167-168 'temperature: float = 0.0 / max_tokens: int = 4096'; :30-34 DEFAULT_REASONING_DISABLED_BY_MODEL = {'openrouter/z-ai/glm-5.2'} with quoted comment. Computed from results/run1_openrouter_*.json: gpt-5.5 empty=127, completion_tokens median 4096, 97.6% >=4000; kimi-k2.6 empty=164, 99% >=4000; step-3.7-flash empty=197.

**Recommended fix:** Rerun all models with an adequate completion budget (or reasoning excluded/capped uniformly), persist finish_reason per instance, and report 'no-patch-produced' as a separate harness-failure category rather than a 0.0 score. Do not publish rows where empty-response rate exceeds a stated threshold.

### C12. Three different judge/harness regimes across models in the same published suite
*Category: fairness · Location: `benchmark/run_eval.py:68`*

Claim is accurate as stated (counts, cohorts, dates, and harness flags all verified). Two additions: (1) the public report docs/v2.html not only mixes the three regimes in one 37-model leaderboard but also misdescribes the methodology, stating patches pass via a "split two-judge vote" — true for only glm-5.2 (3 runs); the other 36 models were judged by a single judge. (2) The repo already contains a partial mitigation — results/analysis/README.md separates models into per-configuration tables with a "cross-table comparisons are not valid" notice, and results/rerun_fixes_2judge_20260613_232410/ holds 25 best3 files re-judged under the 2-judge panel — but the public leaderboard does not use either.

**Evidence:** Computed from results/run*_openrouter_*.json metadata: 54 runs have judge_model='openrouter/anthropic/claude-opus-4-6', 51 runs have 'openrouter/anthropic/claude-opus-4.8', and only the 3 glm-5.2 runs have judge_models=['openrouter/anthropic/claude-opus-4.8','openrouter/openai/gpt-5.5'] plus retry_empty_responses=True/adapter_max_attempts=3. All non-glm-5.2 runs have judge_models=None, max_tokens=None, retry_empty=None in metadata and empty judge_analyses ({} for all 200 instances), i.e. old single-judge harness. run_eval.py:68-72 defines the current panel that only glm-5.2 ever saw.

**Recommended fix:** Re-run the entire suite under one frozen harness version and one judge configuration (record a harness_version/git SHA in metadata). Never mix judge versions on one leaderboard; if a judge upgrade is needed, re-judge all stored patches (they are persisted in the result files, so re-judging is cheap and does not require re-generation).

### C13. Models did not receive identical prompts: source context silently missing for many runs
*Category: fairness · Location: `results/full_openai_gpt-5.4.json:1`*

Directionally correct and critical, but the mechanism is misdescribed. The degraded rows are not prompts sent without the source snippet: gpt-5.4's 207 sub-500-token full-suite rows sit at a constant prompt_tokens=240 (1,274 of its 1,650 rows total, 1,268 with empty patches), and qwen3.7-max run1's 112 empty rows are all exactly prompt_tokens=178 with generation_time_s about 0.003s — physically impossible API round trips. These are failed/aborted generations recorded as legitimate scored attempts (score 0.0, 'Empty or no patch produced'), with no generation_error field in the older result schema. A separate genuine silent-context-omission path also exists in code: build_source_context returns "" without any record when source download fails (benchmark/run_eval.py:711-713). Net impact is larger than claimed: the published VulnBench-1650 leaderboard largely ranks models by infrastructure-failure rate (empty patches out of 1650: gpt-5.4 1268, gpt-5.2 1207, kimi-k2.5 1196, deepseek-v3.2 1058, grok-4.1-fast 1003, minimax-m2.5 873, vs 0 for opus-4.6/sonnet-4.6/haiku-4.5), and README.md:63 presents the resulting artifact ('GPT-5.4 drops from 2nd (18.5%) to 10th (3.4%)') as a model finding. On the 200 subset, best-of-3 selects a whole best run (best3 metadata 'best_run'), so models with a degraded run1 effectively got best-of-2, contradicting README.md:38's 'identical' claim. Fix should both assert prompt-hash equality across models/runs and exclude or rerun rows with adapter failure (empty patch + placeholder token counts / near-zero generation time), rather than scoring them as fails.

**Evidence:** Computed: instances where opus-4.6 full prompt>1000 tok but gpt-5.4 prompt<500 tok: 207 (of 275). Per-run for qwen3.7-max: run1[2026-06-12] big=12 empty=112 pr=11.5% ; run2 big=29 empty=3 pr=28.5%; run3 big=29 empty=1 pr=27.0%. gpt-5.3-codex run1[2026-03-19] big=12 empty=111 pr=8.5%; run2/3 big=29 pr=21.0/22.5%.

**Recommended fix:** Log a content hash of each rendered prompt per instance and assert equality across models/runs; invalidate and rerun any run whose prompt set differs from the canonical set.

### C14. Measured within-run provider heterogeneity fully determines kimi-k2.6's published score (0% pass when capped at 4096 vs 28.3% when uncapped)
*Category: fairness · Location: `results/run1_openrouter_moonshotai_kimi-k2.6.json`*

Corrections to an otherwise accurate claim: (a) the cap is at benchmark/adapters/litellm_adapter.py:168 (claim's path omitted the adapters/ directory); (b) run1's over-cap range is 4,243-29,186 across 23 instances, not 5,387-29,069 (5,387 is run2's minimum); (c) "values are not multiples of 4096" holds for run1, but runs 2-3 each contain 32,768 (=8x4096) — the retry-sum alternative is instead refuted decisively by prompt_tokens: recorded usage is summed across attempts (litellm_adapter.py:485-488), yet every over-cap instance shows single-attempt prompt_tokens and 48/92 exceed the 3-attempt ceiling of 12,288; (d) pair-count denominators differ slightly by method (reproduced: 56 of 127 adjacent same-shape pairs >8% cost difference; 34 of 93 exact-shape cross-run pairs, max ratio 1.372; the cited CVE-2024-43795 1.353 example verified); (e) "fully determines" is precise in one direction only: capped instances cannot pass (0/478, 161/165 empty patches in run1), so routing determines pass eligibility, while the 28.3% among uncapped instances still reflects model ability. Including sub-cap completions, the non-capped bucket passes 36/122 (29.5%).

**Evidence:** Computed from results/run{1,2,3}_openrouter_moonshotai_kimi-k2.6.json: per-attempt completion-token mass at exactly 4096 = {run1:165, run2:160, run3:153} of 200 with outliers 5,387-46,268; identical-shape cost triplet in run1: vulnbench-CVE-2024-9440 (pt=196, ct=4096, $0.01410) vs vulnbench-CVE-2023-52312 (pt=196, ct=4096, $0.01906) vs vulnbench-CVE-2018-1000534 (pt=197, ct=4096, $0.01657); cross-run example vulnbench-CVE-2024-43795 (pt=252, ct=4096): $0.014128 in run1 vs $0.019117 in run2 (ratio 1.353); pass split: capped 0/478 = 0.0% vs uncapped 26/92 = 28.3%; run1 capped instances with empty extracted model_patch: 161/165. Gemini uniform cap: max completion_tokens = 4092 in all three run …

**Recommended fix:** Invalidate and re-run kimi-k2.6 (and audit every other model's runs for the same fingerprints: exact-cap token histograms and cost-at-fixed-shape dispersion) under pinned provider routing with require_parameters=true, and raise or explicitly justify the 4096 output cap for reasoning models; publish per-instance served-provider metadata so reviewers can verify homogeneity.

### C15. GPT-5.5 is simultaneously a judge and the #2 ranked competitor; its solo vote is decisive under pass-on-tie
*Category: judge-validity · Location: `benchmark/run_eval.py:69`*

Claim confirmed as stated, with one strengthening addition: not only was Claude Fable 5 judged solely by Claude Opus 4.8 (same family), but judge panels are inconsistent across the whole merged leaderboard — of 38 best3 files in results/merged_harness_fix_20260620/, some used single opus-4-6, some single opus-4.8, and only ~10 used the dual [opus-4.8, gpt-5.5] panel — so published rows were produced under three different judging regimes, compounding the conflict-of-interest issue with a comparability issue.

**Evidence:** benchmark/run_eval.py:68-72 `JUDGE_MODEL = "openrouter/anthropic/claude-opus-4.8"; DEFAULT_JUDGE_MODELS = [JUDGE_MODEL, "openrouter/openai/gpt-5.5"]`. Computed from results/merged_harness_fix_20260620/best3_openai_gpt-5.5.json judge_analyses: gpt-only-pass=10, opus-only-pass=28, both=28; total_passed=66.

**Recommended fix:** Exclude any model under evaluation from the judge panel (or at minimum exclude a judge from scoring its own family and disclose it). Use judges not on the leaderboard, require unanimous or majority (not tie) pass, and report per-judge agreement statistics per candidate model so self-preference is auditable.

### C16. Voting rule changed retroactively; stored results re-scored, inflating GPT-5.5 from 20% to 33%
*Category: judge-validity · Location: `benchmark/run_eval.py:450`*

Core claim fully confirmed with two evidence-level precision fixes: (1) the pre-change file contains 38 split-verdict instances, not 26 — 12 already passed under the old rule because one judge's inconsistent verdict was demoted to an abstention (making the vote 1-0 pass); the 26 flipped instances are the truly counted 1-1 ties. (2) "Every one of the 26 flipped ties moved in GPT-5.5's favor" is mechanically entailed by tie→pass (all tie flips are fail→pass by definition), so it is a property of the rule rather than independent evidence of selective flipping. The retroactivity, +13-point inflation to the #2-ranked model, unchanged judge outputs, and contradictory un-rescored run artifacts (glm-5.2: runs 8/7/9 vs best3 18) all hold exactly as claimed.

**Evidence:** git log -S: 03e9aae diff shows `- pass if pass_votes > fail_votes` → `+ pass if pass_votes >= fail_votes`. results/rerun_fixes_2judge_20260613_232410/best3_openai_gpt-5.5.json: total_passed=40, rate=0.20, 26 split votes all FAIL; results/merged_harness_fix_20260620/best3_openai_gpt-5.5.json: total_passed=66, rate=0.33, same mean_score=0.3384, 26 splits all PASS. Same pattern for deepseek-v4-pro (12→31 passed) and glm-5.2 (run files 8/7/9 passed vs best3_z-ai_glm-5.2.json 18 passed).

**Recommended fix:** Pick one voting rule before running (a 1-1 tie defaulting to PASS is hard to defend; tie→fail or a third tie-breaking judge is standard), then re-run or at minimum re-score ALL result artifacts — run files, best3 files, and both report branches — under that single rule, and disclose the rule change and its per-model impact in the report.

### C17. Published leaderboard mixes three different judge regimes in one comparative table
*Category: judge-validity · Location: `results/merged_harness_fix_20260620/merge_decisions.json:1`*

The published 37-row leaderboard (docs/index.html, generated from results/merged_harness_fix_20260620/merged_leaderboard.json) mixes three judge regimes: 14 rows single claude-opus-4-6 (March runs, e.g. GPT-5.3 Codex 22.5%), 13 rows single claude-opus-4.8 (June runs, e.g. Claude Fable 5 37.5%), and 10 rows — not just GLM 5.2 — under the Opus-4.8+GPT-5.5 two-judge panel (deepseek-v4-pro, minimax-m2.7, kimi-k2.5/2.6/2.7-code, gpt-5.5, qwen3.5-27b, qwen3.5-35b-a3b, glm-5.1, glm-5.2, sourced from results/rerun_fixes_2judge_20260613_232410). The two-judge regime is lenient OR-voting ("passes when either judge accepts", consensus_voting_rule "pass_on_tie"), not stricter as originally claimed — so the 10 panel-judged rows are if anything advantaged, while the site's methodology section describes this two-judge vote as if it applied to all rows, misdescribing the 27 single-judge rows.

**Evidence:** Extracted metadata.judge_models from every results/*.json: 135 files judged by ('openrouter/anthropic/claude-opus-4-6',) dated 2026-03; 68 files by ('openrouter/anthropic/claude-opus-4.8',) dated 2026-06; only the four z-ai_glm-5.2 files by ('openrouter/anthropic/claude-opus-4.8','openrouter/openai/gpt-5.5') dated 2026-06-21/22. E.g. best3_openai_gpt-5.3-codex.json judge=claude-opus-4-6 (2026-03-20) vs best3_anthropic_claude-fable-5.json judge=claude-opus-4.8 (2026-06-10), both rows in docs/index.html leaderboard.

**Recommended fix:** Re-judge all stored model patches (they are persisted in the result JSONs) with one pinned judge panel and regenerate the leaderboard from that uniform scoring. Record a judge-regime version in metadata and never merge rows across regimes.

### C18. GPT-5.5 sits on its own judge panel; 10 of its 66 published passes come solely from its own vote
*Category: judge-validity · Location: `results/merged_harness_fix_20260620/best3_openai_gpt-5.5.json:1`*

The fixed-harness rerun batch used judge_models=[claude-opus-4.8, openai/gpt-5.5] with pass_on_tie, and GPT-5.5's own leaderboard entry (33.0%, rank 2 in docs/v2.html) was scored by this panel. Because a 1-1 split passes, every instance where GPT-5.5-as-judge approves its own patch passes regardless of the opus vote. 10 of its 66 passes have opus-4.8 verdict=fail and only the gpt-5.5 self-vote as pass; under opus-4.8 alone it would score ~56/200 = 28.0%, not 33.0%. No other frontier model in the table is judged by itself under this rule (opus-4.8's own row used single-judge opus-4.8, a separate self-judging concern).

**Evidence:** Computed from best3_openai_gpt-5.5.json judge_analyses: passed=66 = 28 both-judges-pass + 28 opus-only + 10 gpt-5.5-only; opus-4.8 verdict=pass on ~56 instances total. docs/v2.html: 'GPT-5.5 ranks second at 33.0%'.

**Recommended fix:** Exclude any model from its own judge panel, or use a fixed judge panel that contains no benchmarked model; re-score GPT-5.5 (and any panel-judged rows) with the standard judge.

### C19. Published leaderboard mixes three incompatible judge protocols in one table
*Category: judge-validity · Location: `results/merged_harness_fix_20260620/merged_leaderboard.json:1`*

The public report (docs/index.html, docs/v2.html) is generated from results/merged_harness_fix_20260620/, whose 37 rows were scored under three different judging regimes: 14 rows by single judge openrouter/anthropic/claude-opus-4-6 (March era), 13 rows by single judge claude-opus-4.8 (June era), and 10 rows by a two-judge panel (opus-4.8 + gpt-5.5) with consensus_voting_rule='pass_on_tie'. With two judges, pass_on_tie means an instance passes when EITHER judge passes (run_eval.py:450: consensus_verdict = "pass" if pass_votes >= fail_votes else "fail"), which is strictly more lenient than any single-judge row. docs/v2.html describes one uniform methodology ('All models run against the same 200 vulnerability repair tasks... A split two-judge vote passes when either judge accepts the patch'), concealing that 27 of 37 rows were never panel-judged. Cross-protocol rank comparisons (e.g. Kimi K2.5 19.5% panel-judged vs Sonnet 4.6 10.5% opus-4-6-judged) are not comparable.

**Evidence:** Computed from merged dir metadata: judge=opus-4-6 single: gpt-5.3-codex 22.5%, gpt-5.4 18.5%, opus-4.6 16.0%, gpt-5.2 15.0%, sonnet-4.6 10.5%, +9 more. judge=opus-4.8 single: fable-5 37.5%, opus-4.8 29.5%, qwen3.7-max 28.5%, +10 more. panel pass_on_tie: gpt-5.5 33.0%, kimi-k2.5 19.5%, deepseek-v4-pro 15.5%, glm-5.1 12.5%, kimi-k2.6 11.0%, qwen3.5-35b-a3b 10.0%, qwen3.5-27b 9.5%, glm-5.2 9.0%, minimax-m2.7 8.0%, kimi-k2.7-code 6.0%. Panel leniency measured per file: deepseek-v4-pro 31 passes = 6 both-judges + 18 opus-only + 7 gpt-5.5-only; kimi-k2.5 39 = 14 + 20 + 5.

**Recommended fix:** Re-judge every leaderboard row with one fixed judge configuration (one model, one voting rule) before publishing a combined table; store judge identity in each published row and refuse to merge rows with different judge configs.

### C20. Split-judge tie counts as pass, with benchmarked model gpt-5.5 on the panel; rule applied retroactively to one model
*Category: judge-validity · Location: `benchmark/run_eval.py:450`*

Two corrections, both aggravating. (1) The retroactive flip was not limited to glm-5.2: commit 03e9aae also flipped tie verdicts in 10 models' files under results/merged_harness_fix_20260620/ (gpt-5.5: 26 splits flipped, kimi-k2.5: 19, deepseek-v4-pro: 19, qwen3.5-35b-a3b: 15, glm-5.1: 10, etc.), while the earlier 2-judge rerun in results/rerun_fixes_2judge_20260613_232410/ still stores those same ties as fail. (2) The gpt-5.5 self-judging conflict is realized in published data, not hypothetical: in merged_harness_fix_20260620/best3_openai_gpt-5.5.json, 10 of gpt-5.5's 26 tie-flipped passes are instances where gpt-5.5's own pass vote (against Opus's fail) is what made its own patch pass; its merged-leaderboard pass count rose from 35 to 66. Additionally, merged_leaderboard.json mixes regimes — 27 rows are single-judge (Opus only, where no tie rescue exists) and 10 rows are 2-judge pass-on-tie — and its material_update_rule replaces a prior row only when the 2-judge rerun IMPROVES pass count and mean score, a one-directional ratchet that keeps each model's higher score across two incompatible scoring rules. Minor note: two glm-5.2 flipped instances (median scores 0.4 and 0.45) are passed=true because run_eval.py:609 gates pass on verdict only, not score>=0.5.

**Evidence:** run_eval.py:450: consensus_verdict = "pass" if pass_votes >= fail_votes else "fail". Computed: run1 glm-5.2 file: total passed 8, splits(pass:1,fail:1)=10, splits passed 0; best3_z-ai_glm-5.2.json: total passed 18, splits=10, splits passed 10, metadata best_run=1, all_runs run1 pass_rate 0.09.

**Recommended fix:** Make ties fail (or require unanimous pass), use an odd-sized panel, and exclude any judge that is also a ranked competitor (or at minimum report self-judged models separately). Recompute every model under the final rule; never edit one model's stored passed bits under a rule others didn't get.

### C21. GPT-5.5 judge truncated at 1024 shared tokens; panel silently collapses to solo Anthropic-Opus on 7.15% of published panel rows
*Category: judge-validity · Location: `benchmark/run_eval.py:110`*

Two supplementary details need correction: (1) 413/420 (98.3%), not 100%, of persisted judge_error rows carry the 'Expecting value: line 1 column 1 (char 0)' reason; the remaining 7 are 'Unterminated string' JSON errors — also a truncation signature (JSON cut mid-output), so the root-cause diagnosis is unchanged. (2) The log-derived attempt counts (2,214/2,353 GPT-5.5 char-0 failures vs 46 Opus failures) could not be reproduced exactly with an independent regex over results/logs/ (I measured 195 GPT-5.5 attempt failures, 174 char-0, vs 4 Opus failures), but the qualitative asymmetry — GPT-5.5 failures dominated by empty-content truncation, Opus failures near zero — holds; the primary persisted-result evidence (420/7,000 rows, 7.15%/5.54% by directory, all solo-decided by claude-opus-4.8) is fully reproduced.

**Evidence:** run_eval.py:110 'JUDGE_MAX_TOKENS = 1024'; run_eval.py:324-334 request dict = {model, messages, temperature: 0.0, max_tokens: JUDGE_MAX_TOKENS, num_retries: 2, timeout} — no 'reasoning' key; run_eval.py:425 'if analysis.raw_judge_verdict != "judge_error"'; run_eval.py:450 'consensus_verdict = "pass" if pass_votes >= fail_votes else "fail"'. Computed: 420/7,000 GPT-judged rows errored (merged 143/2,000 = 7.15%, rerun 277/5,000 = 5.54%); all 420 reasons = 'Judge error after retries: Expecting value: line 1 column 1 (char 0)'; all 420 have judge_cost_usd > 0 (mean $0.1123, range $0.0994-$0.1631, total $47.16 spent on failed judging); logs: 2,214/2,353 GPT-5.5 attempt failures are char-0 vs 46 t…

**Recommended fix:** Set the GPT-5.5 judge's completion budget high enough to cover reasoning + JSON (e.g. max_tokens >= 8-16k) or pass an explicit reasoning config (e.g. reasoning.max_tokens or effort=low, or reasoning.exclude) so visible output cannot be starved; escalate max_tokens on retry after an empty-content parse failure; detect finish_reason=='length' / empty content explicitly and treat it as truncation, not a generic parse error. Re-judge the 420 affected rows before republishing.

### C22. Merge rule is an asymmetric ratchet that cherry-picks each model's better measurement
*Category: statistics · Location: `benchmark/generate_v2_report.py:371`*

The merge rule is a one-way ratchet (not a strict per-metric max): a prior row is replaced only when the rerun improves BOTH mean score by >=0.02 AND pass count by >=1 (requires_both:true), and all regressions or mixed results keep the prior number — so rows can only move up, never down, biasing the merged board upward. Because requires_both holds, some rerun improvements were also discarded inconsistently (gpt-5.3-codex rerun passed 75 vs prior 45 but kept at 45; sonnet-4.6 41 vs 21 kept at 21). The selectively-trusted rerun batch was visibly broken: NINE models returned fixed_passed=0 with fixed_score=0.0 (claude-fable-5 prior 75, claude-opus-4.6, gemini-3-flash-preview, gemini-3.1-pro-preview, gpt-5.2, grok-4.1-fast, minimax-m2.5, minimax-m3, glm-5) and qwen3.7-max collapsed 57→8, yet 6 rows were replaced from that same batch. Additionally, the 6 updated rows were judged under a different, more lenient config (two judges, split vote passes) than the 27 kept single-judge rows, so the merged leaderboard mixes harness versions AND judge configurations.

**Evidence:** generate_v2_report.py:371-375 markdown 'Merge Rule' text; merged_leaderboard.json material_update_rule {min_mean_score_delta: 0.02, min_total_passed_delta: 1, requires_both: true}; decisions: claude-fable-5 prior_passed=75, fixed_passed=0, score_delta=-0.4427 (kept prior) while gpt-5.5 prior_passed=35, fixed_passed=66 (updated).

**Recommended fix:** Abandon per-model max-merging. Publish one leaderboard per (harness version, judge config) and clearly date them; when the fixed harness is trusted, rerun ALL models on it and replace the whole board, discarding the batch whose runs returned 0/200.

### C23. The 2-judge validation rerun is invalid: 43.5% of rows are OpenRouter 402 billing failures scored as fail/0.0, then a ratchet merge rule kept the lenient single-judge numbers
*Category: statistics · Location: `results/rerun_fixes_2judge_20260613_232410/best3_anthropic_claude-fable-5.json:1`*

All details confirmed with two trivial corrections: (1) generation-error rows have verdict=None and passed=False (not a literal 'fail' verdict string) with score 0.0; (2) commit 03e9aae removed the Source column from the published HTML pages, but provenance remains in the JSON and Markdown artifacts (merge_decisions.json, merged_leaderboard.json, vulnbench_200_v2_report.md). Additional supporting fact: deepseek-v3.2's valid rerun (9→21 passes) was also discarded under the ratchet (score_delta -0.0638).

**Evidence:** Computed: 2-judge rerun best3 rows: 5000, with generation_error: 2176 (43.5%). Sample generation_error: 'OpenrouterException - {"error":{"message":"Insufficient credits...","code":402}}'. merge_decisions.json: fable-5 'prior_passed': 75, 'fixed_passed': 0, 'decision': 'keep_prior_no_material_improvement'; sonnet-4.6 'prior_passed': 21, 'fixed_passed': 41, 'score_delta': -0.0303, decision keep_prior. Commit 03e9aae also removed the leaderboard 'Source' column that disclosed per-row provenance.

**Recommended fix:** Void the contaminated rerun, re-run the panel with adequate credits, and treat panel results as the canonical scoring rather than merging via an improvement ratchet. Never score rows where generation failed for infrastructure reasons; exclude or retry them. Restore per-row provenance in the published table.

### C24. API/infrastructure failures are scored as model failures in published pass rates
*Category: statistics · Location: `benchmark/run_eval.py:274`*

One numeric detail is off: the raw glm-5.2 run files show pass_rate 0.035 (run2, with the 80 DNS errors) and 0.04 (run1), not 0.08; the 0.09/0.08/0.08 figures appear only in best3_z-ai_glm-5.2.json's all_runs metadata (rebuilt 2026-06-21 with two judges). The contamination conclusion is unchanged: the best3's chosen best_run=1 results still include 26 adapter-error instances scored judge_verdict=fail/0.0 inside the published 0.09 pass rate. Also, the 200/200 errors in rerun_fixes_2judge_20260613_232410/best3_anthropic_claude-fable-5.json are OpenRouter "Insufficient credits" errors (a billing outage), not DNS. Additionally, best-of-3 selection partially masks whole-run outages (qwen's 0.0 runs are not the selected best), but those runs still pollute all_runs metadata and any mean/consistency statistics derived from it.

**Evidence:** run2_openrouter_z-ai_glm-5.2.json: 80 instances with generation_error 'RuntimeError: LiteLLM completion failed in child process: APIError: ... OpenrouterException - [Errno 8] nodename nor servname provided, or not known'. run2/run3_openrouter_qwen_qwen3.5-27b.json: 200/200 empty patches with prompt_tokens=0, completion_tokens=0. rerun_fixes_2judge_20260613_232410/best3_anthropic_claude-fable-5.json: gen errors 200/200, all_runs all 0.0. _adapter_error_analysis at run_eval.py:274-281 hard-codes judge_verdict='fail'.

**Recommended fix:** Treat adapter_error/judge_error instances as invalid rather than failed: report pass rate over valid instances plus an invalid_count in AggregateMetrics, refuse to finalize a report whose invalid rate exceeds a threshold (e.g. 2%), and make run scripts re-drive errored instances before writing the final report. Retro-fix stored runs by re-generating only errored/zero-usage instances.

### C25. One-way 'material improvement' merge ratchet cherry-picks reruns and reorders the leaderboard
*Category: statistics · Location: `results/merged_harness_fix_20260620/merge_decisions.json:1`*

Claim is accurate as stated. One clarification: exactly 9 models (not 10) had fixed_passed=0 in the broken rerun batch; qwen3.7-max is a 10th degraded case (57→8) rather than a zero. One addition strengthening the finding: kept-prior rows and accepted-rerun rows in merged_leaderboard.json were judged under different panels (e.g. Codex row judged by claude-opus-4-6 alone; GPT-5.5 row by a 2-judge opus-4.8+gpt-5.5 consensus with adapter_max_attempts=3 and retry_empty_responses=true), so the table mixes harness version, judge panel, and retry policy per row.

**Evidence:** merge_decisions.json: openai/gpt-5.3-codex decision=keep_prior_no_material_improvement prior=45 fixed=75 d_score=-0.0235; anthropic/claude-sonnet-4.6 keep_prior prior=21 fixed=41 d_score=-0.0303; openai/gpt-5.5 update_material_harness_improvement prior=35 fixed=66; moonshotai/kimi-k2.5 prior=13 fixed=39; merged_leaderboard.json material_update_rule={min_mean_score_delta:0.02, min_total_passed_delta:1, requires_both:true, consensus_voting_rule:'pass_on_tie'}; anthropic/claude-fable-5 fixed_passed=0 d_score=-0.4427 (broken rerun).

**Recommended fix:** Never mix old and new harness results in one table. Rerun ALL models on the fixed harness and publish only that batch; if a rerun fails operationally, mark the row as missing rather than substituting the old number.

### C26. 45 of 906 published leaderboard passes are solo-Opus passes awarded after the GPT-5.5 judge errored — up to 31% of a model's pass count
*Category: statistics · Location: `results/merged_harness_fix_20260620/merged_leaderboard.json:1`*

The abstention was decisive whenever Opus voted pass while GPT-5.5 errored: with the errored judge dropped (run_eval.py:422-426) and pass-on-tie voting (run_eval.py:450), the row passes on one vote. In the published merged leaderboard directory this produced 45 solo-Opus passes out of 906 total published passes, concentrated in the 10 panel-judged rows: GPT-5.5 12/66 passes (18%), Kimi K2.5 6/39 (15%), DeepSeek V4 Pro 6/31 (19%), GLM 5.1 5/25 (20%), MiniMax M2.7 5/16 (31%), GLM 5.2 4/18 (22%), Kimi K2.6 3/22 (14%), Qwen 3.5 27B 2/19 (11%), Qwen 3.5 35B A3B 2/20 (10%), Kimi K2.7 Code 0/12. These pass counts flow verbatim into aggregate.total_passed and merged_leaderboard.json rows (verified equal). The rerun_fixes_2judge directory contains 103 more solo-Opus passes, including a same-vendor case: best3_anthropic_claude-sonnet-4.6.json has 13 solo-Opus passes of 23 total (57% of that Anthropic candidate's passes were granted by the Anthropic judge alone after the OpenAI judge errored on 34/200 rows). Because the GPT-5.5 error rate varies by candidate model (1% to 14.5% of rows in the merged dir; 30.5% for gpt-5.3-codex in the rerun dir), models are effectively scored by different judge panels, breaking cross-model comparability. The reverse direction is negligible (Opus errored on only 2 rows total, yielding 1 solo-GPT pass), so the collapse asymmetrically substitutes 'Opus-solo' for 'panel' — and since Opus is the more lenient judge on these rows (148/420 solo decisions were passes vs the panel's overall ~13% pass rate), the bug systematically inflates panel-row pass counts relative to a true two-judge regime where a GPT-5.5 fail vote would have forced a 1-1 tie decided by the pass-on-tie rule anyway — but a GPT-5.5 fail would at least have been recorded; here its opinion simply never existed.

**Evidence:** Computed from results/merged_harness_fix_20260620/best3_*.json: solo-Opus passes per model (row passed AND judge_analyses['openrouter/openai/gpt-5.5'].raw_judge_verdict=='judge_error' AND Opus valid): gpt-5.5 12, kimi-k2.5 6, deepseek-v4-pro 6, glm-5.1 5, minimax-m2.7 5, glm-5.2 4, kimi-k2.6 3, qwen3.5-27b 2, qwen3.5-35b-a3b 2, kimi-k2.7-code 0 = 45; merged_leaderboard.json total_passed sum = 906. Rerun dir: 103 solo-Opus passes incl. best3_anthropic_claude-sonnet-4.6.json 13 of agg_passed=23. Example published row: best3_openai_gpt-5.5.json vulnbench-CVE-2025-43761 — consensus 'pass:1,fail:0,abstain:1', reasoning 'Consensus by pass-tie vote: pass ... Abstentions: 1', GPT-5.5 analysis raw_ju…

**Recommended fix:** Re-run the GPT-5.5 judge with an adequate token budget on all 420 judge_error rows and recompute consensus, aggregates, and the merged leaderboard; publish per-model abstention counts alongside pass counts; consider requiring both judges to render a verdict (or a third tie-breaking judge) before a pass is counted.

## Major findings

### M1. Documented pass rule (verdict pass AND score >= 0.5) is violated by 42 published passes with score < 0.5
*Category: correctness · Location: `benchmark/run_eval.py:609`*

README and the data model document that an instance passes only when verdict=pass AND score >= 0.5, and judge_patch enforces this per-judge. But the consensus path never re-applies the score threshold: evaluate_instance sets `passed = analysis.judge_verdict == "pass"` and combine_judge_analyses derives the verdict purely from vote counts while the consensus score is the median. A 1-1 split of pass(0.6)/fail(0.2) yields verdict=pass with median score 0.4 → passed=True at score 0.4. The published merged leaderboard contains 42 such instances (e.g., 8 in deepseek-v4-pro, 5 in gpt-5.5), so the public numbers contradict the benchmark's own stated acceptance criterion.

**Evidence:** README.md:130 'An instance passes only when the judge returns `verdict="pass"` and `score >= 0.5`'; eval_models.py:34 `passed: bool = False  # score >= 0.5`; run_eval.py:609 `passed = analysis.judge_verdict == "pass"` with no score check; run_eval.py:450 consensus verdict from votes only. Computed: 42 results with passed=true and score<0.5 across results/merged_harness_fix_20260620/best3_*.json.

**Recommended fix:** Enforce the documented invariant at the consensus level: `passed = verdict == "pass" and score >= 0.5` in evaluate_instance (or gate consensus_verdict on median_score >= 0.5 in combine_judge_analyses), re-score stored artifacts, and update the README if the rule intentionally differs for multi-judge runs.

### M2. run_eval.py resume accepts checkpoints from any prior run without config validation
*Category: correctness · Location: `benchmark/run_eval.py:1105`*

With --resume (default true), run_eval.py loads <output>.partial and keeps its results filtered only by instance_id — it never checks that the checkpoint's model, judge_models, file_hint_mode, include_source, benchmark path, or limit match the current invocation. Reusing an output path (e.g., the default results/eval_report.json) after switching model or judge silently produces a report whose metadata names the new configuration but whose results mix instances generated by the old one. Stale results for instances not in the current benchmark are also retained and counted in the aggregate. run_best_of_n has _report_matches_run for exactly this reason, but even that check omits the benchmark identity — a checkpoint from a different 200-instance dataset with equal config would be resumed.

**Evidence:** run_eval.py:1105-1118: `checkpoint = EvalReport(**json.loads(checkpoint_path.read_text())); results = checkpoint.results; completed_ids = {...}` — no metadata comparison; line 1118 `remaining_instances = [i for i in instances if i.instance_id not in completed_ids]` keeps checkpoint rows not in `instances`. Contrast run_best_of_n.py:53-82 _report_matches_run, which checks model/judges/hints/tokens but not metadata['benchmark'] or the instance-id set.

**Recommended fix:** Port _report_matches_run into run_eval.py's resume path and extend both to compare metadata['benchmark'] (or a dataset content hash) and to drop checkpoint results whose instance_id is not in the current instance set; refuse to resume on mismatch instead of warning.

### M3. Regenerating the report from run files silently reverts the re-scored numbers
*Category: correctness · Location: `benchmark/generate_v2_report.py:117`*

combine_completed_best3 rebuilds best3_<model>.json from run1-3 files verbatim, checking only total_instances==200 — not that the three runs share judge config or harness version, and not the current voting rule. Because the run files on disk still carry the OLD tie→fail verdicts while the checked-in best3 files carry re-scored tie→pass verdicts, running `python -m benchmark.generate_v2_report` with defaults (results/ has no merged_leaderboard.json) will overwrite e.g. best3_z-ai_glm-5.2.json (18 passed) with the max of run files showing 8/7/9 passed, and emit a docs/v2.html that contradicts the published docs/index.html. The published numbers are not reproducible from the pipeline as committed.

**Evidence:** generate_v2_report.py:117-147: `if data.get("aggregate", {}).get("total_instances") != 200: return` is the only validation; writes best3 unconditionally. Computed: results/best3_z-ai_glm-5.2.json total_passed=18 vs run1/2/3_openrouter_z-ai_glm-5.2.json total_passed=8/7/9 (splits scored fail). main():417-429 uses merged manifest only if merged_leaderboard.json is in --results-dir; it lives in results/merged_harness_fix_20260620/, not results/.

**Recommended fix:** Store the voting rule in each result's metadata and make report generation re-derive passed/pass_rate from per-judge analyses under the declared rule (one code path for run files and best3 files). Validate config equality across the three runs before combining, and fail loudly instead of overwriting on mismatch.

### M4. No mechanical validation of candidate patches: apply_patch(dry_run) exists but is never called; judge sees only diff text
*Category: correctness · Location: `benchmark/source_manager.py:98`*

The claim is fully correct except one overstatement: "no ground-truth signal anywhere in the pipeline" — the gold fix-commit diff IS shown to the judge as a reference (run_eval.py:306-309), so a ground-truth artifact exists in the loop. The accurate statement is that there is no MECHANICAL ground-truth signal: no apply check (apply_patch at source_manager.py:98 is dead code with dry_run support and zero callers), no compile, no tests, and non-diff prose can reach the judge via the run_eval.py:262 fallback. All cited file:line references verified as stated.

**Evidence:** source_manager.py:98 `def apply_patch(source_dir, patch_text, dry_run: bool = False)` — zero call sites outside its definition. run_eval.py:262 `return output.strip()` (whole model output treated as the patch). Judge user prompt (run_eval.py:296-316) contains only CVE metadata + gold diff + candidate diff, never the repo source.

**Recommended fix:** Gate judging on `apply_patch(source_dir, model_patch, dry_run=True)` against the already-downloaded source snapshot; record applies_cleanly per instance and either fail or separately report non-applying patches. Where feasible, add per-ecosystem syntax checks on patched files.

### M5. Truncation is never recorded: finish_reason is captured by the adapter but dropped from results
*Category: correctness · Location: `benchmark/eval_models.py:22`*

Claim is accurate as stated. One addendum: the shipped run1_* result files were produced by an older schema and lack even adapter_attempts/empty_response_attempts/reasoning_tokens (results contain only 13 fields), so for the published new-suite numbers the only truncation signal is the circumstantial completion_tokens==cap pattern (e.g. kimi-k2.6 run1: 163 of 164 empty patches have completion_tokens >= 4096, the adapter default max_tokens per litellm_adapter.py:168).

**Evidence:** eval_models.py:22-46 InstanceResult fields — no finish_reason/truncated; run_eval.py:575-586 copies prompt/completion/reasoning tokens and attempt counters from adapter meta but not meta['finish_reason'] which litellm_adapter.py:499 provides; audit_empty_patches.py:88-92 comment about ambiguous empties.

**Recommended fix:** Persist finish_reason (and used_reasoning_content, content_chars, last_error) into InstanceResult; flag finish_reason=='length' instances as truncated in aggregates and in the new 'why did this model do poorly' output.

### M6. Published rows are not reproducible: unversioned dataset, undisclosed generation params, undocumented merge pipeline
*Category: correctness · Location: `README.md:174`*

Claim is accurate with two refinements. First, the dataset-revision ambiguity is worse than stated for the old suite: results/best3_gpt-5.3-codex.json (evaluated 2026-03-09, pre-sanitization) and full_openai_gpt-5.3-codex.json (2026-03-21, post-sanitization) reference the identical benchmark path but ran against different dataset contents, so old-suite rows are mutually incomparable, not merely unprovable. Second, the "no harness SHA" gap is partially acknowledged in the repo: an untracked benchmark/provenance.py already computes harness git SHA (with -dirty suffix) and dataset_sha256, but is only imported by rejudge.py — it is not wired into run_eval.py/run_best_of_n.py and no published result carries its fields. The new-suite June leaderboard runs all postdate the dataset mutation, which is why this is major (reproducibility/defensibility) rather than critical (published numbers not shown to be biased).

**Evidence:** git log for data/benchmark/vulnbench_200.json: 8fb1c05 2026-03-18 modifies it with no filename version bump. results/best3_openai_gpt-5.5.json metadata keys lack max_tokens/temperature; rerun metadata adds max_tokens: 4096, adapter_max_attempts: 3, retry_empty_responses: true — proving config drift between published rows. README Setup/Run sections (163-199) never mention temperature, max_tokens, reasoning, dataset hash, or the merge script.

**Recommended fix:** Ship versioned dataset releases (vulnbench_200-v2.0.json + SHA-256 in README), stamp every result with dataset hash, harness git SHA, and full generation params, document the exact command chain that produced each published table, and add expected API cost estimates.

### M7. Diff extractor grabs the wrong fenced block and misses non-unified formats; 1,922 non-diff 'patches' were judged
*Category: correctness · Location: `benchmark/run_eval.py:236`*

The count of non-empty extracted patches containing no diff marker (no 'diff --git', no '@@', no ---/+++ pair) across results/run*_openrouter_*.json is 1,252, not 1,922 (108 files, 15,589 non-empty patches; 1,192-1,277 depending on marker definition). Per-model figures are accurate: gemini-3.5-flash 162/164/165 per run (run1: 0 of 162 passed, many are raw chain-of-thought prose stored as the patch); gpt-5-mini V4A '*** Begin Patch' output in 195/200/197 patches per run with 9/10/9 passing; gpt-5.4 (11-13/run) and gpt-5.4-mini (31-34/run) also emit V4A. First-fence extraction bug and absence of raw_output persistence in InstanceResult (eval_models.py:22-46) are confirmed as claimed.

**Evidence:** run_eval.py:236-242 fence regex; run_eval.py:262 fallback return output.strip(). Reproduced first-fence bug: extractor returned 'And here is the fix:' for an output whose real ```diff block came after a ```python block. Counted 1,922 non-diff-marker non-empty model_patch values across results/run*_openrouter_*.json; run2_openrouter_openai_gpt-5-mini.json: 200/200 patches in '*** Begin Patch/*** Update File:' format, 10 passed; run1_openrouter_google_gemini-3.5-flash.json: 162 non-diff extractions, 0 passed.

**Recommended fix:** Extract the LAST (or all) fenced blocks and pick the one containing diff markers; recognize '*** Begin Patch' V4A and bare ---/+++/@@ hunks; persist raw_output (or at least a hash + first/last 2KB) in InstanceResult so extraction can be audited; add unit tests for preamble-block, multi-fence, and V4A outputs.

### M8. Judge abstention is invisible in aggregate/metadata and retries never escalate the token budget
*Category: correctness · Location: `benchmark/run_eval.py:777`*

Mechanisms confirmed as claimed (constant max_tokens=1024 across retries at run_eval.py:331; no judge-health fields in AggregateMetrics at 777-790 or build_report metadata at 828-854; vote_summary at 456-462 iterates all analyses including errored ones). Corrected numbers: the example row is vulnbench-CVE-2026-27210 in results/run1_openrouter_z-ai_glm-5.2.json (raw_judge_verdict 'pass:0,fail:1,abstain:1', reasoning shows 'openrouter/openai/gpt-5.5: fail (0.0000)'), not CVE-2025-43761. Abstention counts: 66/800 (8.25%) of panel rows in top-level new-suite 2-judge files, 812/20000 (4.06%) in rerun_fixes_2judge_20260613_232410, 1022/22800 (4.48%) across all result files — not 420/7.15%. All abstentions come from the gpt-5.5 judge; 63/66 top-level errors are 'Expecting value: line 1 column 1 (char 0)' (empty content from reasoning-token exhaustion at max_tokens=1024, deterministic at temp 0.0). Judge cost on affected rows is ~$8.77 (new suite) / ~$136 (all files, mean ~$0.133/row), not $47.16; only the 2 wasted retries per row are strictly 'wasted' cost.

**Evidence:** run_eval.py:109 'JUDGE_MAX_ATTEMPTS = 3'; run_eval.py:331 '"max_tokens": JUDGE_MAX_TOKENS' (constant across attempts, no per-attempt escalation anywhere in the loop at lines 321-388); AggregateMetrics fields at run_eval.py:777-790 (total_instances, total_passed, pass_rate, mean_score, pass_rate_by_tier, pass_rate_by_ecosystem, mean_generation_time_s, cost/token totals — nothing judge-health related); run_eval.py:456-462 vote_summary comprehension over 'analyses.items()' (not voting_analyses), producing 'openrouter/openai/gpt-5.5: fail (0.0000)' in the CVE-2025-43761 example while raw_judge_verdict says 'abstain:1'; computed waste: 420 errored rows x mean $0.1123 = $47.16.

**Recommended fix:** Escalate max_tokens (e.g. 1024 -> 4096 -> 16384) on empty-content/parse-failure retries; add judge_error/abstention counts per judge to AggregateMetrics and report metadata, and fail loudly (or flag the run) when abstention exceeds a threshold; build vote_summary from voting_analyses and label dropped judges as 'abstained' rather than 'fail (0.0000)'.

### M9. 8.5% of curated instances have empty vulnerability descriptions, capping achievable pass rates
*Category: dataset · Location: `data/benchmark/vulnbench_200.json:1`*

Claim is fully accurate as stated. Additional supporting evidence: across the 36 run1 result files, aggregate pass rate on the 17 empty-description instances is 1.5% (9/612) vs 8.8% (577/6588) on the remaining 183, and the rare passes occur only on top-tier models — empirically confirming the tasks are near-unsolvable without prior CVE knowledge.

**Evidence:** Computed: 17/200 instances where task_prompt['vulnerability_description'].rstrip().endswith('Description:'), including vulnbench-CVE-2025-6773, vulnbench-CVE-2016-15025, vulnbench-CVE-2020-36629, vulnbench-CVE-2024-9440, vulnbench-CVE-2018-1000534. All 200 instances have affected_files_hint=[].

**Recommended fix:** Either backfill descriptions from NVD/GHSA for these 17 instances, or drop them from the curated set in a versioned v2.1 release; document the instance-level quality bar in the README.

### M10. Source context is absent for ~78% of instances despite include_source=True; gold hint mode is inert
*Category: dataset · Location: `benchmark/run_eval.py:112`*

In the default file_hint_mode='description', source files are located only via DESCRIPTION_FILE_RE matches in the advisory text (derive_description_files, run_eval.py:637-647). Only 45 of 200 instances in vulnbench_200.json have a description that names any source file, so at most 22.5% of tasks can ever receive source context; observed prompt_tokens confirm it (run3 gpt-5.5: only 33/200 instances above 800 prompt tokens, median 270; the reported prompt_tokens=253 case is simply a context-free prompt). Additionally task_prompt.affected_files_hint is empty for ALL 200 instances, so the documented 'gold' mode (run_eval.py:1013 'uses dataset affected_files_hint derived from the fix') would provide zero hints and zero context. This is uniform across models, so it is not a fairness bug, but every report's metadata says include_source=true while ~4 out of 5 tasks were description-only — a skeptical reviewer measuring prompt tokens will conclude the benchmark does not do what its metadata and README claim, and 'why models fail' analyses will misattribute failures on context-free instances to the model.

**Evidence:** Computed from data/benchmark/vulnbench_200.json: 200/200 have download_url, 45/200 descriptions match DESCRIPTION_FILE_RE (run_eval.py:112-114), 0/200 have non-empty affected_files_hint. results/run3_openrouter_openai_gpt-5.5.json: 33/200 instances with prompt_tokens>800, min 160, median 270. SOURCE_CONTEXT_CHAR_LIMIT=6000 (run_eval.py:107) would be ~1500 tokens if present.

**Recommended fix:** Populate affected_files_hint from the gold patch for every instance (it is derivable from gold_patch.raw_diff), record a per-instance source_context_chars/source_files field in InstanceResult, and report the with-context vs without-context split. If most instances are intentionally description-only, say so in the README and metadata instead of include_source=true.

### M11. Difficulty tiers are not empirically valid: tier_2 is an 88% default bucket and pass rates are flat or inverted across tiers
*Category: dataset · Location: `src/benchmark_generator.py:203`*

The claim is confirmed with one nuance: 'pass rates are flat or inverted across tiers' holds for the cited top models but is not universal — many weaker/mid models in the run1 suite do show tier_1 easiest and tier_3 hardest (e.g. qwen3.7-max 26.9%/7.5%/0.0%, run1 opus-4.6 19.4%/14.9%/1.5%, gpt-5.3-codex on the 200-set 17.9%/7.5%/0.0%). The accurate statement: tier ordering is inconsistent across models (26/36 run1 models violate strict tier1>tier2>tier3), and it fails precisely for the strongest models headlining the leaderboard. The structural defect — tier_2 is 87-88% a default bucket of unmapped CWEs mislabeled as 'Logic (auth checks, CSRF tokens)' in README.md:279, with the full-set distribution 354/1106/190 — is fully confirmed as stated.

**Evidence:** benchmark_generator.py:64-66 (only 10 CWEs across TIER_1/2/3 sets), :203-205 default-to-tier_2. Computed: 200 set tier_2 n=67, only 8 (12%) carry a mapped tier-2 CWE; full tier_2 n=1106, 145 (13%) mapped. Full tier distribution 354/1106/190 vs README 'Balanced'. Pass-by-tier computed from results/full_anthropic_claude-opus-4.6.json, results/full_openai_gpt-5.3-codex.json, results/best3_anthropic_claude-fable-5.json (numbers above). README.md:276-280 tier table.

**Recommended fix:** Either validate tiers empirically (fit tier against observed per-instance pass rates across the 16-model suite and relabel) or rename them to what they are (CWE-category buckets, with an explicit 'other' tier), and drop 'deep reasoning' difficulty language from the README; report per-CWE pass rates instead in the new explanatory output.

### M12. Contamination is unmeasured while the prompt includes the CVE ID — and the leaderboard winner shows a contamination-consistent year signature
*Category: dataset · Location: `src/benchmark_generator.py:232`*

One clarification: the pooled run1-3 fable-5 figure "173/459=38%" is the 2022-2025 subset specifically (overall pre-2026 is 206/552=37.3% vs 2026 14/48=29.2% — same direction). All other numbers reproduce exactly as claimed.

**Evidence:** benchmark_generator.py:232-234: `vuln_desc = (f"CVE: {record.cve_id}\n" f"Package: {record.package_name} ({record.ecosystem})\n" ...)`. Year distribution (full): 2013-2021 = 167, 2022-2025 = 1304, 2026 = 179. Computed from results: best3_anthropic_claude-fable-5.json — pre2022 29%, 2022-2025 41%, 2026 19%; pooled run1-3 fable-5: 173/459=38% vs 14/48=29%. GHSA advisory IDs (another lookup key) also survive sanitization in 23 full / 3 curated descriptions (e.g. CVE-2026-23946 contains 'GHSA-jqmc-fxxp-r589').

**Recommended fix:** Publish a per-model pass-rate-by-CVE-year (pre/post training cutoff) breakdown as part of the planned 'why did this model perform well' output; run an ablation with CVE IDs and package names redacted from prompts on a subsample to bound memorization; consider a rolling post-cutoff subset (e.g. 2026-only) as the headline contamination-resistant number; strip GHSA IDs in the sanitizer.

### M13. ~44% of 'vulnerable' source snapshots are not the pre-fix code; ~11% already contain the gold fix
*Category: dataset · Location: `src/version_finder.py:101`*

Measured over all 1599 cached snapshots with stricter contiguous-block matching: ~27% are not clean pre-fix code (5.9% already contain the gold fix, 11.8% mixed, 5.1% match neither side, 4.2% missing all patched files) — not 44%/11%. The cited example CVE-2022-1233 is a false positive of the reviewer's per-line method (its v1.19.10 snapshot lacks the actual fix and is genuinely pre-fix); genuine post-fix examples include CVE-2022-23494, CVE-2023-6395, CVE-2025-5896, CVE-2023-49796. Exposure figures confirmed: all 108 run files used include_source=true with description-mode hints; 25/200 curated instances get context (17 pre_fix, 4 mixed, 2 post_fix, 2 files-missing); CVE-2023-49796 shows the gold-fixed file verbatim in-prompt but passed only 7/108 runs vs 9.1% baseline, so published numbers show no measurable inflation. The code claims (version_finder.py:104-109 unvalidated tag guess with immediate break; :415-419 second-tag fallback) are accurate, and the proposed fix (validate snapshots against the gold patch pre-image, or download {fix_sha}~1 archives, plus a snapshot_verified flag) is sound.

**Evidence:** Sample of 200 cached snapshots: pre_fix 113 (56%), post_fix 22 (11%), mixed 59 (30%), file_missing 6 (3%). Post-fix examples: vulnbench-CVE-2022-1233 (snapshot v1.19.10 contains 91% of gold added lines, 0% of removed lines — the 'vulnerable' snapshot IS the patched release), vulnbench-CVE-2025-5896 (rem 0.0/add 1.0), vulnbench-CVE-2021-4435 (0/1.0), vulnbench-CVE-2023-42505 (0/1.0). Code: version_finder.py:104-109 'Try common tag prefixes... break # Use "v" prefix as most common' — URL never validated; version_finder.py:416-419 'Fallback: if patched version given but couldn't parse, use second tag'.

**Recommended fix:** Validate every snapshot at build time: the gold patch's pre-image lines must be present (and post-image absent) in the downloaded tree; otherwise walk tags/commits to the true parent of the fix commit (e.g. download github.com/{repo}/archive/{fix_sha}~1.tar.gz, which is exact by construction). Record a `snapshot_verified` flag per instance and exclude unverified ones from source-context modes.

### M14. 8.9M characters of third-party patch code redistributed with zero license metadata, including AGPL/LGPL and unlicensed repos
*Category: dataset · Location: `data/benchmark/vulnbench_full.json:1`*

gold_patch.raw_diff embeds verbatim code hunks copied from third-party repositories: 8,939,953 chars / 195,287 diff lines in vulnbench_full.json (duplicated again in the tracked checkpoint file for ~17.9M chars total in the repo), 545,198 chars / 13,124 lines in vulnbench_200.json, 117,346 chars / 2,896 lines in vulnbench_mini.json. No instance carries a license or attribution field. A live license sweep of 18 randomly sampled repos from vulnbench_200's 200 unique repos found: 1 AGPL-3.0 (OctoPrint/OctoPrint — 8 instances / 43,404 chars of diff in the full set), 1 LGPL-3.0 (Mayuri-Chan/pyrofork), 1 repo with NO license file at all (johnpapa/generator-hottowel — default all-rights-reserved, redistribution not permitted), and 2 NOASSERTION/custom (nodemailer/nodemailer, DedSecInside/TorBot); the remaining 13 were MIT/Apache-2.0/BSD-3-Clause, which still require preservation of the copyright notice and license text that the dataset omits. Extrapolating the sample (~5.5% copyleft, ~5.5% unlicensed), roughly 90+ of the 1,650 full-set instances likely redistribute copyleft or unlicensed code. Industry-standard datasets (The Stack, BigCode) ship per-file license metadata precisely to make this defensible; VulnBench ships none.

**Evidence:** Computed: raw_diff totals above from the tracked JSON files. `gh api repos/<r>/license --jq .license.spdx_id` results: OctoPrint/OctoPrint=AGPL-3.0, Mayuri-Chan/pyrofork=LGPL-3.0, johnpapa/generator-hottowel=404 (no license), nodemailer/nodemailer=NOASSERTION, DedSecInside/TorBot=NOASSERTION; MIT: fgribreau/node-request-retry, selfcontained/deap, DarrenOfficial/dpaste, imbrn/v8n, mscdex/dicer, brianvoe/slim-select, Coding-Solo/godot-mcp, libxmljs/libxmljs, Flow-Scanner/lightning-flow-scanner; Apache-2.0: apache/streampipes, FunAudioLLM/InspireMusic, parse-community/parse-server; BSD-3-Clause: kjd/idna. AGPL diff volume in tracked files: full set 43,404 chars / 952 lines across 8 OctoPrint in…

**Recommended fix:** Add a per-instance `source_license` (SPDX id fetched via the GitHub license API at build time) and `attribution` field; drop or replace instances from unlicensed repos (no-license = no redistribution right); for copyleft repos either exclude the instances from redistributed artifacts (ship a fetch-at-eval-time pointer using the already-present commit_sha/github_repo_url instead of raw_diff) or ensure the dataset release complies with AGPL/LGPL notice requirements; add a NOTICE aggregating all upstream licenses.

### M15. CC-BY 4.0 attribution obligations for embedded GitHub Advisory Database text are unmet (and the text is modified)
*Category: dataset · Location: `data/benchmark/vulnbench_full.json:1`*

Confirmed as stated, with two immaterial corrections: the release-time sanitizer is at benchmark/sanitize_dataset.py:81 (claim cited it without the benchmark/ directory prefix), and README.md's License section does name the GitHub Advisory Database as a source — so partial source attribution exists; the specific unmet CC-BY 4.0 obligations are the license notice/URI and the indication of modification (plus per-instance advisory-level attribution), none of which appear anywhere in the repo (0 grep matches; no LICENSE/NOTICE file).

**Evidence:** Source of text: src/ghsa.py:64 `description = adv.get("description", "")` populated from `_gh_api("/advisories", ...)` (src/ghsa.py:169); prompt assembly src/benchmark_generator.py:228-238 (`description = scrub_advisory_text(record.description ...)`, `vuln_desc += f"\n\nDescription:\n{description}"`). Upstream license verified live: `gh api repos/github/advisory-database/license` -> "CC-BY-4.0 Creative Commons Attribution 4.0 International". Modification evidence: scrub_advisory_text defined at src/benchmark_generator.py:260; sanitize_dataset.py:81 `cleaned = COMMIT_HASH_RE.sub("[redacted]", line)`; 209/6/2 '[redacted]' occurrences in vulnbench_full/200/mini. README.md:312 names the source b…

**Recommended fix:** Add a per-instance provenance block (e.g. `source: {advisory: GHSA-xxxx, url, license: "CC-BY-4.0", modified: true}`) and a top-level NOTICE stating the descriptions derive from the GitHub Advisory Database under CC-BY 4.0 and have been modified (redaction of fix pointers). Surface the same notice in README and both docs pages.

### M16. README leaderboards and Key Findings contradict the published site
*Category: docs · Location: `README.md:13`*

The claim is accurate but omits one mitigating detail: README.md:5 explicitly states 'The published results below cover the previous 16-model suite', so the README does self-label its tables as the prior suite rather than silently presenting them as current. However, the Key Findings paragraph (line 13) still declares GPT-5.3 Codex 'the best model' without qualification, the Best Value Models table and 1650 section are stale relative to the 21+ new models in results/, and the README never links to or mentions the current 37-model results shown on the published site — so a reviewer comparing repo and site still sees two different winners and model sets. The 'under 4%' median claim is contradicted by the README's own table (median 4.2%).

**Evidence:** README.md:13 and :21 ('GPT-5.3 Codex 22.5%... 45/200') vs docs/index.html leaderboard row 1 'Claude Fable 5 | Anthropic | 37.5% | 0.443 | 75/200' and footer 'Generated 2026-06-23 02:53 UTC'; git log 182cd46 2026-06-20.

**Recommended fix:** Regenerate the README leaderboard from the same source of truth as docs (or link to it), label each table with harness/judge version and date, and archive the old-suite tables under a clearly dated 'V1 (March 2026)' heading.

### M17. Dataset table presents 200-subset statistics under the 1,650-benchmark heading, with wrong numbers
*Category: docs · Location: `README.md:85`*

All claimed numbers verified as stated. Minor clarification: the "full has 240 unique CWEs" figure corresponds to the union over the cwe_ids field (240); counting only primary_cwe gives 207 for the full set and 48 for the subset — the README's "55 unique" matches the subset's cwe_ids union, so it is unambiguously a subset-only value either way.

**Evidence:** README.md:89-93 quoted values vs computed from data/benchmark/vulnbench_full.json: severity {medium: 988, high: 448, critical: 214}, tiers {tier_1: 354, tier_2: 1106, tier_3: 190}, 240 unique CWEs, mean 69.07 lines / 3.18 files; vulnbench_200.json: CWE-94=18, CWE-1333=2, 2024-2026 share 59.5%.

**Recommended fix:** Split the table into two columns (VulnBench-200 / VulnBench-1650) with per-column values generated by a script from the dataset files, and regenerate the CWE table from primary_cwe counts.

### M18. Judge model stated as Opus 4.6 in one section and Opus 4.8 in another
*Category: docs · Location: `README.md:125`*

README.md:125 ('Claude Opus 4.6') contradicts README.md:241 ('Claude Opus 4.8'), and run_eval.py's docstring (line 3, 'Claude Opus 4.6') contradicts its code default (line 68, opus-4.8). Result artifacts really span both judges: all README-published rows (best3_gpt-5.3-codex.json and all 18 full_*.json) have judge_model 'openrouter/anthropic/claude-opus-4-6', while June new-suite rows use 'openrouter/anthropic/claude-opus-4.8'. However, the README's own 200-vs-1650 'ranking reversal' narrative is NOT cross-judge — both README leaderboards are entirely opus-4-6-judged. The undisclosed cross-judge comparison occurs in the merged docs/index.html leaderboard, which ranks 37 models mixing opus-4-6-judged rows (e.g. GPT-5.3 Codex, 0.468 mean score) with opus-4.8-judged rows (e.g. Fable 5, GPT-5.5) in one table that has no judge column; the page says 'Judge: see row metadata' but the HTML contains no per-row judge metadata at all, and some new rows also use a different acceptance rule (split two-judge vote passing when either judge accepts).

**Evidence:** README.md:125 '(Claude Opus 4.6)'; README.md:241 'default judge is Claude Opus 4.8'; benchmark/run_eval.py:3 docstring 'Claude Opus 4.6' vs :68 JUDGE_MODEL = 'openrouter/anthropic/claude-opus-4.8'; results/best3_openai_gpt-5.3-codex.json metadata judge_model='openrouter/anthropic/claude-opus-4-6' vs results/best3_anthropic_claude-fable-5.json judge_model='...claude-opus-4.8'.

**Recommended fix:** State one pinned judge (model slug + provider + date) per published table, fix README:125 and the run_eval.py docstring, and add the judge id as a visible column or footnote on every leaderboard.

### M19. Docs claim 'Judge: see row metadata' but the leaderboard renders no judge or source column
*Category: docs · Location: `benchmark/generate_v2_report.py:306`*

Claim is fully accurate; one understatement: the 27 prior_baseline rows are not one regime but two — 14 rows judged by claude-opus-4-6 and 13 by claude-opus-4.8 — so the leaderboard silently mixes three judge regimes (opus-4-6 single, opus-4.8 single, opus-4.8+gpt-5.5 either-accepts vote), while the only methodology sentence shown describes just the most lenient regime (10 rows) and the promised per-row judge metadata does not exist in the HTML.

**Evidence:** generate_v2_report.py:306 judge_desc '...A split two-judge vote passes when either judge accepts the patch.'; :343 'Judge      see row metadata'; leaderboard_html at :233-252 contains no source/judge cell; markdown_table at :256 has the Source column.

**Recommended fix:** Add the source/judge column to leaderboard_html (the Row.source field already exists) and rewrite judge_desc to describe both regimes with row counts.

### M20. No per-model 'why did it win/lose' report, and key attribution fields are missing from 27 of 37 published rows
*Category: docs · Location: `benchmark/generate_v2_report.py:233`*

Directionally correct with two corrections. (1) benchmark/model_report.py now exists (untracked, created 2026-07-23 12:48 by a concurrent agent — absent from the committed codebase the claim describes) and implements most of the proposed per-model "why" report: breakdowns by CWE/tier/ecosystem/severity/CVE-year with Wilson CIs, a 9-mode failure taxonomy, judge-reasoning clustering, cost/latency percentiles, and a generated narrative. The remaining unremediated gaps are: the file is uncommitted and not wired into the published report pipeline; finish_reason is captured in litellm_adapter.py (:65, :86, :452, :499) but never persisted to any result row, forcing model_report.py to infer truncation heuristically (completion_tokens >= 0.98 * max_tokens); raw completions are still discarded; and 27 of 37 merged_leaderboard.json rows (verified: 27 prior_baseline vs 6 fixed_harness + 4 fixed_harness_new_model) lack generation_error/retry/reasoning_tokens fields, so failure attribution for those rows cannot distinguish truncation vs refusal vs API failure without rerunning them. (2) Source-context inclusion is recorded at run level (metadata.include_source, file_hint_mode in both old and new files), contrary to the claim's "nothing records" wording — only per-row source-context detail is missing.

**Evidence:** Old-row keys: ['instance_id','cve_id','difficulty_tier','ecosystem','model_patch','generation_time_s','patch_analysis','score','passed','prompt_tokens','completion_tokens','cost_usd','judge_cost_usd'] (results/best3_openai_gpt-5.5.json) — no finish_reason/generation_error/raw output. New-row keys add generation_error, adapter_attempts, empty_response_attempts, exception_attempts, reasoning_tokens (results/rerun_fixes_2judge_20260613_232410/best3_openai_gpt-5.5.json). litellm_adapter.py:65 'finish_reason: str = ""' captured but not stored by run_eval.

**Recommended fix:** Add benchmark/model_report.py emitting per model: pass rate by CWE family, tier, ecosystem, severity, CVE year, and gold-patch-size bucket (with n and CI per cell); a failure taxonomy (empty/truncated patch via finish_reason, adapter_error via raw_judge_verdict, wrong-file via path comparison with gold_patch, partial-fix/wrong-root-cause via judge_reasoning keyword clustering); cost and latency p50/p90; and a generated strengths/weaknesses narrative. Prerequisite harness change: persist finish_reason, raw completion (or a truncation flag), generation_error, retry counts, reasoning_tokens, and source-context stats on every row.

### M21. No license grant anywhere in a repo advertised for public release
*Category: docs · Location: `README.md:310`*

There is no LICENSE, NOTICE, or COPYING file in the repository (`git ls-files | grep -iE 'licen|notice|copying'` returns nothing, exit 1; none present in the root listing). The README's '## License' section is a two-sentence provenance description, not a license grant: it conveys no rights to use, copy, modify, or redistribute the code or data. Under default copyright, downstream researchers who clone github.com/vulnbench/vulnbench (the URL the citation block at README.md:306 points to) have no legal permission to run or redistribute the benchmark, and vendors' legal teams will flag it. 'Provided for research purposes' is not a recognized license and satisfies no obligation owed to upstream content owners either.

**Evidence:** README.md:310-312: "## License\n\nThis project is provided for research purposes. The CVE data is sourced from public databases (GitHub Advisory Database, NVD). Benchmark instances reference publicly available open-source repositories." `git ls-files` output contains no license-like file. docs/index.html and docs/v2.html contain 0 matches for license/attribution/CC-BY/copyright (grep -c = 0 for both).

**Recommended fix:** Add a LICENSE file: e.g. Apache-2.0 or MIT for the harness code, and an explicit data license statement (CC-BY 4.0 is the natural choice given the GHSA inheritance) for data/benchmark/*.json, plus a NOTICE file covering third-party content. Mirror the statement in docs/index.html and docs/v2.html footers.

### M22. Infrastructure failures scored as model failures; GLM-5.2 uniquely penalized and uniquely configured
*Category: fairness · Location: `benchmark/run_eval.py:592`*

Infrastructure errors are scored as model fails (run_eval.py:592-601 via _adapter_error_analysis, judge_score=0.0/verdict fail; compute_aggregate keeps them in the denominator) and GLM-5.2 is the only affected model: 106/600 run-file results (26/80/0 across runs 1-3) and 26/200 rows of the published best3 file are adapter errors labeled as fails. But the published 18/200 is NOT substantially an availability artifact: best-of-n picks a whole run (run_best_of_n.py:352-356), the winning run's clean-instance pass rate is 18/174 = 10.3% vs 9.0% published (~1.3pp), the fully error-free run3 scored 8% under the same 2-judge config, and 24 of the 26 errored instances also failed cleanly in both other runs. The material fairness/defensibility issues are: (1) undisclosed errors-as-fails policy, (2) GLM effectively got best-of-2 on 106/200 instances while competitors got true best-of-3, and (3) GLM-5.2 is the only model run with reasoning disabled (litellm_adapter.py:30-34 DEFAULT_REASONING_DISABLED_BY_MODEL; only best3 row with reasoning_exclude=true) — a per-model config divergence competitors can dispute in both directions.

**Evidence:** run_eval.py:592-601 routes generation_error to _adapter_error_analysis (judge_score=0.0, verdict fail) and includes it in results; compute_aggregate divides by all results. Computed: generation_error on 106/600 results across run[123]_openrouter_z-ai_glm-5.2.json (no other model >0); best3_z-ai_glm-5.2.json has 26 generation_error instances of 200, total_passed=18. litellm_adapter.py:30-34 `DEFAULT_REASONING_DISABLED_BY_MODEL = {"openrouter/z-ai/glm-5.2"}`.

**Recommended fix:** Report an infrastructure-error rate per row and either rerun errored instances until clean (bounded), or publish pass rate over successfully-generated instances alongside the strict rate. Apply reasoning configuration uniformly (or disclose per-model overrides in the leaderboard row metadata).

### M23. Infrastructure failures are scored as model failures (adapter 402s, judge errors), and panel abstentions silently degrade to single-judge decisions
*Category: fairness · Location: `benchmark/run_eval.py:274`*

One attribution detail is off: the published run1 GLM-5.2 file was generated under the older fail-on-tie rule ('pass_votes > fail_votes' — all 10 pass:1,fail:1 rows resolved as fail, one with median score 0.875), and commit 03e9aae later changed run_eval.py:450 to '>=' (pass-on-tie), which governs current/future runs. The lone-judge conclusion is unaffected since a 1-0 vote passes under either rule; in the published data all 4 lone-judge passes were final and constitute half of GLM-5.2's 8 total passes. Also, the 132 published error rows are entirely GLM-5.2 rows (26/80/26 across run1/run2/best3), so the infra-as-model-failure penalty falls on exactly one vendor in the published leaderboard.

**Evidence:** run_eval.py:274-281 `_adapter_error_analysis` → judge_verdict='fail', raw='adapter_error'; 399-407 judge_error → fail/0.0. Computed: 132 generation_error rows across published results; run1_openrouter_z-ai_glm-5.2.json verdict dist includes 'pass:0,fail:1,abstain:1': 12 and 'pass:1,fail:0,abstain:1': 4; rerun best3_anthropic_claude-fable-5.json: 200/200 generation_errors ('Insufficient credits', code 402) all scored fail.

**Recommended fix:** Track adapter/judge errors as excluded instances (or hard-fail the run above a small threshold, e.g. >2% errors), report an infra-error rate per published row, and require a minimum quorum of non-abstaining judges (e.g. both of 2, or 2 of 3) for a verdict to count.

### M24. Per-model adapter branch: reasoning silently disabled only for GLM-5.2
*Category: fairness · Location: `benchmark/adapters/litellm_adapter.py:30`*

DEFAULT_REASONING_DISABLED_BY_MODEL contains exactly one model, 'openrouter/z-ai/glm-5.2', which gets reasoning:{enabled:false,exclude:true} injected by default (litellm_adapter.py:202-209, 341-351). No other model gets any reasoning normalization, including models with the identical failure mode (gpt-5.5, kimi-k2.6, stepfun, minimax all burned the 4096 budget on hidden reasoning — see the truncation finding). This is a per-model generation-parameter branch in the shared harness: GLM-5.2 was benchmarked as a non-reasoning model while every competitor ran with reasoning on. Whichever direction it moves the score, it makes 'GLM-5.2 vs X' incomparable, and the mitigation being applied to only one vendor is exactly what an external reviewer will call selective treatment.

**Evidence:** litellm_adapter.py:30-34: DEFAULT_REASONING_DISABLED_BY_MODEL = { 'openrouter/z-ai/glm-5.2' } with comment 'GLM 5.2 defaults to hidden reasoning... can consume the whole response budget'. All 3 glm-5.2 run files show reasoning_exclude=true on all 200 instances; all other models' runs show reasoning_exclude=false/absent. Meanwhile run1_openrouter_openai_gpt-5.5.json shows the same empty-at-cap symptom (127/200) with no mitigation.

**Recommended fix:** Remove the per-model set. Apply one policy to every model: either explicitly disable reasoning for all, or give all models a uniform reasoning budget that does not starve the answer. If a model needs special handling to function at all, disclose it in the report metadata as a protocol deviation.

### M25. Fix-description leakage survives the sanitizer in prompt-visible descriptions, including in the published 200 set
*Category: fairness · Location: `benchmark/sanitize_dataset.py:72`*

All qualitative claims and quoted examples confirmed verbatim. Corrected counts (anchored-regex, per-instance): full set retains 26 "### Remediation", 18 "## Fix", 17 "## Patches", 18 "## Workarounds", 15 "## References", 10 "## Remediation", 11 "Upgrading to version X", 13 "fixed/resolved by"; 200 set retains 2 "### Remediation", 3 "## Patches", 2 "## References", 2 "## Remediation", 2 "fixed/resolved by", 1 "Upgrading to version". Additional confirmed impact: CVE-2026-24489 (full set) retains the complete fix function source code in a fenced block, and the ~10 leaky 200-set instances pass at 13% vs 8% overall across 36 run1 models, with pass counts ranging 0/10 to 5/10 per model.

**Evidence:** Counts computed from the shipped JSONs: full set retains 28 '### Remediation', 24 '## Fix', 17 '## Patches', 17 '## Workarounds', 15 '## References', 10 '## Remediation' sections; 16 'Upgrading to version X' and 15 'fixed/resolved by <fix description>' phrases. 200 set: 2 '### Remediation' (CVE-2025-64495, CVE-2017-1000220), 3 '## Patches' (e.g. CVE-2025-68115), 3 'fixed by <fix description>' (e.g. CVE-2024-32472), 2 'Upgrading/Update to version X' (CVE-2025-9654: 'Upgrading to version 1.0.4 and 1.1.0 can resolve this issue'). Code gaps: sanitize_dataset.py:10-20 header set lacks 'remediation'/'resources'/'resolution'; :72 anchors on '### ' only; :26 `\bupgrade to\b` requires exactly one spa…

**Recommended fix:** Match headers at any markdown level with `^#{1,6}\s*(patch(es)?|fix(es)?|remediation|solution|mitigation|workarounds?|references|resources)\b`, add 'remediation' to the set, use `\s+` in phrase regexes, extend SCRUB_REPLACEMENTS to cover 'fixed/resolved/patched by <clause>' and 'upgrad(e|ing) to (version )?X', re-run sanitize_dataset.py on both JSONs, and add a leakage regression test that asserts zero matches.

### M26. Unequal coverage: suite member missing entirely, full-suite runs incomplete, and two models' runs are 100% API-failure artifacts
*Category: fairness · Location: `benchmark/model_suites.sh:19`*

Confirmed with refinements: (a) README.md:5 explicitly limits published leaderboards to "the previous 16-model suite," so the accurate charge is that the advertised full-1650 leaderboard cannot be produced for the current 23-model suite (4 complete full runs + partials of n=24/13/1), not that the README misattributes coverage. (b) kimi-k2.7-code is the only suite model with no standard-protocol run anywhere in results/; its sole number (6.0%) comes from the 2-judge rerun and it is also missing from the results/analysis per-model "why" output. (c) The qwen3.5 issue is worse than stated: the 100%-API-failure runs (200/200 empty model_patch, 200/200 completion_tokens==0 in run2/run3 of both qwen3.5-27b and qwen3.5-35b-a3b) are not merely stored — results/analysis/qwen_qwen3.5-27b.md and qwen_qwen3.5-35b-a3b.md publish them as "Across 3 independent runs the pass rate was 0.0%, 0.0%, 3.5% (mean 1.2% ± 2.0%)" and "mean 0.5% ± 0.9%", framing total API failure as the model's run-to-run variance.

**Evidence:** Inventory: kimi-k2.7-code runs=NONE best3=False; full_*.json exists for only gpt-5.3-codex, sonnet-4.6, haiku-4.5, gemini-3.1-pro among current suite; full_anthropic_claude-fable-5.json.partial n=24. run2_openrouter_qwen_qwen3.5-27b.json: empty=200, zero-completion-token=200 (same for 35b-a3b runs 2-3).

**Recommended fix:** Either complete the missing runs under the standard protocol or drop the models/rows from published tables; add a validity gate that refuses to save a run whose API-failure rate exceeds a threshold.

### M27. 27 of 37 published leaderboard rows never had a second judge at all — including every Anthropic candidate and the declared leader, judged solely by Anthropic Opus
*Category: fairness · Location: `results/merged_harness_fix_20260620/merged_leaderboard.json:1`*

All figures confirmed as claimed (27/37 files with zero gpt-5.5 judging; 27 single-judge vs 10 two-judge leaderboard rows; 143 gpt-5.5-error rows; 5,543/7,400 = 74.9% solo-Anthropic-judged; leader Claude Fable 5 at 37.5% and all five Anthropic candidates judged only by claude-opus-4.8; gpt-5.3-codex judged by older claude-opus-4-6; report line 19 advertises the two-judge panel; markdown table has no judge column) with one correction: the discarded claude-sonnet-4.6 two-judge rerun scored 41 passes, not 23 (merge_decisions.json: prior_passed 21, fixed_passed 41, score_delta -0.0303, decision keep_prior_no_material_improvement) — i.e., a rerun that nearly doubled sonnet-4.6's pass count under the stricter panel was still discarded in favor of the solo-Opus prior row.

**Evidence:** Computed: 27/37 files in results/merged_harness_fix_20260620/ have 0 rows with a 'openrouter/openai/gpt-5.5' key in judge_analyses (list includes all best3_anthropic_*.json, best3_openai_gpt-5.3-codex.json, best3_x-ai_*.json, etc.); metadata of best3_anthropic_claude-fable-5.json = {'judge_model': 'openrouter/anthropic/claude-opus-4.8'} with no judge_models; merged_leaderboard.json rows: 10 with 2-entry judge_models, 27 with single-entry; 5,543/7,400 = 74.9% single-Anthropic-judge rows; report md line 19: 'Fixed-harness rows used ... two judges: Claude Opus 4.8 plus GPT-5.5.'

**Recommended fix:** Re-judge all 37 models' selected best3 outputs under one uniform judge panel (same judges, same budgets) before publishing a comparative leaderboard; at minimum add a judge-panel column and an explicit caveat to the markdown leaderboard, and never carry forward rows judged under a different regime into a ranked table.

### M28. Upstream OpenRouter serving provider is neither pinned nor recorded for candidate generations
*Category: fairness · Location: `benchmark/adapters/litellm_adapter.py:327`*

Claim is accurate except one detail: results/logs/*.log do reveal upstream provider identities in OpenRouter error payloads (e.g. anthropic_claude-fable-5.log shows one request's fallback chain across "provider_name":"Google", "Amazon Bedrock", and "Anthropic"; stepfun logs contain 316 provider_name error entries) — proving multi-provider routing actually occurred in these runs — but the serving provider for successful (scored) generations is never captured anywhere. Also note _response_meta does capture meta["model"] (litellm_adapter.py:451) but run_eval.py:575-586 drops it before persisting.

**Evidence:** litellm_adapter.py:327-334: kwargs = {"model": self.model, "messages": messages, "temperature": self.temperature, "max_tokens": self.max_tokens, "num_retries": self.num_retries, "timeout": self.timeout} — no `provider` key anywhere in the file; the only extra_body use is the reasoning block at lines 348-351. litellm_adapter.py:106: _hidden_params={"response_cost": hidden_params.get("response_cost", 0.0) or 0.0} — all other hidden params (where litellm surfaces OpenRouter's served-provider metadata) are discarded. run_eval.py:575-586 reads only prompt_tokens/completion_tokens/reasoning_tokens/cost_usd/attempts/reasoning_* from adapter.last_response_meta. Verified result keys for run1_openrout…

**Recommended fix:** Pin routing per model via extra_body["provider"] = {"order": [<chosen host>], "allow_fallbacks": false, "require_parameters": true} (and optionally "quantizations": ["fp8"] or ["bf16"]) so all instances, runs, and models are served by one declared stack; and persist the served provider per instance (OpenRouter returns it in the response body; litellm exposes it via the raw response / _hidden_params) alongside meta["model"] in InstanceResult. Publish the provider column in the report and re-run any model whose runs show mixed providers.

### M29. Split-vote rule changed to pass-if-either-judge-passes and applied retroactively; best3 GLM-5.2 now passes instances with consensus score below the documented 0.5 threshold
*Category: judge-validity · Location: `benchmark/run_eval.py:450`*

All substantive claims hold; one numeric detail corrected: the best3_z-ai_glm-5.2.json top-level aggregate went from 9 passes / 0.045 pass rate to 18 / 0.09 (not 8 / 0.04 — that figure is a per-run metadata rate inside the file; the stored run1 file does have 8 passes). Everything else verified exactly: rule change at run_eval.py:450 in commit 03e9aae, 10 pass:1/fail:1 ties all flipped to pass in the rewritten best3 file while run1/2/3 retain the old rule (tie-passes=0), best3 (18 passes) no longer equals best-of the stored runs (max 9), and two flipped ties pass with consensus scores 0.4 (CVE-2025-64495) and 0.45 (CVE-2023-45311) despite README.md:130 documenting a score>=0.5 pass requirement, because run_eval.py sets passed solely from the consensus verdict with no score gate.

**Evidence:** git show 03e9aae: '- consensus_verdict = "pass" if pass_votes > fail_votes else "fail"' → '+ ... pass_votes >= fail_votes'; diffstat shows results/best3_z-ai_glm-5.2.json 6203 lines changed. Computed: best3_z-ai_glm-5.2.json ties=10, tie->pass=10, passed-with-score<0.5: [('vulnbench-CVE-2025-64495', 0.4), ('vulnbench-CVE-2023-45311', 0.45)]; run1 same ties=10, tie->pass=0. tests/test_multi_judge.py:96 'test_two_judge_disagreement_passes_on_one_pass_vote' codifies the new rule.

**Recommended fix:** Use an odd-sized panel (3 judges) so ties cannot occur, or break 2-judge ties with a third tie-break judge; enforce the score>=0.5 gate on the consensus verdict in evaluate_instance; regenerate run1-3 and best3 artifacts under one rule and never edit published result files in place without re-deriving best-of-N.

### M30. Gold-anchoring: prompt requires covering 'the same scope as the gold patch', enforced inconsistently (14.7% of fails cite wrong file, but some passes accept different locations)
*Category: judge-validity · Location: `benchmark/run_eval.py:89`*

Claim confirmed with one nuance: the cited "inconsistency" pass example (CVE-2026-27210, 0.85) involves a different code location within the same file (judge: "line 1503 vs 1734"), not a different file, so it is a weaker parallel to the CVE-2023-48299 different-file fail than implied. The stronger, fully verified core is: the judge receives no repository source (run_eval.py:296-316 sends only CVE metadata + gold diff + candidate diff), so the line-89 criterion "Covers the same scope as the gold patch" is applied as unverifiable similarity to gold's file set; 888/6034 (14.7%) of new-suite best3 failures cite "different file" in the reasoning, including at least one case the judge itself deems "correct and arguably more robust" (CVE-2023-48299, score 0.4, fail).

**Evidence:** run_eval.py:89 '- Covers the same scope as the gold patch (doesn't miss affected files/paths)'. Computed: fails citing 'different file': 888/6034 across best3_*_*.json. best3_anthropic_claude-fable-5.json CVE-2023-48299 (0.4, fail): 'implements correct and arguably more robust Zip Slip validation logic... but it modifies a different file'; same file CVE-2026-27210 (0.85, pass): 'Minor concern: the patch appears to be applied at a different code location'.

**Recommended fix:** Give the judge the actual affected-file source (already downloadable via source_manager) so file-scope judgments are grounded; rewrite the scope criterion as 'addresses all vulnerable code paths' rather than 'same as gold'; and add rubric guidance for valid fixes at alternate layers, with the apply-check determining whether the file actually exists.

### M31. Score/verdict contradictions occur in 8% of rows and are always resolved to fail, including a 0.95-scored 'exact same fix as the gold patch'
*Category: judge-validity · Location: `benchmark/run_eval.py:354`*

One precision nit only: 'always resolved to fail' is strictly true for the single-judge path (run_eval.py:354); the 2 rows that passed with score<0.5 came from a separate split-judge 'consensus' path (both in best3_z-ai_glm-5.2.json, raw verdict 'pass:1,fail:1'). Also, 132 additional fail-with-score>=0.5 rows exist in older-schema files lacking the judge_consistent field (2,484 total vs the 2,352 the claim counts via judge_consistent==false).

**Evidence:** run_eval.py:354 `normalized_verdict = "pass" if score >= 0.5 and raw_verdict == "pass" else "fail"`. Computed over results/run* and best3_*: rows=29200, failed_score_ge_0.5=2352, judge_inconsistent=2434, passed_score_lt_0.5=2. best3_anthropic_claude-fable-5.json vulnbench-CVE-2019-25225: judge_score 0.95, judge_verdict 'fail', judge_consistent false, reasoning '[judge disagreement normalized to fail] The candidate patch applies the exact same fix as the gold patch...'.

**Recommended fix:** On score/verdict contradiction, re-query the judge (it is a parse-quality failure, not a judgment), or adopt a single source of truth (verdict only, or score-thresholded) and report both sensitivities. Publish the contradiction rate per model so reviewers can see it does not drive rankings.

### M32. No limitations, contamination, or judge-validation content anywhere in README or docs
*Category: judge-validity · Location: `README.md:109`*

All substance confirmed with two detail corrections: (a) the grep evidence line 'README.md:310 ## License' is spurious — the patterns match nothing at all in README or docs, which is stronger support for the claim; (b) the existing review sample (results/v200_gpt-5.4_review_sample.json) is 20 items, not 50, and contains no human annotations (metadata sample_size=20; 0 items have any human-label field), so judge-human agreement cannot be 'published from the existing file' without first conducting the human review. Year figure verified: 81/200 (40.5%) instances are CVE-2013 through CVE-2023.

**Evidence:** grep -rin 'contaminat|limitation|confidence interval' README.md docs/index.html docs/v2.html -> only README.md:310 '## License'. README.md:201-217 documents judge_validation commands but no results. Dataset years: 81/200 instances from 2013-2023.

**Recommended fix:** Add a Limitations section covering judge validity, contamination, npm skew, and truncation history; publish judge-human agreement on the existing 50-sample review file; publish pass rate by CVE year (pre/post training cutoff) as a contamination probe.

### M33. Judge model changed between eras and is mixed within the vendor-prefixed best3 set used for cross-suite comparisons
*Category: judge-validity · Location: `results/best3_anthropic_claude-fable-5.json:1`*

The stale-judge set is larger than claimed: 16 of 34 vendor-prefixed best3 files (not 4 models) carry the old opus-4-6 judge, and the merged leaderboard mixes THREE judge configurations, not two: 14 rows opus-4-6-only, 13 rows opus-4.8-only, and 10 rows a 2-judge panel of opus-4.8 + gpt-5.5. The four models named in the claim are indeed among the opus-4-6-judged rows, and the headline Fable 5 (37.5%) vs GPT-5.3 Codex (22.5%) comparison does cross judge versions exactly as claimed. The self-preference figure of 27/37 Anthropic-only-judged rows is exact (14+13). File census correction: 135 opus-4-6, 72 opus-4.8, and 19 metadata-format files among 226 top-level results JSONs (claim said 135/68/4 of 229). Additional supporting evidence: README.md:125 states the judge is Claude Opus 4.6 while README.md:241 states the default judge is Claude Opus 4.8.

**Evidence:** Metadata extraction across all 229 result files: 135 files judge_model=openrouter/anthropic/claude-opus-4-6 (incl. best3_openai_gpt-5.3-codex.json, best3_anthropic_claude-sonnet-4.6.json), 68 files judge_model=openrouter/anthropic/claude-opus-4.8 (incl. best3_anthropic_claude-fable-5.json, best3_anthropic_claude-opus-4.8.json), 4 files with 2-judge panel.

**Recommended fix:** Freeze one judge version per published table and re-judge stale rows (judging is cheap relative to generation since patches are stored); add judge_model as a visible leaderboard column.

### M34. One-way 'material improvement' merge rule is a statistical ratchet that only accepts favorable reruns
*Category: statistics · Location: `benchmark/generate_v2_report.py:369`*

Confirmed as stated, with corrections: (1) the rule is not per-metric max(old,new) — ambiguous cases keep the prior even when pass count improved (gpt-5.3-codex published 45 while its fixed-harness rerun scored 48 passed), so it is "keep old unless new dominates on both metrics by thresholds", still a one-way upward-only selection; (2) most discarded regressions (9-11 of 15 rerun models) were broken reruns with 200/200 empty patches and 0 passes rather than statistical noise, which mitigates but does not eliminate the bias since genuine complete regressions (qwen3.7-plus 20 vs 33 passed) were also discarded; (3) an additional unclaimed asymmetry strengthens the finding: the 6 updated rows used a two-judge pass-on-tie protocol (pass if either of Opus 4.8/GPT-5.5 passes) that is strictly more lenient than the single-judge Opus protocol of the kept rows, so the merged leaderboard mixes judge protocols and only accepted the easier protocol's results when they were favorable.

**Evidence:** generate_v2_report.py render_markdown: 'A prior row is replaced only when the fixed-harness row improves mean score by at least 0.02 and pass count by at least 1... Regressions and ambiguous changes are kept from the prior baseline, even if one metric improved.' merged_leaderboard.json material_update_rule={'min_mean_score_delta': 0.02, 'min_total_passed_delta': 1, 'requires_both': True}; kept_count=27, updated_count=6, added_count=4. run_best_of_n.py:353-357 selects max by (pass_rate, mean_score).

**Recommended fix:** When the harness changes, re-run every model and publish only new-harness numbers (report the old table separately as deprecated). Never gate row replacement on whether the new number is better. For best-of-3, additionally report mean-of-3 with a dispersion measure so readers can see variance, and state that the headline is a max statistic.

### M35. No confidence intervals or significance testing; published rank gaps are within noise
*Category: statistics · Location: `docs/index.html:1`*

All numbers check out; only a file attribution is swapped in the evidence. The GPT-5.5 all_runs of 0.33/0.19/0.23 are in results/merged_harness_fix_20260620/best3_openai_gpt-5.5.json (the file behind the published 66/200 leaderboard row), while the top-level results/best3_openai_gpt-5.5.json holds the prior runs 0.15/0.17/0.175. Additional supporting evidence: 29 of 35 adjacent leaderboard pairs differ by <=2 passes, and GPT-5.5's published 33% is the max of runs averaging 25%, so best-of-3 selection materially inflates the point estimate the "4.5-point gap" finding card is built on.

**Evidence:** Computed: Wilson/normal CI ±6.7pp at p=0.375, n=200; two-prop z=0.94. generate_v2_report.py:305 'the leaderboard reflects the strongest observed run'; run-to-run spread in artifacts is large (best3_openai_gpt-5.5.json all_runs pass rates 0.33/0.19/0.23; prior 0.15/0.17/0.175).

**Recommended fix:** Add binomial 95% CIs to every pass-rate cell (data already sufficient), report mean-of-3-runs alongside best-of-3, and group statistically indistinguishable models into tiers rather than strict ranks.

### M36. 'Best-of-3' is max-of-3-runs on the noisy metric — an upward-biased order statistic, not variance reduction and not pass@3
*Category: statistics · Location: `benchmark/run_best_of_n.py:352`*

All substantive details confirmed. Minor numeric corrections from recomputation over the full set of complete run1/run2/run3 triples: 36 models (not 33), inflation mean +1.60pp (not +1.64), median +1.17pp (not +1.2), max +6.17pp — qwen3.7-max runs 11.5/28.5/27.0 → published 28.5% vs mean 22.3%; run-spread median 2.5pp, max 17.0pp. The max() selection is at run_best_of_n.py:353-356 (comment at 352). Also note docs/index.html:43 carries the same 'strongest observed run' wording as docs/v2.html, and README.md:270 repeats the 'variance reduction' mislabel.

**Evidence:** run_best_of_n.py:352-355: best_report = max(all_run_reports, key=lambda r: (r.aggregate.pass_rate, r.aggregate.mean_score)). Computed inflation stats over 33 models: mean +1.64pp, median +1.20pp, max +6.2pp; run-spread median 2.5pp, max 17.0pp at temperature=0.0 (run_best_of_n.py:115 default).

**Recommended fix:** Report mean-of-3 with a CI as the headline number, and pass@3 (computed per-instance) as a separate clearly-labeled column; keep max-run only as a diagnostic.

### M37. Every adjacent leaderboard gap at n=200 is statistically indistinguishable; no CIs published
*Category: statistics · Location: `README.md:19`*

All cited numbers verified exact. One refinement: the "33/33" count refers to all 34 vendor-prefixed best3 models (old + new suites combined), not the new suite alone (which is 17/17 among 18 models) — both support the same conclusion. Also, CI overlap is conservative; a paired McNemar test on the shared 200 instances would be the rigorous gate, and would still fail to separate the 273-vs-271 headline pair.

**Evidence:** Computed Wilson CIs: fable-5 37.5% [31.1,44.4]; opus-4.8 29.5% [23.6,36.2]; adjacent-overlap counts 33/33 (best3 n=200), 15/15 (README-200), 12/15 (README-1650; separated only codex-vs-sonnet, gemini-flash-vs-gpt-5.2, deepseek-vs-step). README.md:13 'narrowly ahead' claim = 273 vs 271 passes.

**Recommended fix:** Publish Wilson 95% CIs per row, group models into statistically indistinguishable tiers, and gate all 'X beats Y' copy on a two-proportion test.

### M38. Full-benchmark leaderboard double-counts fixes: 152 instances share identical gold diffs and top repos contribute up to 29 instances each
*Category: statistics · Location: `data/benchmark/vulnbench_full.json:1`*

Core claim exact: 152/1650 instances (9.2%) in 67 duplicate groups share an identical gold_patch.raw_diff AND commit_sha; largest group is the 5-CVE cluster CVE-2024-24779/26016/24773/24772/27315, plus 4x CVE-2026-24766..69 and 4x CVE-2024-32645/46/47/49. Minor number corrections (by github_repo_url normalization): apache/airflow is 29 (not 28), parse-community/parse-server 22 (not 21), unique repos 878 (not 888), top-10 repos total 197/1650 (not 195). The curated 200 set is clean as claimed (0 duplicate diffs, 200 unique repos). The published 1650 leaderboard's #1 vs #2 margin (README.md:46-47) is only 2 instances (273 vs 271), well within the swing a single 3-5 instance duplicate cluster can cause.

**Evidence:** Computed from vulnbench_full.json: gold diffs shared by >1 instance = 152 instances in 67 groups; largest groups ['CVE-2024-24779','CVE-2024-26016','CVE-2024-24773','CVE-2024-24772','CVE-2024-27315'], ['CVE-2026-24766','CVE-2026-24767','CVE-2026-24768','CVE-2026-24769']; repo counts directus/directus=29, apache/airflow=28, openclaw/openclaw=23; 888 unique repos for 1650 instances.

**Recommended fix:** Deduplicate by gold commit SHA in the full set (keep one instance per unique fix commit, or merge multi-CVE advisories into one instance), and report full-set pass rates both raw and repo-weighted (cluster by repository) so rankings are robust to concentration.

## Minor findings

### M1. --judge-model set explicitly to the default value silently activates the two-judge panel
*Category: correctness · Location: `benchmark/run_eval.py:1058`*

Judge selection uses `elif args.judge_model != JUDGE_MODEL` to detect an explicit single-judge request. A user who runs `--judge-model openrouter/anthropic/claude-opus-4.8` (the documented default, per README 'The default judge is Claude Opus 4.8') gets the two-judge Opus+GPT-5.5 panel instead of the single judge they asked for. The same pattern is copied in run_best_of_n.py:219-224, compare.py:252-257, and run_eval_skills.py:365-370. This makes runs hard to reproduce from their command lines alone and likely contributed to the mixed-protocol artifacts already in results/.

**Evidence:** run_eval.py:1058-1063: `if args.judge_models: ... elif args.judge_model != JUDGE_MODEL: active = [args.judge_model] else: active = DEFAULT_JUDGE_MODELS`. README.md:241 'The default judge is Claude Opus 4.8 via OpenRouter.'

**Recommended fix:** Use argparse default=None for --judge-model and branch on 'was it provided' (None check), or remove --judge-model in favor of --judge-models with an explicit documented default panel.

### M2. Sanitizer hex regex mangles CVE IDs and long numbers inside the prompts
*Category: correctness · Location: `benchmark/sanitize_dataset.py:29`*

COMMIT_HASH_RE = `\b[0-9a-f]{7,40}\b` treats any 7+ digit decimal number as a commit hash. Legacy CVE IDs with 7-digit suffixes are redacted inside their own descriptions — models see 'CVE-2017-[redacted]' — and any long numeric token (issue numbers, timestamps) is similarly destroyed. 5 full-set and 2 curated instances are affected. Cosmetic, but it is prompt text every model sees and an external reviewer will screenshot it.

**Evidence:** Computed: full set instances with 'CVE-\d{4}-\[redacted\]' in their own description: ['CVE-2016-1000229','CVE-2017-1000491','CVE-2018-1000534','CVE-2017-1000424','CVE-2017-1000220']; 200 set: ['CVE-2018-1000534','CVE-2017-1000220']. E.g. CVE-2017-1000220's prompt reads 'CVE: CVE-2017-[redacted]'. sanitize_dataset.py:29 and src/benchmark_generator.py:42 define the same regex.

**Recommended fix:** Require at least one alphabetic hex char: `\b(?=[0-9a-f]*[a-f])[0-9a-f]{7,40}\b`, and whitelist the instance's own CVE ID before scrubbing; re-run the sanitizer.

### M3. Gold diffs are stored without ---/+++ file headers and are not machine-applicable, precluding any executable validation
*Category: dataset · Location: `src/benchmark_generator.py:159`*

fetch_fix_diff builds raw_diff by concatenating 'diff --git a/X b/X' with GitHub's `patch` hunk field, which contains only @@ hunks — no '--- a/X' / '+++ b/X' lines. GNU patch cannot apply these (verified: `patch -p1 --batch --dry-run` fails on 120/120 sampled instances in both directions), so the benchmark can never mechanically verify that gold applies to the snapshot, that candidate patches apply, or run tests — everything rests on the LLM judge's textual comparison. For an 'industry-standard' claim, the absence of even a patch-applies check is a defensibility gap and is the reason findings like the wrong-version snapshots went undetected.

**Evidence:** src/benchmark_generator.py:159-164: `diff_parts.append(f"diff --git a/{f['filename']} b/{f['filename']}"); diff_parts.append(patch)` — no ---/+++ emitted. Sampled 120 instances with cached sources: gold applies forward 0, reverse 0, neither 120 (patch cannot parse the file headers). benchmark/source_manager.py:98-131 ships an apply_patch helper that is unusable against these gold diffs.

**Recommended fix:** Emit proper '--- a/path' / '+++ b/path' headers when reconstructing diffs (or fetch the commit's .patch/.diff endpoint verbatim), then add a CI check that every gold patch dry-run-applies to its snapshot; use the same mechanism to grade candidate patch applicability as an objective sub-metric alongside the judge.

### M4. Leaderboard cost column is inconsistent and undercounts best-of-3 spend
*Category: docs · Location: `benchmark/generate_v2_report.py:169`*

Claim is accurate except one detail in the proposed fix: metadata['all_runs'] (run_best_of_n.py ~361-370, mirrored in generate_v2_report.py:138-146) stores per-run generation cost only, not per-run judge cost. Only the best run's judge cost survives in the aggregate, so total spend can be reconstructed as sum(all runs' gen cost) + best run's judge cost; exact all-runs judge spend would require adding per-run judge costs to all_runs. Example: claude-fable-5 shows $32.27 in the non-merged path ($34.80 in merged) while reconstructable spend is at least $95.51 gen + $2.53 judge.

**Evidence:** generate_v2_report.py:169 `cost=agg.get("total_cost_usd", 0)` (gen only) vs :205 `cost=item.get("total_cost_usd", 0) + item.get("total_judge_cost_usd", 0)`; render_markdown note at :401. run_best_of_n.py:362-370 stores per-run costs in metadata['all_runs'] but the best report's aggregate carries only the best run's cost.

**Recommended fix:** Define cost as total spend to produce the row (sum of all runs' gen cost + all judge cost, available in all_runs metadata), compute it identically in both loaders, and label the column accordingly.

### M5. Documentation contradicts the implementation: judge identity, panel default, and pass rule are all misdescribed
*Category: docs · Location: `README.md:125`*

All cited quotes are accurate. Two refinements: (1) the two sub-0.5 passes live in results/best3_z-ai_glm-5.2.json, not the run1/run2/run3 files, and they are the only such cases across all results/*.json; (2) the score>=0.5 threshold IS enforced per-judge via verdict normalization at run_eval.py:354, so single-judge runs match the documented rule — the documented pass criterion is violated only at consensus level, where score becomes the median of judge scores while the verdict passes on a 1-1 split (run_eval.py:450, 609).

**Evidence:** README.md:125 '**Scoring** uses an LLM-as-judge approach (Claude Opus 4.6)'; README.md:241 'The default judge is Claude Opus 4.8'; run_eval.py:3 'Uses an LLM judge (Claude Opus 4.6 via OpenRouter)'; run_eval.py:69-72 DEFAULT_JUDGE_MODELS=[claude-opus-4.8, openai/gpt-5.5]; eval_models.py:34 'passed: bool = False  # score >= 0.5' vs run_eval.py:609 'passed = analysis.judge_verdict == "pass"'.

**Recommended fix:** Single-source the scoring spec: document the exact panel, tie rule, threshold, and normalization in README, and generate the methodology section of reports from the code constants so they cannot drift.

### M6. Report methodology text misdescribes the majority of leaderboard rows
*Category: docs · Location: `benchmark/generate_v2_report.py:306`*

Two small detail corrections: (1) the provenance field in merged_leaderboard.json is 'source' (values prior_baseline/fixed_harness/fixed_harness_new_model), not 'src'; (2) in the actual runs (file_hint_mode='description') the explicit 'Affected files:' hint line is NOT included in prompts (run_eval.py:524 gates it to gold mode) — localization instead comes from advisory-named filenames driving selection of up to 3 inlined source files, plus the advisory text itself. The substance (pre-localized, guided task; two-judge text covering only 10/37 rows) is correct.

**Evidence:** generate_v2_report.py:306 judge_desc string; :295 hero_eyebrow 'Blind vulnerability find and fix benchmark'; merged_leaderboard.json: 27 rows src=prior_baseline (single judge per their metadata). Verified dataset stats computed from data/benchmark/vulnbench_200.json: 55 unique CWEs, 7 ecosystems, 200 unique repos, mean 36.1 changed lines, 1.9 files.

**Recommended fix:** State per-row judging provenance on the page (single vs dual judge, harness version), describe the task as guided patch generation with source context rather than blind find-and-fix, and generate the methodology text from the actual row metadata instead of hardcoding it.

### M7. Cosmetic org mapping errors and duplicate legacy result files invite confusion
*Category: docs · Location: `benchmark/generate_v2_report.py:30`*

ORG_CLASS in benchmark/generate_v2_report.py:30-31 maps "nvidia"->"google" and "mistralai"->"minimax" (and line 32 maps "qwen"->"zhipu"), and the class is emitted at line 243 as gs-vb-leaderboard__org--{org_class}, so those vendors render with other vendors' brand styling. Duplicate-era files: best3_gpt-5.3-codex.json (Mar 17, 50-instance run, pass_rate 0.60) coexists with best3_openai_gpt-5.3-codex.json (Jun 13, 200-instance run, pass_rate 0.225) — same model, conflicting headline numbers under near-identical names; the flat results/ dir also mixes old- and new-suite run1_* files, three full_*.json.partial files, and undocumented subdirs (merged_harness_fix_20260620/, rerun_fixes*/ x5, logs/). README.md:283-292 documents only best3_*/full_*/skills.

**Evidence:** generate_v2_report.py:30-31 '"nvidia": "google", "mistralai": "minimax"'; ls results/ shows best3_gpt-5.3-codex.json (Mar 17) and best3_openai_gpt-5.3-codex.json (Jun 13) plus 200-instance/1650-instance .partial files; README.md:284-294 Data Outputs table lists only best3_*/full_*/skills.

**Recommended fix:** Fix the two ORG_CLASS entries; move legacy-era results into results/archive/v1/ and document the current results directory layout (run{1..3}_*, best3_*, merged_harness_fix_*, .partial semantics) in the README.

### M8. Generation settings are not fully recorded: temperature never, max_tokens/retries missing from all pre-June-21 runs
*Category: docs · Location: `benchmark/run_eval.py:828`*

Four glm-5.2 files (run1/run2/run3_openrouter_z-ai_glm-5.2.json and best3_z-ai_glm-5.2.json) carry the richer metadata, not three; even those omit temperature. Old-suite best3_* files additionally lack even file_hint_mode/include_source. Otherwise the claim is accurate.

**Evidence:** Metadata keys of results/run1_openrouter_openai_gpt-5.5.json: ['benchmark','evaluated_at','file_hint_mode','include_source','judge_model','model','total_instances'] — no temperature, no max_tokens. run_eval.py:807-860 build_report signature has max_tokens/reasoning_* but no temperature and no harness version/git SHA.

**Recommended fix:** Record temperature, max_tokens, retry policy, adapter defaults (including DEFAULT_REASONING_DISABLED_BY_MODEL hits), litellm version, and a harness git SHA in every report; regenerate or clearly version-stamp legacy result files.

### M9. Stale duplicate best3_* files with wildly different numbers break reproducibility of the README tables
*Category: docs · Location: `README.md:291`*

README.md:291 documents 'results/best3_*.json — VulnBench-200 best-of-3 reports per model', but the directory contains both the n=200 vendor-prefixed reports the README tables were computed from AND older n=50 vulnbench_mini runs under unprefixed names with much higher pass rates (best3_gpt-5.3-codex.json = 60.0% on 50 instances vs best3_openai_gpt-5.3-codex.json = 22.5% on 200; best3_claude-opus-4.6.json = 46.0%/50 vs 16.0%/200). A reviewer following the README glob will reproduce the wrong numbers. Related staleness: README.md:125 says the judge is 'Claude Opus 4.6' while README.md:241 says 'The default judge is Claude Opus 4.8'; results/linkedin_post.md still claims 'GPT-5.3 Codex — 57.0%' and a 45.5% Opus 4.6, figures matching no file currently in the repo's published tables.

**Evidence:** best3_gpt-5.3-codex.json: benchmark=vulnbench_mini.json n=50 pass_rate=0.6 (2026-03-09) vs best3_openai_gpt-5.3-codex.json: vulnbench_200.json n=200 pass_rate=0.225 (2026-03-20). All 16 README-200 rows verified to reproduce exactly (pass rate, mean score, passed count, cost) from the vendor-prefixed files; all 16 README-1650 rows verified against full_*.json.

**Recommended fix:** Move mini/50-instance and superseded runs into an archive subdirectory, and name published report files with the dataset and judge version (e.g. best3_v200_judge-opus46_<model>.json).

### M10. README dataset statistics conflate the 200 subset with the full benchmark and contain a wrong percentage
*Category: docs · Location: `README.md:89`*

Claim is fully accurate as stated; one addition: the Top CWE Categories table also disagrees slightly with primary-CWE counts on the 200 set (README CWE-94=19 vs computed 18; CWE-1333=5 not in computed top 10), suggesting it was computed over multi-CWE membership without saying so.

**Evidence:** README.md:89-93 vs computed values from the shipped JSONs: full CWEs=240, severity {'medium':988,'high':448,'critical':214}, mean patch 69.1 lines, tiers {'tier_1':354,'tier_2':1106,'tier_3':190}; 2024-2026 share = 974/1650 = 59.0% (curated 119/200 = 59.5%); full ecosystems {'npm':1163,'pip':474,'maven':5,'rubygems':4,'composer':2,'rust':1,'swift':1}.

**Recommended fix:** Split the table into two labeled columns (VulnBench-1650 vs VulnBench-200) with recomputed values, correct 55%->59%, label the CWE table as curated-subset, and state the npm/pip share explicitly.

### M11. Older result files lack even the adapter attempt/reasoning telemetry, so provider effects cannot be retro-diagnosed
*Category: docs · Location: `results/run1_openrouter_moonshotai_kimi-k2.6.json`*

Directionally right but the framing "older files lack telemetry" understates it: glm-5.2 is the ONLY model with the 22-key schema — all four of its files (run1/2/3 + best3) — while all 166 other result files across every other model use the 13-key schema. Additionally, the schema drift coincides with a real protocol difference: glm-5.2's metadata lists judge_models = [claude-opus-4.8, gpt-5.5] (dual judge) whereas kimi-k2.6 and other 13-key files list a single judge_model; that judge asymmetry should be tracked as a separate, more serious finding. No results file records the harness_version that benchmark/provenance.py:15 provides.

**Evidence:** Computed key sets: run1_openrouter_moonshotai_kimi-k2.6.json keys = [completion_tokens, cost_usd, cve_id, difficulty_tier, ecosystem, generation_time_s, instance_id, judge_cost_usd, model_patch, passed, patch_analysis, prompt_tokens, score] (13 keys); run1_openrouter_z-ai_glm-5.2.json has 22 keys including adapter_attempts, reasoning_tokens, generation_error, judge_analyses.

**Recommended fix:** Record a harness/schema version in every results file, backfill or re-run models whose files predate the telemetry fields, and require a uniform schema (including served-provider) before any cross-model table is published.

### M12. Diff parser falls back to raw model output; 1,197 non-diff responses were judged as 'patches'
*Category: judge-validity · Location: `benchmark/run_eval.py:262`*

The exact count is 1,196 (not 1,197) non-empty model_patch values with no line-start diff markers across the 108 run[123] files; all other specifics — including the 9 passing non-diff results and their per-model breakdown — reproduce exactly.

**Evidence:** run_eval.py:236-241 fence regex `r"```(?:diff|patch)?\s*\n(.*?)```"` matches any first fence (the `?` makes the language tag optional); run_eval.py:262 `return output.strip()`. Computed: 1,197 results across results/run[123]_openrouter_*.json where model_patch lacks any of diff --git//---/+++/@@ at line start; 9 passed (2 claude-fable-5, 2 claude-opus-4.8, 2 mistral-medium-3-5, 1 each minimax-m3/qwen3.7-max/grok-build-0.1).

**Recommended fix:** Prefer fenced blocks tagged diff/patch, else scan all fences for diff-marker content before falling back; validate the extracted text with parse_hunks (diff_analysis.py already exists) and record a 'no_valid_diff' outcome that fails deterministically without invoking the judge; report the per-model malformed-output rate.

### M13. Judge-error abstention lets one judge decide alone under pass-on-tie
*Category: judge-validity · Location: `benchmark/run_eval.py:425`*

combine_judge_analyses (run_eval.py:422-450) drops judges whose raw verdict is 'judge_error' from voting, so with the 2-judge panel one abstention reduces the decision to a single judge, and consensus 'pass if pass_votes >= fail_votes' means panel strictness varies per instance (pass-on-tie with 2 votes vs sole-judge rule with 1). Confirmed 50 abstention-decided rows across results/run[123]_openrouter_*.json — all in the three z-ai_glm-5.2 runs, the only top-level panel-judged files (13 lone-pass, 37 lone-fail). The GPT-5.5 numbers are correct but belong to results/rerun_fixes_2judge_20260613_232410/best3_openai_gpt-5.5.json (not the top-level best3, which is single-judge): 26 recorded 1-1 splits plus 12 lone-judge passes = 38 apparent per-judge disagreements (the errored judge's judge_verdict defaults to 'fail', line 403, inflating naive disagreement counts). Scope is larger than claimed: the 2-judge rerun directory contains 807 abstention-decided rows (289 lone-pass, 518 lone-fail), up to 61 in a single 200-instance file. Abstentions are recorded only in per-instance raw_judge_verdict strings; AggregateMetrics surfaces no count.

**Evidence:** run_eval.py:422-427 filters `analysis.raw_judge_verdict != "judge_error"`; consensus then computed over survivors. Computed: 50 results with 'abstain' in raw_judge_verdict across results/run[123]_openrouter_*.json; in merged best3_openai_gpt-5.5.json, per-judge disagreements (38) exceed recorded 1-1 splits (26), the difference being abstention-decided rows.

**Recommended fix:** Retry the errored judge until a verdict exists (judges are cheap relative to invalid rows), or mark abstention-decided instances and report their count in AggregateMetrics; consider failing the instance's judgment as 'inconclusive' rather than letting one judge decide.

### M14. Judge reproducibility unpinned and never human-calibrated: temperature 0 but no seed, floating OpenRouter aliases, judge_validation tooling never exercised
*Category: judge-validity · Location: `benchmark/judge_validation.py:35`*

Judge is unpinned (temperature 0.0, no seed, mutable OpenRouter aliases; published results mix judge ids 'claude-opus-4-6' and 'claude-opus-4.8') and has never been human-calibrated: a judge_validation.py review-sample export exists (results/v200_gpt-5.4_review_sample.json, 20 items from one old-suite gpt-5.4 run under the old judge) but was never annotated — no human labels anywhere in the repo. Measurable inter-judge (opus-4.8 vs gpt-5.5) verdict disagreement from results/rerun_fixes_2judge_20260613_232410/ is 3.0% (568/19,188 jointly-judged rows), not the claimed 8.0%/4,721; this rate is computable from repo data (2-judge consensus reruns record per-judge votes) but is unpublished.

**Evidence:** run_eval.py:329-333 judge kwargs: temperature 0.0, no seed param. Judge ids differ in format across runs: 'openrouter/anthropic/claude-opus-4-6' (135 files) vs 'openrouter/anthropic/claude-opus-4.8' (68 files). `find results docs -iname '*review*' -o -iname '*calibration*'` returns only gemini 'preview' model files; `ls results/rerun_fixes_multijudge/` is empty. Computed inter-judge verdict disagreement on 4,721 jointly-judged rows: 380 (8.0%).

**Recommended fix:** Pin judge model snapshots (dated model ids), record judge response fingerprints, run judge_validation.py's human-review export on a stratified ~100-instance sample with 2+ security engineers, and publish judge-vs-human agreement plus the inter-judge agreement rate alongside the leaderboard.

### M15. Some judge abstentions were caused by OpenRouter credit exhaustion mid-run, silently converting funding failures into single-judge scoring
*Category: judge-validity · Location: `benchmark/run_eval.py:399`*

Directionally correct with refined counts: 402 credit and network errors did hit both judges and all funnel to the generic judge_error path (run_eval.py:399-407), but in the current top-level published suite only 1 row remains degraded by these errors (run2_openrouter_z-ai_glm-5.2.json, CVE-2025-9910, single-judge after GPT-5.5 DNS error); 3 zero-judge credit rows (scored fail/0.0) and 4 other degraded rows exist only in results/rerun_fixes_2judge_20260613_232410/ intermediate files, having been re-judged in top-level versions. Note the same outage caused a much larger adjacent problem outside this claim: 80/200 rows in published run2_openrouter_z-ai_glm-5.2.json have generation_error='Network is unreachable' and are counted as model failures (pass count 7/200).

**Evidence:** Log tally (results/logs/, warning format from run_eval.py:380-387): GPT-5.5 judge failures include 12x '[Errno 8] nodename nor servname provided' and multiple 402 groups ('can only afford 535', '212', '176' tokens); Opus judge failures include 402 groups ('can only afford 642', '255', '211') and 3x '[Errno 51] Network is unreachable'; all reach the generic judge_error return at run_eval.py:399-407 with no error-class field.

**Recommended fix:** Record the exception class/HTTP status in the PatchAnalysis (e.g. judge_error_kind: truncation|credit|network|parse), abort or pause the run on 402 credit errors instead of scoring through them, and exclude credit/network-failure rows from published aggregates or re-judge them.

### M16. Per-ecosystem aggregates published from n=1-5 cells without sample sizes; npm dominance undisclosed
*Category: statistics · Location: `docs/index.html:1`*

Claim fully accurate, with one precision: the docs page does not itself render per-ecosystem pass rates — the n=1-5 rate cells are published only in the result JSON files (and run_eval.py console output at benchmark/run_eval.py:886-888), while docs/index.html and README.md contribute the undisclosed-breadth framing ("7 Ecosystems") without stating that npm is 67% of the 200 subset and 70.5% of the full set.

**Evidence:** Computed from vulnbench_200.json: ecosystems {npm: 134, pip: 54, maven: 5, rubygems: 3, composer: 2, rust: 1, swift: 1}; vulnbench_full.json npm 1163/1650. results/run1_openrouter_openai_gpt-5.5.json aggregate pass_rate_by_ecosystem includes 'composer: 0.5', 'rust: 0.0', 'swift: 0.0'.

**Recommended fix:** Attach n to every breakdown cell, suppress or pool cells with n<20, and state the npm/pip concentration in the dataset sections of README and docs.

### M17. prompt/completion tokens and cost are summed across retry attempts, skewing per-model cost/token comparisons
*Category: statistics · Location: `benchmark/adapters/litellm_adapter.py:485`*

The aggregation design flaw exists as cited (sums across attempts stored as instance tokens, litellm_adapter.py:485-488 -> run_eval.py:577-580), but its observed impact is the opposite of the claim: empty-response retries contribute zero usage in practice (3 cases total, no inflation), while exception retries zero out the entire instance's tokens/cost (e.g. 81 instances at pt=0/ct=0/cost=0 in run2_openrouter_z-ai_glm-5.2.json), undercounting cost for exactly the models with reliability problems. Separately, run1_openrouter_qwen_qwen3.7-max.json has 112 empty-patch instances all bearing an identical copied meta tuple (178 prompt / 17,718 completion / $0.066665) from a pre-aggregation code version — a stale-meta artifact that corrupts that file's token/cost totals and any tokens-vs-score analysis; the 17,718 figure is not evidence of retry summation.

**Evidence:** litellm_adapter.py:485-488: 'prompt_tokens': sum(m.get('prompt_tokens', 0) for m in attempt_metas), same for completion/reasoning/cost; run_eval.py:577-580 stores these as InstanceResult.prompt_tokens/completion_tokens. Observed: run1_openrouter_qwen_qwen3.7-max.json empty-patch instances mean completion_tokens 17,718 vs max_tokens 4096 (multi-attempt summation plus uncapped reasoning).

**Recommended fix:** Store final-attempt tokens as the instance's tokens and keep the summed values in separate fields (total_attempt_tokens, total_attempt_cost), or persist the full per-attempt meta list.
## Remediation Status (2026-07-23)

### Fixed in this change set

| Area | Fix |
|---|---|
| Token-budget artifact | Default completion budget raised 4,096 → 16,384; uniform escalation ladder on exhausted-empty responses (retry at 32,768, then with provider reasoning excluded) — identical for every model (`benchmark/adapters/litellm_adapter.py`) |
| Per-model special-casing | GLM-5.2-only reasoning disable removed; a test now asserts no model gets special configuration (`tests/test_litellm_adapter.py`) |
| Truncation invisibility | `finish_reason`, `truncated`, `budget_escalations`, `used_reasoning_content`, `patch_parse_mode`, `source_context_present`, `provider`, `judge_quorum_met` now persisted per instance (`benchmark/eval_models.py`) |
| Split-judge tie → pass | Consensus now requires a strict majority AND median score ≥ 0.5; split votes are adjudicated by a cross-vendor tie-breaker judge (default `google/gemini-3.5-flash`); an unresolved tie fails (`benchmark/run_eval.py`) |
| Self-judging | `resolve_judge_panel` removes the candidate model from its own judge panel, filling the seat with the adjudicator (`benchmark/run_eval.py`) |
| Judge truncation | Judge max_tokens 1,024 → 4,096 |
| `--judge-model` default bug | Explicit-default no longer silently activates the two-judge panel (sentinel default) |
| Resume config mixing | `run_eval.py` resume now validates checkpoint configuration before reuse |
| Best-of-3 selection bias | `run_best_of_n.py` now reports mean pass rate across runs ± pooled Wilson 95% CI plus labeled pass@N; max-run selection retired |
| No statistics | `benchmark/stats.py`: Wilson intervals, multi-run aggregation, paired bootstrap significance, leaderboard tie groups (+ tests) |
| No per-model "why" output | `benchmark/model_report.py`: per-model markdown/JSON cards (failure taxonomy, judge-reasoning clusters, CWE/tier/ecosystem/severity/year breakdowns vs suite median, run variance, cost) + comparability-guarded leaderboard index |
| Mixed-judge leaderboards | `benchmark/rejudge.py` re-scores stored patches under a pinned panel without re-generation; the leaderboard index never ranks rows across different judge configurations |
| No provenance | Harness git SHA + dataset SHA-256 + full generation/judge parameters stamped into every report (`benchmark/provenance.py`) |
| Sanitizer gaps | v2 sanitizer: any-level header prefix matching, commit-hash regex requires a hex letter (no more mangled CVE IDs), fixed-by/upgrade-phrase scrubbing; all three datasets re-sanitized from the raw checkpoint; regression tests pin the leakage classes (`tests/test_sanitize_dataset.py`). Curated-200 set verified clean; 20 residual pattern hits remain in the full set's minimal-fallback path (kept to avoid empty prompts) |
| Empty descriptions | Re-sanitization from raw advisories eliminated all near-empty prompt descriptions |
| Answer-key leak | `data/benchmark/checkpoints/` untracked and gitignored (history purge still required — see below) |
| Ratchet merge | `generate_v2_report.py` refuses the merged manifest without `--allow-legacy-merged-manifest` |

### Action required (owner decision, spend, or data rebuild)

1. **Purge `data/benchmark/checkpoints/` from git history** (`git filter-repo` or BFG) before any public push — the unsanitized answer key remains in every clone's history until then.
2. **Retire the published numbers and re-run the suite under Protocol v2** (see `METHODOLOGY.md`). Generation must be re-done (empty patches cannot be re-judged); estimate spend before launching. Until then the public pages under `docs/` should be taken down or banner-flagged.
3. **Dataset rebuild** for the deeper data defects: ~44% of source snapshots are not pre-fix code (~11% already contain the fix); gold "fixes" that are version bumps/changelogs; 152 duplicate gold diffs in the full set; repo concentration; gold diffs lacking `---/+++` headers (blocks mechanical apply validation); tier definitions that don't track empirical difficulty.
4. **Licensing**: choose a repository license; add per-instance license metadata and CC-BY attribution for GitHub Advisory Database text; consider distributing gold patches by reference (repo URL + commit SHA) rather than inline.
5. **Source-context coverage**: description-derived localization leaves ~78% of instances with no source context despite `--include-source`; decide between always-on context (e.g. package entry files) or a clearly-labeled no-context track. The gold-hint mode is currently inert because `affected_files_hint` is cleared during sanitization; a hints-retained dataset variant would be needed for that ablation.
6. **Judge validation**: run the human-calibration sample (`benchmark.judge_validation` supports it), publish inter-judge agreement per release, and add a mechanical `apply_patch --dry-run` gate (the helper exists in `benchmark/source_manager.py` but is never called).
7. **Skills mode**: `run_eval_skills.py` received the judge fixes but still lacks the new telemetry fields; bring to parity before publishing skills-mode numbers.
