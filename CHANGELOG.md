# Changelog

## 0.1.3 — 2026-08-30

Precision. Both changes come from one measurement, and the measurement is the point:
the analyzer was run over **~570 workflow files in 30 professional repositories**
(Prefect, zitadel, DoltHub, VictoriaMetrics, Infisical, terragrunt, sglang, urllib3,
OpenCTI, mondoo, LMCache and others), asking five rules. It produced **13 findings, and
a hand-read of every one rejected 11.** A linter's real cost is the false positive, so
the 11 were treated as bugs in the rules rather than as noise to live with.

### `cache-key-static` no longer reports a key it cannot resolve

Eight hits, none filable, and **seven were one cause**: the rule read the key as text
when the key was a *reference*.

The sharpest case is PrefectHQ/prefect, where a `setup` job computes the key once from
`hashFiles('ui-v2/package-lock.json')` and publishes it as a job output, and four
consumer jobs use `key: ${{ needs.setup.outputs.cache-key }}`. That is the recommended
shape for a multi-job workflow, and the rule reported all four consumers of it. The same
shape appeared as `${{ env.PROVIDER_CACHE_DAY }}` (mondoohq/cnspec, a deliberate daily
rotation), `gon-${{ env.GON_VERSION }}` (gruntwork-io/terragrunt) and
`hf-hub-${{ matrix.model.name }}-v2` (LMCache/LMCache).

A key containing `needs.*`, `steps.*`, `env.*`, `inputs.*`, `matrix.*`, `vars.*` or
`secrets.*` is now silent, in the key or in `restore-keys`. Whether it tracks your
lockfile is decided somewhere the file cannot see, and a linter that guesses there is
the false positive that gets it uninstalled.

`runner.*` and `github.*` are deliberately **not** on that list — they resolve to values
the rule can reason about. `${{ runner.os }}-docker-mysql-client-integrations`
(dolthub/dolt), the one genuinely static key in the sweep, still reports, and so does a
plain literal. The rule was narrowed, not muted, and the tests pin both directions.

### `job-continue-on-error` says only what the file can show

Five hits, none filable. Every one was a job that is non-blocking on purpose —
zitadel's `homebrew-tap`, `helm-chart` and `npm-packages` release legs, fastly/cli's
`golangci-latest` canary, super-productivity's `deploy-preview`. The old message
conceded the problem in its own second sentence: *"**If** this job is a required
check."* Whether it is required lives in branch protection, which is not in the
workflow, so at `warning` the rule was asserting something it cannot see.

One half of it **is** visible, and it is the sharper bug: GitHub counts a
`continue-on-error` job as successful when resolving `needs:`, so a job other jobs wait
on cannot gate them however it fails. That keeps the `warning`, and the message now
names the waiting jobs.

A job nothing in the file depends on drops to `info` and says plainly what it cannot
know. With `min-severity: warning` — already the documented way to hide info-level
noise — those five stop appearing at all.

### Verification

Re-running the same sweep after the change: **13 findings → 2**, and the two survivors
are the one genuinely static cache key and one correctly-reworded `info`. No rule was
disabled and no severity floor was raised. Tests went from 45 to 61, including the four
real-world key shapes above as named negative controls and both dolthub/dolt and a plain
literal as positive ones.

## 0.1.2

`--exclude` for the CLI and the action, so a repository that ships deliberately-broken
example workflows can skip those paths without disabling a rule everywhere else.
