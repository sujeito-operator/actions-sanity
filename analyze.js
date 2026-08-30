'use strict';
// GitHub Actions workflow analysis, deliberately free of any vscode import so it can be
// unit-tested under plain node. That is not a style preference: on both previous
// extensions in this family the plain-node tests caught defects that clicking around in
// an Editor window did not.
//
// The differentiator against the incumbents in this niche is that nothing has to be
// installed. `actionlint` is a Go binary the user must fetch and keep on PATH; the
// security scanners are hosted services that want a repository connection. This is a
// parse and a set of rules, in-process, on the buffer you are already looking at.

const yaml = require('js-yaml');

// ---------------------------------------------------------------------------
// Locating findings in the source text.
//
// js-yaml gives structure and no positions. Rather than swap in a
// position-preserving parser (a much larger dependency for one field), every rule
// carries the token it fired on and we find that token in the raw lines. A rule that
// cannot find its own token reports line 0 rather than guessing, and a wrong line is
// the one defect a reader notices immediately -- so `find` matches on the whole token
// and never on a prefix.
// ---------------------------------------------------------------------------

function splitLines(text) {
  return text.split(/\r?\n/);
}

// First line at or after `from` that contains `needle` (a plain substring).
function find(lines, needle, from = 0) {
  if (!needle) return -1;
  for (let i = Math.max(0, from); i < lines.length; i++) {
    if (lines[i].includes(needle)) return i;
  }
  return -1;
}

// First line at or after `from` whose content is the mapping key `key` at any indent.
// The optional `- ` matters: a step is a sequence item, so the first key of every step
// in the file is written `- uses:` / `- run:` and an anchored `^\s*uses:` finds none of
// them. Without it every step-scoped finding fell back to the line of its job header.
function findKey(lines, key, from = 0, to = Infinity) {
  const re = new RegExp('^\\s*(-\\s+)?' + key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\s*:');
  for (let i = Math.max(0, from); i < Math.min(lines.length, to); i++) {
    if (re.test(lines[i])) return i;
  }
  return -1;
}

// The line ranges of each job, so a job-scoped finding lands inside its own job rather
// than on the first textual match anywhere in the file. Jobs are the children of the
// top-level `jobs:` key, so their indent is whatever the first child uses.
function jobRanges(lines, jobIds) {
  const jobsLine = findKey(lines, 'jobs', 0);
  const ranges = {};
  if (jobsLine < 0) return ranges;

  let indent = null;
  const starts = [];
  for (let i = jobsLine + 1; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim() || /^\s*#/.test(line)) continue;
    const m = line.match(/^(\s*)([A-Za-z0-9_.-]+)\s*:/);
    if (!m) continue;
    if (m[1].length === 0) break;               // back out to another top-level key
    if (indent === null) indent = m[1].length;
    if (m[1].length !== indent) continue;       // deeper: a key inside a job
    if (!jobIds.includes(m[2])) break;          // a sibling of `jobs:` at odd indent
    starts.push([m[2], i]);
  }
  for (let k = 0; k < starts.length; k++) {
    const end = k + 1 < starts.length ? starts[k + 1][1] : lines.length;
    ranges[starts[k][0]] = [starts[k][1], end];
  }
  return ranges;
}

// ---------------------------------------------------------------------------
// Rule data.
// ---------------------------------------------------------------------------

// The expressions an attacker controls. This list is GitHub's own -- the contexts named
// in "Understanding the risk of script injections" in the Actions hardening guide --
// and it is deliberately a LIST rather than a pattern like `github.event.*`, because
// most of `github.event` is not attacker-controlled (`github.event.number`,
// `github.event.action`, `github.event.repository.id` and so on are not) and flagging
// those would make the rule noise.
const UNTRUSTED = [
  'github.event.issue.title',
  'github.event.issue.body',
  'github.event.pull_request.title',
  'github.event.pull_request.body',
  'github.event.pull_request.head.ref',
  'github.event.pull_request.head.label',
  'github.event.pull_request.head.repo.default_branch',
  'github.event.pull_request.head.repo.description',
  'github.event.pull_request.head.repo.homepage',
  'github.event.comment.body',
  'github.event.review.body',
  'github.event.review_comment.body',
  'github.event.discussion.title',
  'github.event.discussion.body',
  'github.event.head_commit.message',
  'github.event.head_commit.author.email',
  'github.event.head_commit.author.name',
  'github.event.commits',           // .*.message / .*.author.*
  'github.event.pages',             // .*.page_name
  'github.head_ref',
];

// Triggers that hand a workflow a WRITE token and the repository secrets while the code
// under test is still the contributor's. This is the pairing that makes rule
// `untrusted-checkout` a finding rather than a preference.
const PRIVILEGED_TRIGGERS = ['pull_request_target', 'workflow_run'];

// The refs that resolve to the contributor's own commit.
const UNTRUSTED_REFS = [
  'github.event.pull_request.head.sha',
  'github.event.pull_request.head.ref',
  'github.event.pull_request.merge_commit_sha',
  'github.head_ref',
  'github.event.workflow_run.head_sha',
  'github.event.workflow_run.head_branch',
];

const FIRST_PARTY = /^(actions|github)\//;

// Expression scopes whose value is chosen somewhere this file cannot read: another
// job's output, an earlier step's output, an environment variable a `run:` step may
// have written with `>> $GITHUB_ENV`, a reusable-workflow input, a matrix leg, or a
// repository variable. A cache key built from one of these is not knowable as static
// or varying from the text, so `cache-key-static` says nothing about it.
const OPAQUE_REF = /\$\{\{[^}]*\b(needs|steps|env|inputs|matrix|vars|secrets)\./;

function isSha(ref) {
  return /^[0-9a-f]{40}$/i.test(ref);
}

// ---------------------------------------------------------------------------

function analyze(text) {
  const problems = [];
  const lines = splitLines(text);
  const add = (rule, severity, line, message) =>
    problems.push({ rule, severity, line: Math.max(0, line), message });

  let doc;
  try {
    // `json: false` keeps js-yaml's default refusal of duplicate mapping keys, which is
    // itself a finding worth surfacing: GitHub keeps the LAST one silently.
    doc = yaml.load(text, { schema: yaml.CORE_SCHEMA });
  } catch (err) {
    const line = err.mark && typeof err.mark.line === 'number' ? err.mark.line : 0;
    add('yaml', 'error', line,
      'This file is not valid YAML, so GitHub will not run it: ' +
      String(err.reason || err.message));
    return problems;
  }

  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return problems;

  // A workflow has jobs. Anything else in .github/workflows (a reusable config, a
  // stray note) is not ours to lint.
  const jobs = doc.jobs;
  if (!jobs || typeof jobs !== 'object') return problems;

  const jobIds = Object.keys(jobs);
  const ranges = jobRanges(lines, jobIds);

  // `on:` is the YAML 1.1 boolean `true` under the default schema, which is why this
  // parses with CORE_SCHEMA. Both spellings are read anyway: a file written by a tool
  // may quote it.
  const on = doc.on !== undefined ? doc.on : doc['on'];
  const triggers = on == null ? []
    : typeof on === 'string' ? [on]
    : Array.isArray(on) ? on.map(String)
    : Object.keys(on);

  const privileged = triggers.filter(t => PRIVILEGED_TRIGGERS.includes(t));

  // A `workflow_run` filtered to literal branch names cannot carry a contributor's code.
  // `branches:` matches the TRIGGERING run's `head_branch`, and a fork pull request's run
  // has the contributor's branch name there, not `main` -- so `branches: [main]` restricts
  // the checked-out `head_sha` to commits already on a trusted branch of the base
  // repository. A wildcard (`release-*`, `*`) can match a branch an outsider chose, so it
  // does not count, and `branches-ignore` constrains nothing about who wrote the code.
  //
  // Measured, not assumed: without this, the rule fired on BasedHardware/omi's
  // `gcp_backend_auto_dev.yml`, which is `workflow_run` on `branches: [main]` -- a false
  // positive, and a false positive is what a linter actually costs its user.
  const LITERAL_BRANCH = /^[^*?\[\]!]+$/;
  const trustedByBranchFilter = (trigger) => {
    if (trigger !== 'workflow_run') return false;
    if (on == null || typeof on === 'string' || Array.isArray(on)) return false;
    const spec = on[trigger];
    if (!spec || typeof spec !== 'object' || Array.isArray(spec)) return false;
    const branches = spec.branches;
    if (!Array.isArray(branches) || branches.length === 0) return false;
    return branches.every(b => typeof b === 'string' && LITERAL_BRANCH.test(b));
  };
  const privilegedUntrusted = privileged.filter(t => !trustedByBranchFilter(t));

  // --- workflow-level ------------------------------------------------------

  if (triggers.includes('schedule') && !triggers.includes('workflow_dispatch')) {
    add('schedule-no-dispatch', 'info', Math.max(0, findKey(lines, 'schedule')),
      'This workflow only runs on a schedule, so there is no way to run it by hand when ' +
      'it fails. Adding `workflow_dispatch:` to `on:` gives it a Run workflow button and ' +
      'costs nothing.');
  }

  const topPermissions = doc.permissions !== undefined;

  // Jobs running on the repository default token. Collected rather than reported
  // in place: measured against 40 real workflows the per-job form fired 55 times,
  // and the fix for all 55 is ONE top-level `permissions:` block. A rule that puts a
  // squiggle on every job in the file to say one thing is how a linter gets uninstalled.
  const unscoped = [];

  // Who depends on whom, read off `needs:` before the per-job walk. Used by
  // `job-continue-on-error` -- see there for what it changed and why.
  const dependents = {};
  for (const id of jobIds) {
    const j = jobs[id];
    if (!j || typeof j !== 'object') continue;
    const ns = j.needs == null ? [] : Array.isArray(j.needs) ? j.needs : [j.needs];
    for (const n of ns) {
      if (typeof n !== 'string') continue;
      (dependents[n] = dependents[n] || []).push(id);
    }
  }

  // --- per job -------------------------------------------------------------

  for (const jobId of jobIds) {
    const job = jobs[jobId];
    if (!job || typeof job !== 'object') continue;
    const [jstart, jend] = ranges[jobId] || [0, lines.length];
    const jobLine = ranges[jobId] ? jstart : 0;

    // needs: pointing at a job id that is not in this file. GitHub rejects the whole
    // workflow for this, so the run you are waiting for never starts.
    const needs = job.needs == null ? []
      : Array.isArray(job.needs) ? job.needs : [job.needs];
    for (const n of needs) {
      if (typeof n !== 'string' || jobIds.includes(n)) continue;
      const at = find(lines, n, jstart);
      add('needs-unknown-job', 'error', at >= 0 && at < jend ? at : jobLine,
        'Job `' + jobId + '` needs `' + n + '`, and there is no job called `' + n +
        '` in this file. GitHub refuses the whole workflow when a `needs:` cannot be ' +
        'resolved, so nothing in it runs.');
    }

    if (!topPermissions && job.permissions === undefined) unscoped.push([jobId, jobLine]);

    if (job['timeout-minutes'] === undefined) {
      add('no-timeout', 'info', jobLine,
        'Job `' + jobId + '` has no `timeout-minutes`, so a hung step runs for the ' +
        'default 6 hours before GitHub stops it, holding a runner the whole time.');
    }

    if (job['continue-on-error'] === true) {
      // MEASURED 2026-08-30 across ~570 workflow files in 30 professional repositories:
      // this fired 5 times as a `warning` and a hand-read rejected all 5. Every one was
      // a job that is non-blocking ON PURPOSE -- zitadel's `homebrew-tap`, `helm-chart`
      // and `npm-packages` release legs, fastly/cli's `golangci-latest` canary,
      // super-productivity's `deploy-preview`. The old message already conceded the
      // problem in its own second sentence: "IF this job is a required check". Whether
      // it is required lives in branch protection, which is not in this file, so at
      // `warning` the rule was asserting something it cannot see.
      //
      // One half of it IS visible here, and it is the sharper bug: GitHub counts a
      // `continue-on-error` job as SUCCESS when resolving `needs:`, so a job that other
      // jobs wait on cannot gate them. That is decidable from the text, so it keeps the
      // warning. A job nothing depends on drops to `info` and says what it cannot know.
      const waiters = dependents[jobId] || [];
      const line = (() => {
        const l = findKey(lines, 'continue-on-error', jstart, jend);
        return l >= 0 ? l : jobLine;
      })();
      if (waiters.length) {
        add('job-continue-on-error', 'warning', line,
          'Job `' + jobId + '` has `continue-on-error: true`, so it reports SUCCESS ' +
          'whatever happens inside it -- and `' + waiters.join('`, `') + '` ' +
          (waiters.length > 1 ? 'wait' : 'waits') + ' on it with `needs:`. GitHub ' +
          'treats a continue-on-error job as successful when resolving `needs:`, so ' +
          'this job cannot stop what comes after it, however it fails.');
      } else {
        add('job-continue-on-error', 'info', line,
          'Job `' + jobId + '` has `continue-on-error: true`, so it reports SUCCESS ' +
          'whatever happens inside it. Nothing in this file depends on it, so this is ' +
          'only a problem if branch protection lists it as a required check -- a green ' +
          'tick that cannot go red. That setting is not visible from the workflow.');
      }
    }

    const steps = Array.isArray(job.steps) ? job.steps : [];
    let cursor = jstart;

    for (const step of steps) {
      if (!step || typeof step !== 'object') continue;
      const uses = typeof step.uses === 'string' ? step.uses : null;
      const run = typeof step.run === 'string' ? step.run : null;
      const stepNeedle = uses ? 'uses:' : 'run:';
      let at = findKey(lines, uses ? 'uses' : 'run', cursor, jend);
      if (at < 0) at = jobLine; else cursor = at + 1;

      // -- script injection ------------------------------------------------
      // The script body, and the `script:` input of actions/github-script, are the two
      // places where an expression is expanded into code BEFORE the code runs. An
      // expression in `env:` is not: it arrives as an environment variable, which is
      // the documented fix, so `env:` is deliberately not checked.
      const scriptBodies = [];
      if (run) scriptBodies.push(run);
      if (uses && /^actions\/github-script@/.test(uses) &&
          step.with && typeof step.with.script === 'string') {
        scriptBodies.push(step.with.script);
      }
      for (const body of scriptBodies) {
        for (const ctx of UNTRUSTED) {
          const re = new RegExp('\\$\\{\\{[^}]*\\b' + ctx.replace(/\./g, '\\.') + '\\b');
          if (!re.test(body)) continue;
          const hit = find(lines, ctx, at >= 0 ? at : jstart);
          add('script-injection', 'error', hit >= 0 && hit < jend ? hit : at,
            '`' + ctx + '` is written by whoever opened the issue, pull request or ' +
            'comment, and here it is pasted straight into the shell script before the ' +
            'shell reads it -- so a title containing a backtick or `$(...)` runs as ' +
            'code on the runner, with this job\'s token. Pass it through `env:` and ' +
            'read `"$VAR"` inside the script instead; the value arrives the same way ' +
            'and is never parsed as source.');
          break;                                  // one finding per script body
        }
      }

      // -- untrusted checkout under a privileged trigger --------------------
      if (privilegedUntrusted.length && uses && /^actions\/checkout@/.test(uses)) {
        const ref = step.with && (step.with.ref || step.with.repository);
        const refStr = typeof ref === 'string' ? ref : '';
        const hitRef = UNTRUSTED_REFS.find(r => refStr.includes(r));
        if (hitRef) {
          const hit = find(lines, hitRef, at >= 0 ? at : jstart);
          add('untrusted-checkout', 'error', hit >= 0 && hit < jend ? hit : at,
            'This workflow runs on `' + privilegedUntrusted[0] + '`, which means it gets a ' +
            'read/write token and the repository secrets, and this step checks out ' +
            '`' + hitRef + '` -- the contributor\'s own code. Anything they put in a ' +
            'build script, a test, or a dependency hook then runs with that token. ' +
            'Check out the base commit, or move the job that needs the contributor\'s ' +
            'code onto `pull_request`, where the token is read-only.');
        }
      }

      // -- action pinning ---------------------------------------------------
      if (uses && !uses.startsWith('./') && !uses.startsWith('docker://')) {
        const [name, ref] = uses.split('@');
        if (!ref) {
          add('unpinned-action', 'error', at,
            '`' + uses + '` names no version at all, so GitHub resolves it to the ' +
            'action\'s default branch and the step can change under you between two ' +
            'runs of the same commit.');
        } else if (!FIRST_PARTY.test(name) && !isSha(ref)) {
          const mutable = !/^v?\d/.test(ref);
          add(mutable ? 'action-branch-ref' : 'unpinned-action',
            mutable ? 'error' : 'warning', at,
            '`' + name + '` is pinned to ' + (mutable ? 'the branch' : 'the tag') +
            ' `' + ref + '`, which its author can move at any time -- ' +
            (mutable
              ? 'every push to that branch is a silent change to what runs here'
              : 'a tag is a pointer, not a version, and re-tagging is how the ' +
                'tj-actions/changed-files compromise reached tens of thousands of ' +
                'repositories') +
            '. Pin third-party actions to a full commit SHA and put the version in a ' +
            'trailing comment.');
        }
      }

      // -- cache keys, in both directions -----------------------------------
      // MEASURED 2026-08-30 against ~570 workflow files in 30 professional
      // repositories: `cache-key-static` fired 8 times and a hand-read rejected all 8.
      // SEVEN of the eight were one cause -- the key is a REFERENCE, not a literal, and
      // this rule read the reference text:
      //
      //   PrefectHQ/prefect  key: ${{ needs.setup.outputs.cache-key }}   (x4)
      //   mondoohq/cnspec    key: ...-${{ env.PROVIDER_CACHE_DAY }}
      //   gruntwork/terragrunt  key: gon-${{ env.GON_VERSION }}
      //   LMCache/LMCache    key: hf-hub-${{ matrix.model.name }}-v2
      //
      // Prefect is the sharpest: `setup` computes the key ONCE from
      // `hashFiles('ui-v2/package-lock.json')` and publishes it as a job output, which is
      // the recommended shape for a multi-job workflow -- and this rule reported the four
      // consumers of a correct design. When the key is assembled out of this file's
      // sight, whether it tracks the lockfile is NOT DECIDABLE HERE, and a linter that
      // guesses in that situation is the false positive that gets it uninstalled.
      // `runner.*` and `github.*` are deliberately NOT in this list: they resolve to
      // values this rule can reason about, so `${{ runner.os }}-docker-integrations`
      // (dolthub/dolt, the ONE true instance in the sweep) still reports.
      // A cache key can be wrong two opposite ways and the first version of this rule
      // reported the wrong one on a real workflow. A key holding `github.sha` changes
      // on EVERY run, so nothing ever restores it -- unless `restore-keys` is set, which
      // is the documented rolling-cache pattern and is correct. A key holding no file
      // hash never changes, so the same cache is restored forever.
      if (uses && /^actions\/cache@/.test(uses) && step.with &&
          typeof step.with.key === 'string') {
        const key = step.with.key;
        const restore = typeof step.with['restore-keys'] === 'string'
          ? step.with['restore-keys'] : (Array.isArray(step.with['restore-keys']) ? 'set' : '');
        const hit = findKey(lines, 'key', at >= 0 ? at : jstart, jend);
        const line = hit >= 0 ? hit : at;
        if (/github\.(sha|run_id|run_number|run_attempt)/.test(key)) {
          if (!restore) {
            add('cache-key-per-run', 'warning', line,
              'This cache key changes on every run, and there are no `restore-keys` to ' +
              'fall back to a previous one -- so every run writes a cache that no run ' +
              'will ever read. Either add a `restore-keys:` prefix, or key on ' +
              '`hashFiles(...)` of the lockfile.');
          }
        } else if (OPAQUE_REF.test(key) || OPAQUE_REF.test(restore)) {
          // Silent on purpose. See OPAQUE_REF: the key is assembled somewhere this
          // file cannot read, so whether it tracks the lockfile is not decidable here.
        } else if (!/hashFiles\s*\(/.test(key) && !/hashFiles\s*\(/.test(restore)) {
          add('cache-key-static', 'warning', line,
            'This cache key contains no `hashFiles(...)`, so it does not change when the ' +
            'lockfile does. The first run stores a cache under this key and every later ' +
            'run restores that same one -- the build gets faster and stops seeing your ' +
            'dependency updates.');
        }
      }
    }
  }

  if (unscoped.length) {
    const all = unscoped.length === jobIds.length;
    add('no-permissions', 'warning', all ? Math.max(0, findKey(lines, 'jobs')) : unscoped[0][1],
      (all
        ? 'No job in this workflow sets `permissions:`, so every GITHUB_TOKEN here gets '
        : 'Job' + (unscoped.length > 1 ? 's' : '') + ' `' +
          unscoped.map(u => u[0]).join('`, `') + '` set no `permissions:`, so their ' +
          'GITHUB_TOKEN gets ') +
      'the repository default -- on repositories and organisations created before ' +
      'February 2023 that is write access to every scope, handed to every step ' +
      'including third-party actions. ' +
      (all
        ? 'One top-level `permissions:` block fixes the whole file; start from ' +
          '`permissions:\n  contents: read` and add back what a job actually needs.'
        : 'Declare the scopes those jobs actually need.'));
  }

  problems.sort((a, b) => a.line - b.line || a.rule.localeCompare(b.rule));
  return problems;
}

module.exports = { analyze, splitLines, find, findKey, jobRanges, UNTRUSTED };
