'use strict';
// Plain-node tests. No framework -- run with `node test.js`.
// Every rule gets a positive case AND a negative control, because a linter's real cost
// is the false positive: one wrong finding on a file the reader knows is fine and the
// extension is uninstalled.
const assert = require('assert');
const { analyze, findKey, jobRanges } = require('./analyze.js');

let failures = 0;
function t(name, fn) {
  try { fn(); console.log('  ok   ' + name); }
  catch (e) { failures++; console.log('  FAIL ' + name + '\n       ' + e.message); }
}
const rules = (wf) => analyze(wf).map(p => p.rule);
const has = (wf, rule) => rules(wf).includes(rule);
const at = (wf, rule) => (analyze(wf).find(p => p.rule === rule) || {}).line;

// A workflow that is clean on every rule, used as the base for negative controls.
const CLEAN = `name: ci
on:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
      - uses: actions/cache@v4
        with:
          path: ~/.npm
          key: npm-\${{ hashFiles('package-lock.json') }}
      - run: npm test
`;

console.log('baseline');
t('the clean workflow reports nothing at all', () => {
  assert.deepStrictEqual(analyze(CLEAN), [], JSON.stringify(analyze(CLEAN), null, 1));
});
t('empty input returns no problems', () => assert.deepStrictEqual(analyze(''), []));
t('a YAML file with no jobs is not a workflow and is left alone', () =>
  assert.deepStrictEqual(analyze('name: notes\nvalue: 3\n'), []));
t('junk input does not throw', () => { analyze('\u0000\u0001 [[[ }}}'); });
t('problems are ordered by line', () => {
  const p = analyze(`on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: some/thing@main
      - run: echo "\${{ github.event.issue.title }}"
`);
  for (let i = 1; i < p.length; i++) assert.ok(p[i].line >= p[i - 1].line);
});

console.log('invalid YAML');
t('reports a parse error rather than staying silent', () => {
  const p = analyze('on: push\njobs:\n  a:\n   - x\n  b:\n\t bad tab\n');
  assert.strictEqual(p.length, 1);
  assert.strictEqual(p[0].rule, 'yaml');
});
t('reports a duplicate key, which GitHub resolves silently to the last one', () => {
  const p = analyze('on: push\njobs:\n  a:\n    runs-on: x\n    runs-on: y\n');
  assert.strictEqual(p[0].rule, 'yaml');
});

console.log('script injection');
const INJECT = `on: issues
permissions: {contents: read}
jobs:
  greet:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - run: echo "\${{ github.event.issue.title }}"
`;
t('flags an issue title interpolated into run:', () => assert.ok(has(INJECT, 'script-injection')));
t('points at the line the expression is on', () => assert.strictEqual(at(INJECT, 'script-injection'), 7));
t('flags github.head_ref in a script', () =>
  assert.ok(has(INJECT.replace('github.event.issue.title', 'github.head_ref'), 'script-injection')));
t('flags the script: input of actions/github-script', () => assert.ok(has(`on: issue_comment
permissions: {contents: read}
jobs:
  a:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: actions/github-script@v7
        with:
          script: console.log("\${{ github.event.comment.body }}")
`, 'script-injection')));
t('does NOT flag the same value passed through env:, which is the documented fix', () => {
  const fixed = `on: issues
permissions: {contents: read}
jobs:
  greet:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - env:
          TITLE: \${{ github.event.issue.title }}
        run: echo "$TITLE"
`;
  assert.ok(!has(fixed, 'script-injection'), rules(fixed).join());
});
t('does NOT flag github.event fields the attacker does not control', () => {
  const ok = INJECT.replace('github.event.issue.title', 'github.event.issue.number');
  assert.ok(!has(ok, 'script-injection'), rules(ok).join());
});
t('does NOT flag github.repository or github.sha', () => {
  assert.ok(!has(INJECT.replace('github.event.issue.title', 'github.repository'), 'script-injection'));
  assert.ok(!has(INJECT.replace('github.event.issue.title', 'github.sha'), 'script-injection'));
});
t('reports one finding per script body, not one per line of it', () => {
  const many = `on: issues
permissions: {contents: read}
jobs:
  a:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - run: |
          echo "\${{ github.event.issue.title }}"
          echo "\${{ github.event.issue.body }}"
`;
  assert.strictEqual(rules(many).filter(r => r === 'script-injection').length, 1);
});

console.log('untrusted checkout under a privileged trigger');
const PRT = `on: pull_request_target
permissions: {contents: read}
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - run: npm ci && npm test
`;
t('flags checkout of the PR head under pull_request_target', () =>
  assert.ok(has(PRT, 'untrusted-checkout')));
t('flags it under workflow_run too', () =>
  assert.ok(has(PRT.replace('on: pull_request_target', 'on: workflow_run')
                  .replace('github.event.pull_request.head.sha', 'github.event.workflow_run.head_sha'),
             'untrusted-checkout')));
t('does NOT flag the same checkout under pull_request, where the token is read-only', () => {
  const ok = PRT.replace('on: pull_request_target', 'on: pull_request');
  assert.ok(!has(ok, 'untrusted-checkout'), rules(ok).join());
});
t('does NOT flag a plain checkout under pull_request_target', () => {
  const ok = `on: pull_request_target
permissions: {contents: read}
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@v4
      - run: echo base only
`;
  assert.ok(!has(ok, 'untrusted-checkout'), rules(ok).join());
});

console.log('action pinning');
const usesWf = (u) => `on: push
permissions: {contents: read}
jobs:
  a:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: ${u}
`;
t('flags a third-party action on a branch', () =>
  assert.ok(has(usesWf('tj-actions/changed-files@main'), 'action-branch-ref')));
t('flags a third-party action on a tag, as a warning not an error', () => {
  const p = analyze(usesWf('tj-actions/changed-files@v44')).find(x => x.rule === 'unpinned-action');
  assert.ok(p); assert.strictEqual(p.severity, 'warning');
});
t('accepts a third-party action pinned to a full SHA', () => {
  const ok = usesWf('tj-actions/changed-files@a1b2c3d4e5f60718293a4b5c6d7e8f9012345678 # v44');
  assert.ok(!rules(ok).some(r => r.startsWith('unpinned') || r === 'action-branch-ref'), rules(ok).join());
});
t('does NOT nag about actions/* and github/*, which GitHub itself publishes', () => {
  assert.ok(!has(usesWf('actions/setup-node@v4'), 'unpinned-action'));
  assert.ok(!has(usesWf('github/codeql-action/analyze@v3'), 'unpinned-action'));
});
t('flags a uses: with no version at all', () =>
  assert.ok(has(usesWf('some/action'), 'unpinned-action')));

// --- first party by owner ---------------------------------------------------
// The three shapes below are the MEASURED false positives from the 2026-08-29/30 sweep
// of ~570 workflow files, not invented cases. Each one had this tool telling an owner
// that "its author" might re-tag an action that owner publishes.
const owned = (wf, owner) => analyze(wf, { owner }).map(p => p.rule);
t('commaai/timeout@v1 inside commaai is first party, not unpinned-action', () => {
  assert.ok(has(usesWf('commaai/timeout@v1'), 'unpinned-action'), 'baseline: fires with no owner');
  assert.ok(!owned(usesWf('commaai/timeout@v1'), 'commaai').includes('unpinned-action'));
});
t('temporalio/deputy/actions/x@main inside temporalio is first party', () => {
  const wf = usesWf('temporalio/deputy/actions/setup@main');
  assert.ok(rules(wf).includes('action-branch-ref'), 'baseline: fires with no owner');
  assert.ok(!owned(wf, 'temporalio').includes('action-branch-ref'));
});
t('dolthub/label-customer-issues@main inside dolthub is first party', () =>
  assert.ok(!owned(usesWf('dolthub/label-customer-issues@main'), 'dolthub')
    .includes('action-branch-ref')));
t('owner matching is case-insensitive, as GitHub owner names are', () =>
  assert.ok(!owned(usesWf('CommaAI/timeout@v1'), 'commaai').includes('unpinned-action')));

// The exemption must not become a hole. These are the cases where it must NOT apply.
t('a DIFFERENT owner is still third party even when an owner is known', () => {
  const r = owned(usesWf('tj-actions/changed-files@main'), 'commaai');
  assert.ok(r.includes('action-branch-ref'), r.join());
});
t('an owner that is a PREFIX of the action owner does not exempt it', () => {
  // `comma` must not swallow `commaai/`. Matching the segment, not the string, is the
  // difference between an exemption and a bypass anyone can register a name for.
  assert.ok(owned(usesWf('commaai/timeout@main'), 'comma').includes('action-branch-ref'));
  assert.ok(owned(usesWf('comma/timeout@main'), 'commaai').includes('action-branch-ref'));
});
t('no owner, empty owner and junk owner all leave every rule reporting', () => {
  for (const o of [undefined, null, '', '   ', 42, {}]) {
    assert.ok(analyze(usesWf('commaai/timeout@main'), { owner: o })
      .some(p => p.rule === 'action-branch-ref'), `owner=${JSON.stringify(o)}`);
  }
  assert.ok(has(usesWf('commaai/timeout@main'), 'action-branch-ref'));
});
t('a first-party action with NO ref at all still reports -- a different defect', () => {
  // Not an oversight: no `@` means the workflow text does not say what it runs, which is
  // unreadable for the repository's own maintainers however owns the action. This is
  // also the pre-existing behaviour for actions/* and it is deliberately unchanged.
  assert.ok(owned(usesWf('commaai/timeout'), 'commaai').includes('unpinned-action'));
  assert.ok(has(usesWf('actions/checkout'), 'unpinned-action'));
});
t('the owner exemption changes nothing else about a workflow', () => {
  assert.deepStrictEqual(analyze(CLEAN, { owner: 'someone' }), []);
  const wf = usesWf('commaai/timeout@main');
  const dropped = rules(wf).filter(r => !owned(wf, 'commaai').includes(r));
  assert.deepStrictEqual(dropped, ['action-branch-ref'], dropped.join());
});
t('does NOT flag a local action or a docker:// reference', () => {
  assert.ok(!rules(usesWf('./.github/actions/build')).some(r => r.includes('pinned') || r.includes('branch-ref')));
  assert.ok(!rules(usesWf('docker://alpine:3.20')).some(r => r.includes('pinned') || r.includes('branch-ref')));
});

console.log('needs');
t('flags a needs: that names a job which does not exist', () => {
  const wf = `on: push
permissions: {contents: read}
jobs:
  a:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps: [{run: echo}]
  b:
    needs: buld
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps: [{run: echo}]
`;
  assert.ok(has(wf, 'needs-unknown-job'), rules(wf).join());
});
t('accepts a needs: list where every entry exists', () => {
  const wf = `on: push
permissions: {contents: read}
jobs:
  a:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps: [{run: echo}]
  b:
    needs: [a]
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps: [{run: echo}]
`;
  assert.ok(!has(wf, 'needs-unknown-job'), rules(wf).join());
});

console.log('token scope, timeouts and green ticks that cannot go red');
t('flags a job with no permissions anywhere', () =>
  assert.ok(has(CLEAN.replace('permissions:\n  contents: read\n', ''), 'no-permissions')));
t('accepts per-job permissions with no top-level block', () => {
  const wf = CLEAN.replace('permissions:\n  contents: read\n', '')
                  .replace('    runs-on: ubuntu-latest', '    permissions:\n      contents: read\n    runs-on: ubuntu-latest');
  assert.ok(!has(wf, 'no-permissions'), rules(wf).join());
});
t('flags a job with no timeout-minutes', () =>
  assert.ok(has(CLEAN.replace('    timeout-minutes: 10\n', ''), 'no-timeout')));
t('flags continue-on-error on a job', () => {
  const wf = CLEAN.replace('    runs-on: ubuntu-latest', '    continue-on-error: true\n    runs-on: ubuntu-latest');
  assert.ok(has(wf, 'job-continue-on-error'), rules(wf).join());
});
t('does NOT flag continue-on-error on a single step', () => {
  const wf = CLEAN.replace('      - run: npm test', '      - run: npm test\n        continue-on-error: true');
  assert.ok(!has(wf, 'job-continue-on-error'), rules(wf).join());
});

// Measured 2026-08-30: 5 hits across ~570 real workflow files, 0 filable. Every one was
// a deliberately non-blocking job nothing depended on. The half that IS visible from the
// file -- a job others `needs:` -- keeps the warning; the rest says what it cannot know.
console.log('continue-on-error severity follows what the file can actually see');
const COE = (extra) => `on: push
permissions:
  contents: read
jobs:
  flaky:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    continue-on-error: true
    steps: [{run: ./maybe.sh}]
` + extra;
t('a continue-on-error job nothing depends on is info, not a warning', () => {
  const p = analyze(COE('')).find(x => x.rule === 'job-continue-on-error');
  assert.ok(p, rules(COE('')).join());
  assert.strictEqual(p.severity, 'info', JSON.stringify(p));
  assert.ok(/not visible from the workflow/.test(p.message), p.message);
});
t('a continue-on-error job that others `needs:` stays a warning, and names them', () => {
  const wf = COE(`  ship:
    needs: flaky
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps: [{run: ./ship.sh}]
`);
  const p = analyze(wf).find(x => x.rule === 'job-continue-on-error');
  assert.ok(p, rules(wf).join());
  assert.strictEqual(p.severity, 'warning', JSON.stringify(p));
  assert.ok(/`ship`/.test(p.message), p.message);
  assert.ok(/cannot stop what comes after it/.test(p.message), p.message);
});
t('a needs: written as a list is followed too', () => {
  const wf = COE(`  ship:
    needs: [flaky]
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps: [{run: ./ship.sh}]
`);
  const p = analyze(wf).find(x => x.rule === 'job-continue-on-error');
  assert.strictEqual(p.severity, 'warning', JSON.stringify(p));
});
t('zitadel\'s release legs -- three non-blocking jobs -- report info, not three warnings', () => {
  const wf = `on: push
permissions:
  contents: read
jobs:
  homebrew-tap:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    continue-on-error: true
    steps: [{run: ./tap.sh}]
  helm-chart:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    continue-on-error: true
    steps: [{run: ./helm.sh}]
  npm-packages:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    continue-on-error: true
    steps: [{run: ./npm.sh}]
`;
  const ps = analyze(wf).filter(x => x.rule === 'job-continue-on-error');
  assert.strictEqual(ps.length, 3, JSON.stringify(ps));
  assert.ok(ps.every(p => p.severity === 'info'), JSON.stringify(ps));
});

console.log('cache and schedule');
t('flags a cache key with no hashFiles', () =>
  assert.ok(has(CLEAN.replace("key: npm-${{ hashFiles('package-lock.json') }}", 'key: npm-cache'), 'cache-key-static')));
t('accepts hashFiles in restore-keys instead of key', () => {
  const wf = CLEAN.replace("key: npm-${{ hashFiles('package-lock.json') }}",
    "key: npm-cache\n          restore-keys: npm-${{ hashFiles('package-lock.json') }}");
  assert.ok(!has(wf, 'cache-key-static'), rules(wf).join());
});

// Measured 2026-08-30 across ~570 real workflow files: 8 cache-key-static hits, 0
// filable, and SEVEN were this -- a key the rule read as text when it was a reference.
console.log('cache-key-static is silent on a key it cannot resolve (7 of 8 false hits)');
const KEYED = (key) => CLEAN.replace("key: npm-${{ hashFiles('package-lock.json') }}", 'key: ' + key);
t("PrefectHQ/prefect: a key taken from another job's output is not readable here", () =>
  assert.ok(!has(KEYED('${{ needs.setup.outputs.cache-key }}'), 'cache-key-static'),
    rules(KEYED('${{ needs.setup.outputs.cache-key }}')).join()));
t('mondoohq/cnspec: a key holding an env var a run: step wrote is not readable here', () =>
  assert.ok(!has(KEYED('${{ runner.os }}-mql-providers-${{ env.PROVIDER_CACHE_DAY }}'),
    'cache-key-static')));
t('gruntwork-io/terragrunt: a key holding a tool version from env is not readable here', () =>
  assert.ok(!has(KEYED('gon-${{ env.GON_VERSION }}'), 'cache-key-static')));
t('LMCache/LMCache: a key varying per matrix leg is not readable here', () =>
  assert.ok(!has(KEYED('hf-hub-${{ matrix.model.name }}-v2'), 'cache-key-static')));
t("a key from an earlier step's output is not readable here", () =>
  assert.ok(!has(KEYED('${{ steps.k.outputs.value }}'), 'cache-key-static')));
t('a reusable-workflow input is not readable here', () =>
  assert.ok(!has(KEYED('deps-${{ inputs.profile }}'), 'cache-key-static')));
t('an opaque reference in restore-keys silences it too', () => {
  const wf = CLEAN.replace("key: npm-${{ hashFiles('package-lock.json') }}",
    'key: npm-cache\n          restore-keys: ${{ needs.setup.outputs.prefix }}');
  assert.ok(!has(wf, 'cache-key-static'), rules(wf).join());
});
t('dolthub/dolt: a genuinely static key STILL reports -- the rule was not just muted', () => {
  const wf = KEYED('${{ runner.os }}-docker-mysql-client-integrations\n' +
    '          restore-keys: |\n            ${{ runner.os }}-docker');
  assert.ok(has(wf, 'cache-key-static'), rules(wf).join());
});
t('a plain literal key STILL reports', () =>
  assert.ok(has(KEYED('npm-cache'), 'cache-key-static')));
t('github.sha still outranks the opaque check, so the per-run finding is not lost', () => {
  const wf = KEYED('build-${{ github.sha }}-${{ env.FLAVOUR }}');
  assert.ok(has(wf, 'cache-key-per-run'), rules(wf).join());
  assert.ok(!has(wf, 'cache-key-static'), rules(wf).join());
});
t('flags a schedule-only workflow with no manual trigger', () => {
  const wf = CLEAN.replace('on:\n  push:\n    branches: [main]', "on:\n  schedule:\n    - cron: '0 3 * * *'");
  assert.ok(has(wf, 'schedule-no-dispatch'), rules(wf).join());
});
t('accepts schedule alongside workflow_dispatch', () => {
  const wf = CLEAN.replace('on:\n  push:\n    branches: [main]',
    "on:\n  workflow_dispatch:\n  schedule:\n    - cron: '0 3 * * *'");
  assert.ok(!has(wf, 'schedule-no-dispatch'), rules(wf).join());
});

console.log('noise control, measured against 40 real workflows');
t('no-permissions is reported once for the file, not once per job', () => {
  const wf = `on: push
jobs:
  a:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps: [{run: echo}]
  b:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps: [{run: echo}]
`;
  assert.strictEqual(rules(wf).filter(r => r === 'no-permissions').length, 1, rules(wf).join());
});
t('names the jobs when only some of them are unscoped', () => {
  const wf = `on: push
jobs:
  a:
    permissions: {contents: read}
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps: [{run: echo}]
  b:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps: [{run: echo}]
`;
  const p = analyze(wf).find(x => x.rule === 'no-permissions');
  assert.ok(p && p.message.includes('`b`'), JSON.stringify(p));
  assert.ok(!p.message.includes('`a`'));
});
t('a per-run cache key with no restore-keys is the OPPOSITE finding, worded as such', () => {
  const wf = CLEAN.replace("key: npm-${{ hashFiles('package-lock.json') }}",
                           'key: build-${{ github.sha }}');
  const p = analyze(wf).find(x => x.rule === 'cache-key-per-run');
  assert.ok(p, rules(wf).join());
  assert.ok(/no run will ever read/.test(p.message), p.message);
  assert.ok(!has(wf, 'cache-key-static'));
});
t('a per-run cache key WITH restore-keys is the documented rolling pattern, not a finding', () => {
  const wf = CLEAN.replace("key: npm-${{ hashFiles('package-lock.json') }}",
    'key: build-${{ github.sha }}\n          restore-keys: build-');
  assert.ok(!rules(wf).some(r => r.startsWith('cache-key')), rules(wf).join());
});

console.log('locating findings');
t('jobRanges keeps a finding inside its own job', () => {
  const wf = `on: push
permissions: {contents: read}
jobs:
  first:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@v4
  second:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: bad/action@main
`;
  const line = at(wf, 'action-branch-ref');
  assert.ok(line > 8, 'expected the finding inside `second`, got line ' + line);
});
t('findKey matches a whole key and not a prefix of one', () => {
  const l = ['  keychain: x', '  key: y'];
  assert.strictEqual(findKey(l, 'key'), 1);
});

console.log('\nworkflow_run branch filters (untrusted-checkout precision)');
t('workflow_run filtered to a literal branch is not an untrusted checkout', () => {
  // The real fixture this rule was wrong about: BasedHardware/omi.
  const p = analyze(`name: deploy
on:
  workflow_run:
    workflows: ["Release Eligibility"]
    branches: [main]
    types: [completed]
jobs:
  d:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.workflow_run.head_sha }}
`);
  assert.ok(!p.some(x => x.rule === 'untrusted-checkout'),
    'fired on a workflow_run restricted to main: ' + JSON.stringify(p.filter(x=>x.rule==='untrusted-checkout')));
});
t('a wildcard branch filter can match a fork branch, so it still fires', () => {
  const p = analyze(`name: deploy
on:
  workflow_run:
    workflows: ["x"]
    branches: ["release-*"]
    types: [completed]
jobs:
  d:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.workflow_run.head_sha }}
`);
  assert.ok(p.some(x => x.rule === 'untrusted-checkout'), JSON.stringify(p));
});
t('an unfiltered workflow_run still fires', () => {
  const p = analyze(`name: deploy
on:
  workflow_run:
    workflows: ["x"]
    types: [completed]
jobs:
  d:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.workflow_run.head_sha }}
`);
  assert.ok(p.some(x => x.rule === 'untrusted-checkout'), JSON.stringify(p));
});
t('branches-ignore constrains nothing about who wrote the code, so it still fires', () => {
  const p = analyze(`name: deploy
on:
  workflow_run:
    workflows: ["x"]
    branches-ignore: [gh-pages]
    types: [completed]
jobs:
  d:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.workflow_run.head_sha }}
`);
  assert.ok(p.some(x => x.rule === 'untrusted-checkout'), JSON.stringify(p));
});
t('pull_request_target is never excused by a workflow_run branch filter', () => {
  const p = analyze(`name: deploy
on:
  pull_request_target:
  workflow_run:
    workflows: ["x"]
    branches: [main]
    types: [completed]
jobs:
  d:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
`);
  assert.ok(p.some(x => x.rule === 'untrusted-checkout'), JSON.stringify(p));
});

console.log(failures ? `\n${failures} FAILING` : '\nall passing');
process.exit(failures ? 1 : 0);
