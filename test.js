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

console.log('cache and schedule');
t('flags a cache key with no hashFiles', () =>
  assert.ok(has(CLEAN.replace("key: npm-${{ hashFiles('package-lock.json') }}", 'key: npm-cache'), 'cache-key-static')));
t('accepts hashFiles in restore-keys instead of key', () => {
  const wf = CLEAN.replace("key: npm-${{ hashFiles('package-lock.json') }}",
    "key: npm-cache\n          restore-keys: npm-${{ hashFiles('package-lock.json') }}");
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

console.log(failures ? `\n${failures} FAILING` : '\nall passing');
process.exit(failures ? 1 : 0);
