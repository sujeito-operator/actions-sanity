'use strict';
// Tests for the command-line front end. Same harness as test.js: plain node, no
// framework, run with `node test-cli.js`.
//
// These drive run() through its io object rather than spawning a process, so the exit
// code, stdout and stderr are all assertable and the suite stays fast enough to run on
// every commit. The exit code is the part CI actually depends on, so it is asserted on
// every case, not just the failing ones.
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const cli = require('./cli.js');

let failures = 0;
function t(name, fn) {
  try { fn(); console.log('  ok   ' + name); }
  catch (e) { failures++; console.log('  FAIL ' + name + '\n       ' + (e.stack || e.message)); }
}

// `env` defaults to EMPTY, not process.env: owner detection reads GITHUB_REPOSITORY, and
// a suite that inherited it would pass or fail depending on whether it happened to be run
// inside GitHub Actions. Tests that care about it pass one in.
function invoke(argv, opts) {
  let out = '', err = '';
  const code = cli.run(argv, {
    stdout: s => { out += s; },
    stderr: s => { err += s; },
    colorDefault: (opts && opts.color) || false,
    env: (opts && opts.env) || {},
    cwd: (opts && opts.cwd) || process.cwd(),
  });
  return { code, out, err };
}

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'assanity-'));
const write = (rel, text) => {
  const full = path.join(tmp, rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, text);
  return full;
};

const CLEAN = `name: ci
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo hello
`;

// The canonical script-injection hole: an attacker writes the issue title, and the
// expression is expanded before bash parses the line.
const INJECT = `name: triage
on: issues
permissions:
  contents: read
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - run: echo "\${{ github.event.issue.title }}"
`;

const BRANCH_REF = `name: ci
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: some-vendor/some-action@main
`;

const cleanFile = write('.github/workflows/clean.yml', CLEAN);
const injectFile = write('.github/workflows/inject.yml', INJECT);

console.log('discovery');
t('a repository root finds .github/workflows', () => {
  const found = cli.collect([tmp], [], []);
  assert.strictEqual(found.length, 2, JSON.stringify(found));
});
t('.yaml is found as well as .yml', () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'assanity-y-'));
  fs.mkdirSync(path.join(d, '.github/workflows'), { recursive: true });
  fs.writeFileSync(path.join(d, '.github/workflows/a.yaml'), CLEAN);
  assert.strictEqual(cli.collect([d], [], []).length, 1);
  fs.rmSync(d, { recursive: true, force: true });
});
t('YAML outside .github/workflows is not linted', () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'assanity-o-'));
  fs.writeFileSync(path.join(d, 'docker-compose.yml'), 'services: {}\n');
  fs.mkdirSync(path.join(d, 'config'), { recursive: true });
  fs.writeFileSync(path.join(d, 'config/app.yml'), 'a: 1\n');
  assert.deepStrictEqual(cli.collect([d], [], []), []);
  fs.rmSync(d, { recursive: true, force: true });
});
t('pointing straight at .github/workflows works', () => {
  const found = cli.collect([path.join(tmp, '.github/workflows')], [], []);
  assert.strictEqual(found.length, 2);
});
t('GitHub does not recurse inside workflows, so neither does the walk', () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'assanity-r-'));
  fs.mkdirSync(path.join(d, '.github/workflows/nested'), { recursive: true });
  fs.writeFileSync(path.join(d, '.github/workflows/top.yml'), CLEAN);
  fs.writeFileSync(path.join(d, '.github/workflows/nested/deep.yml'), CLEAN);
  const found = cli.collect([d], [], []);
  assert.strictEqual(found.length, 1, JSON.stringify(found));
  assert.ok(found[0].endsWith('top.yml'));
  fs.rmSync(d, { recursive: true, force: true });
});
t('an explicit file is linted whatever it is called', () => {
  const odd = write('somewhere/pipeline.txt', INJECT);
  const r = invoke([odd]);
  assert.strictEqual(r.code, 1, r.out);
  assert.ok(/script-injection/.test(r.out), r.out);
});
t('.git is skipped and .github is not — they differ by three characters', () => {
  assert.ok(cli.SKIP_DIRS.has('.git'));
  assert.ok(!cli.SKIP_DIRS.has('.github'));
});
t('isWorkflowDir matches the real directory and not a lookalike', () => {
  assert.ok(cli.isWorkflowDir('.github/workflows'));
  assert.ok(cli.isWorkflowDir('/repo/.github/workflows/'));
  assert.ok(!cli.isWorkflowDir('/repo/github/workflows'));
  assert.ok(!cli.isWorkflowDir('/repo/.github/workflows-old'));
});

console.log('\nexit codes');
t('a clean workflow is exit 0', () => {
  const r = invoke([cleanFile]);
  assert.strictEqual(r.code, 0, r.out);
  assert.ok(/nothing to report in 1 workflow\./.test(r.out), r.out);
});
t('script injection is an error, so the default fail-on exits 1', () => {
  const r = invoke([injectFile]);
  assert.strictEqual(r.code, 1, r.out);
  assert.ok(/script-injection/.test(r.out), r.out);
});
t('--fail-on never reports and still exits 0', () => {
  const r = invoke(['--fail-on', 'never', injectFile]);
  assert.strictEqual(r.code, 0, r.out);
  assert.ok(/script-injection/.test(r.out), r.out);
});
t('an unreadable path is exit 2, never a quiet 0', () => {
  const r = invoke([path.join(tmp, 'does-not-exist')]);
  assert.strictEqual(r.code, 2, r.out);
  assert.ok(/cannot read/.test(r.err), r.err);
});
t('an unknown option is exit 2 and names itself', () => {
  const r = invoke(['--nonsense']);
  assert.strictEqual(r.code, 2);
  assert.ok(/unknown option --nonsense/.test(r.err), r.err);
});
t('an option missing its value is exit 2', () => {
  assert.strictEqual(invoke(['--fail-on']).code, 2);
});
t('a bad --fail-on value is refused rather than ignored', () => {
  const r = invoke(['--fail-on', 'catastrophe']);
  assert.strictEqual(r.code, 2);
  assert.ok(/--fail-on must be one of/.test(r.err), r.err);
});
t('no workflows found is exit 0 and says so', () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'assanity-e-'));
  const r = invoke([d]);
  assert.strictEqual(r.code, 0);
  assert.ok(/no \.github\/workflows found/.test(r.out), r.out);
  fs.rmSync(d, { recursive: true, force: true });
});

console.log('\nfiltering');
t('no-timeout is off by default, matching the editor', () => {
  assert.deepStrictEqual(cli.DEFAULT_DISABLED, ['no-timeout']);
  const r = invoke(['--fail-on', 'never', cleanFile]);
  assert.ok(!/no-timeout/.test(r.out), r.out);
});
t('--enable turns a default-off rule back on', () => {
  const r = invoke(['--enable', 'no-timeout', '--fail-on', 'never', cleanFile]);
  assert.ok(/no-timeout/.test(r.out), r.out);
});
t('--disable suppresses a rule and can flip the exit code', () => {
  const before = invoke([injectFile]);
  assert.strictEqual(before.code, 1);
  const after = invoke(['--disable', 'script-injection', injectFile]);
  assert.strictEqual(after.code, 0, after.out);
  assert.ok(!/script-injection/.test(after.out), after.out);
});
t('--min-severity hides the levels below it', () => {
  const r = invoke(['--min-severity', 'error', '--fail-on', 'never', path.join(tmp, '.github/workflows')]);
  assert.ok(!/warning/.test(r.out.replace(/\d+ warnings?/g, '')), r.out);
});
t('a third-party version tag is a warning, so adoption does not need a pinning sprint', () => {
  const f = write('.github/workflows/tagged.yml', BRANCH_REF.replace('@main', '@v3'));
  const r = invoke([f]);
  assert.strictEqual(r.code, 0, r.out);
  fs.rmSync(f);
});
t('a branch reference is an error, because its author can move it', () => {
  const f = write('.github/workflows/branch.yml', BRANCH_REF);
  const r = invoke([f]);
  assert.strictEqual(r.code, 1, r.out);
  assert.ok(/action-branch-ref/.test(r.out), r.out);
  fs.rmSync(f);
});

console.log('\njson');
t('--json is valid JSON and prints nothing else', () => {
  const r = invoke(['--json', injectFile]);
  const d = JSON.parse(r.out);
  assert.ok(Array.isArray(d.findings) && d.findings.length >= 1);
  assert.strictEqual(d.files.length, 1);
});
t('json findings carry file, 1-based line, rule and severity', () => {
  const d = JSON.parse(invoke(['--json', injectFile]).out);
  const f = d.findings.find(x => x.rule === 'script-injection');
  assert.ok(f, JSON.stringify(d.findings));
  assert.ok(f.line >= 1 && Number.isInteger(f.line));
  assert.strictEqual(f.severity, 'error');
  assert.ok(f.file.endsWith('inject.yml'));
});
t('the reported line points at the injecting expression', () => {
  const d = JSON.parse(invoke(['--json', injectFile]).out);
  const f = d.findings.find(x => x.rule === 'script-injection');
  const src = fs.readFileSync(injectFile, 'utf8').split('\n');
  assert.ok(/github\.event\.issue\.title/.test(src[f.line - 1]), src[f.line - 1]);
});
t('--json on a clean file is an empty findings array, not an absent one', () => {
  const d = JSON.parse(invoke(['--json', cleanFile]).out);
  assert.deepStrictEqual(d.findings, []);
});

console.log('\nrobustness');
t('invalid YAML is a finding, not a crash', () => {
  const f = write('.github/workflows/broken.yml', 'name: [unclosed\n  on: push\n');
  const r = invoke(['--fail-on', 'never', f]);
  assert.ok(r.code === 0, r.err);
  assert.ok(/yaml/.test(r.out), r.out);
  fs.rmSync(f);
});
t('a duplicate key is reported rather than silently kept', () => {
  const f = write('.github/workflows/dup.yml', 'name: a\nname: b\non: push\njobs: {}\n');
  const r = invoke(['--fail-on', 'never', f]);
  assert.ok(r.code === 0 || r.code === 1, r.err);
  fs.rmSync(f);
});
t('multiple paths are all scanned and the worst exit code wins', () => {
  const r = invoke([cleanFile, injectFile]);
  assert.strictEqual(r.code, 1, r.out);
  assert.ok(/in 2 workflows\./.test(r.out), r.out);
});
t('an empty file does not throw', () => {
  const f = write('.github/workflows/empty.yml', '');
  const r = invoke(['--fail-on', 'never', f]);
  assert.ok(r.code === 0 || r.code === 1, r.err);
  fs.rmSync(f);
});
t('the walk is deterministic — two runs list files in the same order', () => {
  assert.deepStrictEqual(cli.collect([tmp], [], []), cli.collect([tmp], [], []));
});
// --exclude. The case that forced it: this repository's own demo/ workflow is broken on
// purpose, so `lint this repository with itself` could never pass, and the only escape
// before this flag was to --disable script-injection everywhere.
t('a bare pattern excludes that directory at any depth', () => {
  const d = fs.mkdtempSync(path.join(tmp, 'exc-'));
  write(path.join(path.basename(d), 'demo/.github/workflows/bad.yml'), INJECT);
  write(path.join(path.basename(d), '.github/workflows/ok.yml'), CLEAN);
  const found = cli.collect([d], [], [], cli.makeMatcher(['demo'], []));
  assert.strictEqual(found.length, 1);
  assert.ok(found[0].endsWith('ok.yml'));
});
t('--exclude flips the exit code the demo workflow would have caused', () => {
  const d = fs.mkdtempSync(path.join(tmp, 'exc2-'));
  write(path.join(path.basename(d), 'demo/.github/workflows/bad.yml'), INJECT);
  write(path.join(path.basename(d), '.github/workflows/ok.yml'), CLEAN);
  assert.strictEqual(invoke([d]).code, 1);
  assert.strictEqual(invoke(['--exclude', 'demo', d]).code, 0);
});
t('an excluded path is reported, never silently dropped', () => {
  const d = fs.mkdtempSync(path.join(tmp, 'exc3-'));
  write(path.join(path.basename(d), 'demo/.github/workflows/bad.yml'), INJECT);
  write(path.join(path.basename(d), '.github/workflows/ok.yml'), CLEAN);
  const r = invoke(['--exclude', 'demo', d]);
  assert.ok(/excluded/.test(r.out), 'the summary never mentions the exclusion');
});
t('excluding everything says so rather than reporting a clean run', () => {
  const d = fs.mkdtempSync(path.join(tmp, 'exc4-'));
  write(path.join(path.basename(d), '.github/workflows/ok.yml'), CLEAN);
  const r = invoke(['--exclude', '**', d]);
  assert.strictEqual(r.code, 0);
  assert.ok(/excluded/.test(r.out), 'a fully-excluded run looks identical to an empty repo');
});
t('--json carries the excluded list', () => {
  const d = fs.mkdtempSync(path.join(tmp, 'exc5-'));
  write(path.join(path.basename(d), 'demo/.github/workflows/bad.yml'), INJECT);
  write(path.join(path.basename(d), '.github/workflows/ok.yml'), CLEAN);
  const parsed = JSON.parse(invoke(['--json', '--exclude', 'demo', d]).out);
  assert.strictEqual(parsed.findings.length, 0);
  assert.strictEqual(parsed.excluded.length, 1);
});
t('a glob matches inside one segment and ** crosses them', () => {
  assert.ok(cli.globToRe('*.yml').test('a.yml'));
  assert.ok(!cli.globToRe('*.yml').test('d/a.yml'), '* must not cross a separator');
  assert.ok(cli.globToRe('**/a.yml').test('d/e/a.yml'));
  assert.ok(cli.globToRe('a?c').test('abc'));
  assert.ok(!cli.globToRe('a.c').test('abc'), 'a dot is a literal, not any-character');
});
t('a path pattern with a separator is anchored and does not match a bare segment', () => {
  const m = cli.makeMatcher(['demo/**'], []);
  assert.ok(m('demo/.github/workflows/x.yml'));
  assert.ok(!m('src/demo.yml'));
});
t('an explicitly named file is still excluded — --exclude is the more specific instruction', () => {
  const f = write('explicit/hand.yml', INJECT);
  assert.strictEqual(invoke([f]).code, 1);
  assert.strictEqual(invoke(['--exclude', 'hand.yml', f]).code, 0);
});
t('--exclude with no value is exit 2 rather than silently excluding nothing', () => {
  assert.strictEqual(invoke(['--exclude']).code, 2);
});
t('no --exclude means nothing is skipped and no exclusion line is printed', () => {
  const d = fs.mkdtempSync(path.join(tmp, 'exc6-'));
  write(path.join(path.basename(d), '.github/workflows/ok.yml'), CLEAN);
  const r = invoke([d]);
  assert.ok(!/excluded/.test(r.out));
});

t('--help is exit 0 and lists the exit codes it documents', () => {
  const r = invoke(['--help']);
  assert.strictEqual(r.code, 0);
  assert.ok(/Exit codes/.test(r.out) && /--fail-on/.test(r.out));
});
t('--version prints the package version', () => {
  const r = invoke(['--version']);
  assert.strictEqual(r.code, 0);
  assert.strictEqual(r.out.trim(), require('./package.json').version);
});
t('every rule named in --help exists in the configuration enum', () => {
  const enumerated = require('./package.json')
    .contributes.configuration.properties['actionsSanity.disabledRules'].items.enum;
  const help = cli.usage();
  for (const rule of enumerated) {
    assert.ok(help.includes(rule), `--help never mentions ${rule}`);
  }
});

console.log('\nrepository owner detection');
// An owner resolved WRONGLY makes a real supply-chain finding disappear, so every source
// gets a test and so does every way of declining to answer.
const OWNED = `name: ci
on: push
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: commaai/timeout@main
`;
// A repository laid out like a real clone: a workflow, and a .git/config naming origin.
function repo(prefix, url, remote) {
  const d = fs.mkdtempSync(path.join(tmp, prefix));
  fs.mkdirSync(path.join(d, '.github', 'workflows'), { recursive: true });
  fs.writeFileSync(path.join(d, '.github', 'workflows', 'ci.yml'), OWNED);
  if (url !== null) {
    fs.mkdirSync(path.join(d, '.git'), { recursive: true });
    fs.writeFileSync(path.join(d, '.git', 'config'),
      `[core]\n\trepositoryformatversion = 0\n[remote "${remote || 'origin'}"]\n\turl = ${url}\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n`);
  }
  return d;
}

t('a no-owner run reports the owner\'s own action — the baseline being fixed', () => {
  const d = repo('own-none-', null);
  const r = invoke([d]);
  assert.strictEqual(r.code, 1);
  assert.ok(/action-branch-ref/.test(r.out), r.out);
  assert.ok(!/first party/.test(r.out), r.out);
});
t('--owner exempts the owner\'s own action and flips the exit code', () => {
  const d = repo('own-flag-', null);
  const r = invoke(['--owner', 'commaai', d]);
  assert.strictEqual(r.code, 0);
  assert.ok(!/action-branch-ref/.test(r.out), r.out);
});
t('GITHUB_REPOSITORY is read, which is what makes the Action work with no config', () => {
  const d = repo('own-env-', null);
  const r = invoke([d], { env: { GITHUB_REPOSITORY: 'commaai/opendbc' } });
  assert.strictEqual(r.code, 0);
  assert.ok(/commaai\/\*/.test(r.out) && /GITHUB_REPOSITORY/.test(r.out), r.out);
});
t('a malformed GITHUB_REPOSITORY is ignored rather than half-parsed', () => {
  for (const bad of ['commaai', '/opendbc', 'a/b/c', '', '   ']) {
    const d = repo('own-bad-', null);
    const r = invoke([d], { env: { GITHUB_REPOSITORY: bad } });
    assert.strictEqual(r.code, 1, `GITHUB_REPOSITORY=${JSON.stringify(bad)} was accepted`);
  }
});
t('the origin remote is read from .git/config, in all three URL spellings', () => {
  for (const url of ['git@github.com:commaai/opendbc.git',
    'https://github.com/commaai/opendbc.git',
    'https://github.com/commaai/opendbc',
    'ssh://git@github.com/commaai/opendbc.git']) {
    const d = repo('own-git-', url);
    const r = invoke([d]);
    assert.strictEqual(r.code, 0, `${url} -> ${r.out}`);
    assert.ok(/origin remote/.test(r.out), r.out);
  }
});
t('a non-github.com remote resolves to no owner, so nothing is exempted', () => {
  for (const url of ['git@gitlab.com:commaai/opendbc.git',
    'https://git.example.com/commaai/opendbc.git',
    'https://github.com.evil.example/commaai/opendbc.git']) {
    const d = repo('own-host-', url);
    assert.strictEqual(invoke([d]).code, 1, `${url} was treated as github.com`);
  }
});
t('a remote that is not named origin is not guessed from', () => {
  const d = repo('own-upstream-', 'git@github.com:commaai/opendbc.git', 'upstream');
  assert.strictEqual(invoke([d]).code, 1);
});
t('--owner "" turns the exemption off even inside a detectable clone', () => {
  const d = repo('own-off-', 'git@github.com:commaai/opendbc.git');
  const r = invoke(['--owner', '', d]);
  assert.strictEqual(r.code, 1, r.out);
  assert.ok(!/first party/.test(r.out), r.out);
});
t('--owner beats GITHUB_REPOSITORY, which beats the origin remote', () => {
  const d = repo('own-prec-', 'git@github.com:someoneelse/repo.git');
  assert.strictEqual(invoke([d], { env: { GITHUB_REPOSITORY: 'commaai/opendbc' } }).code, 0);
  assert.strictEqual(invoke(['--owner', 'commaai', d],
    { env: { GITHUB_REPOSITORY: 'someoneelse/repo' } }).code, 0);
});
t('the resolved owner is on stdout, never applied invisibly', () => {
  const d = repo('own-say-', 'git@github.com:commaai/opendbc.git');
  const r = invoke([d]);
  assert.ok(/treating `commaai\/\*` actions as first party/.test(r.out), r.out);
  assert.ok(/--owner ""/.test(r.out), 'the way to turn it off is not stated');
});
t('--json carries owner and ownerSource so a sweep can check what was applied', () => {
  const d = repo('own-json-', 'git@github.com:commaai/opendbc.git');
  const j = JSON.parse(invoke(['--json', d]).out);
  assert.strictEqual(j.owner, 'commaai');
  assert.ok(/origin remote/.test(j.ownerSource), j.ownerSource);
  const none = JSON.parse(invoke(['--json', repo('own-json2-', null)]).out);
  assert.strictEqual(none.owner, null);
  assert.strictEqual(none.ownerSource, null);
});
t('the owner is found by walking up, not only at the path given', () => {
  const d = repo('own-walk-', 'git@github.com:commaai/opendbc.git');
  // Pointing straight at the workflows directory, three levels below the .git.
  assert.strictEqual(invoke([path.join(d, '.github', 'workflows')]).code, 0);
  // ...and straight at the file.
  assert.strictEqual(invoke([path.join(d, '.github', 'workflows', 'ci.yml')]).code, 0);
});
t('a linked worktree follows commondir to the real repository config', () => {
  const main = repo('own-wt-main-', 'git@github.com:commaai/opendbc.git');
  const wt = fs.mkdtempSync(path.join(tmp, 'own-wt-'));
  fs.mkdirSync(path.join(wt, '.github', 'workflows'), { recursive: true });
  fs.writeFileSync(path.join(wt, '.github', 'workflows', 'ci.yml'), OWNED);
  const gd = path.join(main, '.git', 'worktrees', 'wt');
  fs.mkdirSync(gd, { recursive: true });
  fs.writeFileSync(path.join(gd, 'commondir'), '../..\n');
  fs.writeFileSync(path.join(wt, '.git'), `gitdir: ${gd}\n`);
  assert.strictEqual(cli.ownerFromGit(wt), 'commaai');
  assert.strictEqual(invoke([wt]).code, 0);
});
t('a .git file pointing nowhere is no owner rather than a crash', () => {
  const d = fs.mkdtempSync(path.join(tmp, 'own-broken-'));
  fs.mkdirSync(path.join(d, '.github', 'workflows'), { recursive: true });
  fs.writeFileSync(path.join(d, '.github', 'workflows', 'ci.yml'), OWNED);
  fs.writeFileSync(path.join(d, '.git'), 'not a gitdir line at all\n');
  assert.strictEqual(cli.gitDirOf(d), null);
  assert.strictEqual(invoke([d]).code, 1);
});
t('ownerFromRemoteUrl rejects what it cannot read instead of guessing', () => {
  assert.strictEqual(cli.ownerFromRemoteUrl('git@github.com:a/b.git'), 'a');
  for (const bad of ['', null, undefined, 'github.com', 'https://github.com/onlyowner',
    'not a url', 'https://example.com/a/b.git']) {
    assert.strictEqual(cli.ownerFromRemoteUrl(bad), null, JSON.stringify(bad));
  }
});
t('--owner is documented in --help', () =>
  assert.ok(/--owner/.test(cli.usage()) && /first party/.test(cli.usage())));

fs.rmSync(tmp, { recursive: true, force: true });
console.log(failures ? `\n${failures} FAILING` : '\nall passing');
process.exit(failures ? 1 : 0);
