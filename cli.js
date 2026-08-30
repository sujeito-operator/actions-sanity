#!/usr/bin/env node
'use strict';
// Command-line front end. Deliberately separate from extension.js: that file imports
// vscode and cannot run anywhere else, while analyze.js imports only js-yaml. Everything
// here is node built-ins, so the GitHub Action needs no install step and no lockfile.

const fs = require('fs');
const path = require('path');
const { analyze } = require('./analyze.js');

const PKG = require('./package.json');

const YAML_EXT = /\.ya?ml$/i;

// GitHub reads workflows from `.github/workflows` and nowhere else, and it does not
// recurse into subdirectories of it. Matching that exactly is the point: a linter that
// reports on files GitHub never runs is inventing work, and one that misses the
// directory GitHub does read is worse than nothing.
const WORKFLOW_DIR_RE = /(^|[/\\])\.github[/\\]workflows[/\\]?$/;

// Directories that never hold a workflow. `.git` is here and `.github` is deliberately
// not -- they differ by three characters and skipping the wrong one finds nothing at all.
const SKIP_DIRS = new Set([
  '.git', 'node_modules', 'vendor', '.venv', 'venv', '__pycache__',
  'dist', 'build', 'target', '.next', '.cache', '.tox', '.mypy_cache',
]);

const SEVERITIES = ['error', 'warning', 'info'];

// --- who owns the repository being linted ------------------------------------------
// analyze.js exempts an action published by the SAME owner as the repository under scan,
// because "its author can move this tag under you" is not a finding when the reader IS
// the author. That exemption is only as good as the answer here, and a WRONG answer
// suppresses a real supply-chain finding -- the one direction this tool must never fail
// in silently. So: the accepted sources are narrow, anything unrecognised yields null
// (which keeps every non-GitHub action third party and reporting), and whatever was
// resolved is always stated in the output rather than applied invisibly.
//
// Accepts scp-style (git@github.com:owner/repo.git), https, and ssh:// remotes, and
// only on github.com -- a GHES or GitLab host is not a namespace this rule reasons about.
const GH_REMOTE =
  /^(?:(?:https?|ssh|git):\/\/)?(?:[^@/]+@)?github\.com[:/]+([^/]+)\/([^/]+?)(?:\.git)?\/?$/i;

function ownerFromRemoteUrl(url) {
  const m = GH_REMOTE.exec(String(url || '').trim());
  return m ? m[1] : null;
}

// The `.git` next to the worktree is a directory in an ordinary clone and a file holding
// `gitdir:` in a linked worktree or a submodule. A linked worktree's own git dir has no
// `config` of its own -- `commondir` points at the main repository, which is where the
// remotes live -- so following it is what makes this work inside `git worktree`.
function gitDirOf(startDir) {
  let cur = path.resolve(startDir);
  for (;;) {
    const g = path.join(cur, '.git');
    let st = null;
    try { st = fs.statSync(g); } catch (err) { st = null; }
    if (st && st.isDirectory()) return g;
    if (st && st.isFile()) {
      let m = null;
      try { m = /^gitdir:\s*(.+?)\s*$/m.exec(fs.readFileSync(g, 'utf8')); } catch (err) { m = null; }
      if (!m) return null;
      const gd = path.resolve(cur, m[1]);
      try {
        return path.resolve(gd, fs.readFileSync(path.join(gd, 'commondir'), 'utf8').trim());
      } catch (err) { return gd; }
    }
    const up = path.dirname(cur);
    if (up === cur) return null;
    cur = up;
  }
}

// Only `origin`. A repository with three remotes has no single owner this file can pick,
// and guessing among them is exactly how the wrong owner gets applied in silence.
function ownerFromGit(startDir) {
  const gd = gitDirOf(startDir);
  if (!gd) return null;
  let text;
  try { text = fs.readFileSync(path.join(gd, 'config'), 'utf8'); } catch (err) { return null; }
  let inOrigin = false;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    const sect = /^\[\s*remote\s+"([^"]*)"\s*\]$/.exec(line);
    if (sect) { inOrigin = sect[1] === 'origin'; continue; }
    if (/^\[/.test(line)) { inOrigin = false; continue; }
    if (!inOrigin) continue;
    const kv = /^url\s*=\s*(.+)$/.exec(line);
    if (kv) return ownerFromRemoteUrl(kv[1]);
  }
  return null;
}

// Precedence: what the caller said, then what GitHub Actions says about itself, then the
// clone on disk. `--owner ""` is an explicit "I do not know", and it wins over both.
function detectOwner(opts, env, cwd) {
  if (opts.ownerGiven) {
    return { owner: opts.owner || null, source: opts.owner ? 'the --owner option' : 'disabled by --owner ""' };
  }
  const slug = String((env && env.GITHUB_REPOSITORY) || '').trim();
  const m = /^([^/\s]+)\/[^/\s]+$/.exec(slug);
  if (m) return { owner: m[1], source: 'GITHUB_REPOSITORY' };
  const roots = opts.paths.length ? opts.paths : [cwd || '.'];
  for (const p of roots) {
    let base = path.resolve(cwd || '.', p);
    try { if (fs.statSync(base).isFile()) base = path.dirname(base); } catch (err) { /* walk anyway */ }
    const owner = ownerFromGit(base);
    if (owner) return { owner, source: `the origin remote of ${p}` };
  }
  return { owner: null, source: null };
}

// --exclude exists because a workflow can be broken on purpose. Demo repositories,
// action templates and this repository's own `demo/` hold files that are meant to trip
// every rule -- that is what they are for. Without a path filter the only escape is
// `--disable`, which turns the rule off EVERYWHERE, so tolerating one fixture costs you
// script-injection coverage across the whole repository. That trade is not worth making
// and nobody should be asked to make it.
//
// Glob vocabulary, deliberately small: `*` matches within one path segment, `**` crosses
// separators, `?` matches one character that is not a separator. Anything else is a
// literal, including `.`.
function globToRe(glob) {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const ch = glob[i];
    if (ch === '*') {
      if (glob[i + 1] === '*') { re += '.*'; i++; } else re += '[^/]*';
    } else if (ch === '?') re += '[^/]';
    else re += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`^${re}$`);
}

// Three ways to match, because all three are what someone typing `--exclude demo` means:
// the path itself, anything underneath it, and -- for a bare pattern with no separator --
// any single segment, so `--exclude node_modules` works at any depth without a `**/`.
// The matcher records what it turned away. A linter that silently drops files is the
// failure this whole file is written against, so the summary says what was skipped and
// the JSON carries the list -- an exclusion you forgot is then visible in the log rather
// than showing up as a clean run.
function makeMatcher(globs, skipped) {
  const compiled = globs.map(g => {
    const clean = g.replace(/\\/g, '/').replace(/\/+$/, '');
    return { re: globToRe(clean), segment: !clean.includes('/') ? globToRe(clean) : null };
  });
  const hit = p => { if (skipped && !skipped.includes(p)) skipped.push(p); return true; };
  return function excluded(p) {
    const norm = p.replace(/\\/g, '/').replace(/^\.\//, '');
    const segments = norm.split('/').filter(Boolean);
    for (const c of compiled) {
      if (c.re.test(norm)) return hit(p);
      // A directory pattern excludes what is under it: `demo` hides `demo/x/y.yml`.
      for (let i = 1; i < segments.length; i++) {
        if (c.re.test(segments.slice(0, i).join('/'))) return hit(p);
      }
      if (c.segment && segments.some(s => c.segment.test(s))) return hit(p);
    }
    return false;
  };
}

// Off unless asked for, matching the editor's default. `no-timeout` is true of almost
// every workflow ever written -- measured against 40 real ones it fired 88 times. It is
// real and it is noise, and a CI step that fires 88 times on adoption gets switched off
// entirely rather than tuned.
const DEFAULT_DISABLED = ['no-timeout'];

function isWorkflowDir(dir) {
  return WORKFLOW_DIR_RE.test(dir);
}

function usage() {
  return `actions-sanity ${PKG.version}

  Lints .github/workflows for the mistakes that get a repository owned or a green tick
  that cannot go red: script injection from untrusted expressions, untrusted checkout
  under a privileged trigger, third-party actions on a moving reference, unscoped
  tokens, and workflows GitHub will refuse to start. No Go toolchain, no hosted
  service, no repository connection.

Usage
  actions-sanity [options] [path...]

  Each path may be a workflow file or a directory to search. A directory is searched for
  .github/workflows, and every *.yml and *.yaml directly inside it is linted -- which is
  exactly the set GitHub itself runs. With no path, searches the working directory.

Options
  --json                 Emit findings as JSON on stdout and print nothing else.
  --exclude <globs>      Comma-separated paths to skip (repeatable). * stays inside one
                         path segment, ** crosses them, ? is one character. A pattern
                         with no / matches any segment, so --exclude demo skips demo/ at
                         any depth. For workflows that are broken on purpose -- demos,
                         fixtures, action templates -- where --disable would have to turn
                         the rule off across the whole repository to tolerate one file.
                         Skipped files are counted in the summary, never hidden.
  --owner <name>         The owner of the repository being linted. Actions published by
                         that owner are treated as first party, the same way actions/*
                         and github/* are, because "its author can re-tag this under you"
                         is not a finding when the reader is the author. Detected from
                         GITHUB_REPOSITORY and then the origin remote, so it is usually
                         not needed; pass --owner "" to turn the exemption off entirely.
                         Whatever is resolved is printed with the findings.
  --disable <ids>        Comma-separated rule ids to suppress (repeatable).
  --enable <ids>         Turn on a rule that is off by default (${DEFAULT_DISABLED.join(', ')}).
  --min-severity <s>     Only report error | warning | info and above. Default: info.
  --fail-on <s>          Exit 1 when a finding of this severity or worse survives.
                         Default: error. Use "warning" to make CI strict, or "never".
  --no-color             Disable ANSI colour (also honours NO_COLOR and non-TTY stdout).
  -h, --help             This text.
  -v, --version          Print the version.

Exit codes
  0  no finding at or above --fail-on
  1  at least one such finding
  2  bad usage, or a path that could not be read

Rules
  error    yaml script-injection untrusted-checkout unpinned-action
           action-branch-ref needs-unknown-job
  warning  no-permissions job-continue-on-error cache-key-static cache-key-per-run
  info     schedule-no-dispatch no-timeout

  A third-party action pinned to a version tag (@v4) is a warning, not an error, so the
  default --fail-on can be turned on across an existing repository without a pinning
  sprint first. What fails the build is the set you cannot argue with: a workflow GitHub
  will not start, an attacker-controlled expression in a shell, and a step on a branch
  its author can move under you.
`;
}

function parseArgs(argv) {
  const opts = {
    json: false, disabled: new Set(DEFAULT_DISABLED), minSeverity: 'info', failOn: 'error',
    color: null, paths: [], help: false, version: false, exclude: [],
    owner: null, ownerGiven: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const need = () => {
      const v = argv[++i];
      if (v === undefined) throw new Error(`${a} needs a value`);
      return v;
    };
    if (a === '--json') opts.json = true;
    else if (a === '--owner') { opts.owner = need().trim(); opts.ownerGiven = true; }
    else if (a === '--exclude') need().split(',').forEach(g => { if (g.trim()) opts.exclude.push(g.trim()); });
    else if (a === '--disable') need().split(',').forEach(r => { if (r.trim()) opts.disabled.add(r.trim()); });
    else if (a === '--enable') need().split(',').forEach(r => { if (r.trim()) opts.disabled.delete(r.trim()); });
    else if (a === '--min-severity') {
      const v = need();
      if (!SEVERITIES.includes(v)) throw new Error(`--min-severity must be one of ${SEVERITIES.join(', ')}`);
      opts.minSeverity = v;
    } else if (a === '--fail-on') {
      const v = need();
      if (v !== 'never' && !SEVERITIES.includes(v)) {
        throw new Error(`--fail-on must be one of ${SEVERITIES.join(', ')}, never`);
      }
      opts.failOn = v;
    } else if (a === '--no-color') opts.color = false;
    else if (a === '--color') opts.color = true;
    else if (a === '-h' || a === '--help') opts.help = true;
    else if (a === '-v' || a === '--version') opts.version = true;
    else if (a.startsWith('-') && a !== '-') throw new Error(`unknown option ${a}`);
    else opts.paths.push(a);
  }
  return opts;
}

// A path given explicitly is linted whatever it is called -- if you point this at a file
// you have decided it is a workflow -- but a path that is walked has to sit in a
// directory GitHub actually reads, or `.` would lint every YAML file in the repository.
// `excluded` is optional so that the three-argument calls that predate --exclude keep
// working; with no matcher nothing is ever skipped.
function collect(paths, out, errors, excluded) {
  const skip = excluded || (() => false);
  for (const p of paths) {
    // An excluded path is skipped even when named explicitly. Pointing at a file usually
    // means "lint this whatever it is called", but --exclude is the more specific
    // instruction of the two and the later one on the command line.
    if (skip(p)) continue;
    let st;
    try {
      st = fs.statSync(p);
    } catch (err) {
      errors.push(`cannot read ${p}: ${err.code || err.message}`);
      continue;
    }
    if (st.isDirectory()) walk(p, out, errors, skip);
    else out.push(p);
  }
  return out;
}

function walk(dir, out, errors, excluded) {
  const skip = excluded || (() => false);
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (err) {
    errors.push(`cannot read ${dir}: ${err.code || err.message}`);
    return;
  }
  entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  const here = isWorkflowDir(dir);
  for (const e of entries) {
    const full = path.join(dir, e.name);
    // Pruning at the directory, not just filtering the files, so an excluded tree is
    // never read at all.
    if (skip(full)) continue;
    if (e.isDirectory()) {
      // GitHub does not recurse inside .github/workflows, so neither does this.
      if (here || SKIP_DIRS.has(e.name)) continue;
      walk(full, out, errors, skip);
    } else if (here && e.isFile() && YAML_EXT.test(e.name)) {
      out.push(full);
    }
  }
}

function lintFile(file, opts) {
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (err) {
    return { file, error: `cannot read ${file}: ${err.code || err.message}`, problems: [] };
  }
  let problems;
  try {
    problems = analyze(text, { owner: opts.owner });
  } catch (err) {
    // A linter that throws on a malformed file is worse than one that says nothing, but
    // in CI it has to be visible rather than swallowed the way an editor squiggle can be.
    return { file, error: `analyze failed on ${file}: ${err.message}`, problems: [] };
  }
  const floor = SEVERITIES.indexOf(opts.minSeverity);
  const kept = problems
    .filter(p => !opts.disabled.has(p.rule))
    .filter(p => SEVERITIES.indexOf(p.severity) <= floor)
    .map(p => ({ line: p.line + 1, rule: p.rule, severity: p.severity, message: p.message }));
  return { file, error: null, problems: kept };
}

function paint(color) {
  const on = (code, s) => (color ? `[${code}m${s}[0m` : s);
  return {
    dim: s => on('2', s),
    bold: s => on('1', s),
    sev: (severity, s) =>
      severity === 'error' ? on('31', s) : severity === 'warning' ? on('33', s) : on('36', s),
  };
}

// The message text carries the reasoning, so it is long on purpose. Wrapping it under the
// rule column keeps that readable in a CI log, which is 80-ish columns and has no scrollback.
function wrap(text, width, indent) {
  const words = text.split(/\s+/);
  const lines = [];
  let line = '';
  for (const w of words) {
    if (line && line.length + 1 + w.length > width) { lines.push(line); line = w; }
    else line = line ? `${line} ${w}` : w;
  }
  if (line) lines.push(line);
  return lines.map((l, i) => (i === 0 ? l : indent + l)).join('\n');
}

function render(results, opts, color) {
  const c = paint(color);
  const lines = [];
  const counts = { error: 0, warning: 0, info: 0 };
  const INDENT = ' '.repeat(6 + 8 + 1 + 21 + 1);
  for (const r of results) {
    if (!r.problems.length) continue;
    lines.push(c.bold(r.file));
    for (const p of r.problems) {
      counts[p.severity]++;
      const loc = String(p.line).padStart(4);
      const msg = wrap(p.message.replace(/`/g, ''), 72, INDENT);
      lines.push(`  ${c.dim(loc)}  ${c.sev(p.severity, p.severity.padEnd(7))} ${c.dim(p.rule.padEnd(21))} ${msg}`);
    }
    lines.push('');
  }
  const scanned = results.length;
  const total = counts.error + counts.warning + counts.info;
  if (total === 0) {
    lines.push(`actions-sanity: nothing to report in ${scanned} workflow${scanned === 1 ? '' : 's'}.`);
  } else {
    const parts = SEVERITIES.filter(s => counts[s]).map(s => `${counts[s]} ${s}${counts[s] === 1 ? '' : 's'}`);
    lines.push(`actions-sanity: ${parts.join(', ')} in ${scanned} workflow${scanned === 1 ? '' : 's'}.`);
  }
  return { text: lines.join('\n'), counts };
}

function run(argv, io) {
  const stdout = io.stdout, stderr = io.stderr;
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (err) {
    stderr(`actions-sanity: ${err.message}\n`);
    stderr(`Try --help.\n`);
    return 2;
  }
  if (opts.help) { stdout(usage()); return 0; }
  if (opts.version) { stdout(`${PKG.version}\n`); return 0; }

  const color = opts.color === null ? io.colorDefault : opts.color;
  // Resolved once for the whole run, before any file is read, so every file in one
  // invocation is judged against the same owner.
  const detected = detectOwner(opts, io.env || process.env, io.cwd || process.cwd());
  opts.owner = detected.owner;
  const errors = [];
  const skipped = [];
  const matcher = opts.exclude.length ? makeMatcher(opts.exclude, skipped) : null;
  const files = collect(opts.paths.length ? opts.paths : ['.'], [], errors, matcher);

  if (!files.length && !errors.length) {
    const where = opts.paths.length ? opts.paths.join(', ') : 'the working directory';
    // Saying "none found" when --exclude is why none were found would be a lie of
    // omission, and the one most likely to hide a typo in the pattern.
    const because = skipped.length ? ` (${skipped.length} path(s) excluded: ${skipped.join(', ')})` : '';
    if (opts.json) {
      stdout(JSON.stringify({ version: PKG.version, files: [], findings: [], excluded: skipped }, null, 2) + '\n');
    } else stdout(`actions-sanity: no .github/workflows found in ${where}${because}.\n`);
    return 0;
  }

  const results = files.map(f => lintFile(f, opts));
  for (const r of results) if (r.error) errors.push(r.error);

  if (opts.json) {
    const findings = [];
    for (const r of results) {
      for (const p of r.problems) findings.push({ file: r.file, ...p });
    }
    stdout(JSON.stringify({
      version: PKG.version,
      files: results.map(r => r.file),
      findings,
      excluded: skipped,
      owner: detected.owner,
      ownerSource: detected.source,
      errors,
    }, null, 2) + '\n');
  } else {
    const { text } = render(results, opts, color);
    stdout(text + '\n');
    if (skipped.length) {
      stdout(`actions-sanity: ${skipped.length} path(s) excluded: ${skipped.join(', ')}\n`);
    }
    // Stated on every run that resolved one, because this is the setting that makes
    // findings DISAPPEAR. An owner detected wrongly has to be visible in the log rather
    // than showing up as a repository that got quieter for no stated reason.
    if (detected.owner) {
      stdout(`actions-sanity: treating \`${detected.owner}/*\` actions as first party `
        + `(owner from ${detected.source}; --owner "" turns this off).\n`);
    }
  }
  for (const e of errors) stderr(`actions-sanity: ${e}\n`);

  // An unreadable path is exit 2 and never a quiet 0. A linter that reports success
  // because it found nothing to look at is worse than no linter.
  if (errors.length) return 2;

  if (opts.failOn === 'never') return 0;
  const bar = SEVERITIES.indexOf(opts.failOn);
  const tripped = results.some(r => r.problems.some(p => SEVERITIES.indexOf(p.severity) <= bar));
  return tripped ? 1 : 0;
}

module.exports = {
  run, parseArgs, collect, lintFile, isWorkflowDir, usage, SKIP_DIRS, DEFAULT_DISABLED,
  makeMatcher, globToRe, detectOwner, ownerFromRemoteUrl, ownerFromGit, gitDirOf,
};

if (require.main === module) {
  const code = run(process.argv.slice(2), {
    stdout: s => process.stdout.write(s),
    stderr: s => process.stderr.write(s),
    colorDefault: Boolean(process.stdout.isTTY) && !process.env.NO_COLOR,
  });
  process.exitCode = code;
}
