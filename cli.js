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
    color: null, paths: [], help: false, version: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const need = () => {
      const v = argv[++i];
      if (v === undefined) throw new Error(`${a} needs a value`);
      return v;
    };
    if (a === '--json') opts.json = true;
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
function collect(paths, out, errors) {
  for (const p of paths) {
    let st;
    try {
      st = fs.statSync(p);
    } catch (err) {
      errors.push(`cannot read ${p}: ${err.code || err.message}`);
      continue;
    }
    if (st.isDirectory()) walk(p, out, errors);
    else out.push(p);
  }
  return out;
}

function walk(dir, out, errors) {
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
    if (e.isDirectory()) {
      // GitHub does not recurse inside .github/workflows, so neither does this.
      if (here || SKIP_DIRS.has(e.name)) continue;
      walk(full, out, errors);
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
    problems = analyze(text);
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
  const errors = [];
  const files = collect(opts.paths.length ? opts.paths : ['.'], [], errors);

  if (!files.length && !errors.length) {
    const where = opts.paths.length ? opts.paths.join(', ') : 'the working directory';
    if (opts.json) stdout(JSON.stringify({ version: PKG.version, files: [], findings: [] }, null, 2) + '\n');
    else stdout(`actions-sanity: no .github/workflows found in ${where}.\n`);
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
      errors,
    }, null, 2) + '\n');
  } else {
    const { text } = render(results, opts, color);
    stdout(text + '\n');
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

module.exports = { run, parseArgs, collect, lintFile, isWorkflowDir, usage, SKIP_DIRS, DEFAULT_DISABLED };

if (require.main === module) {
  const code = run(process.argv.slice(2), {
    stdout: s => process.stdout.write(s),
    stderr: s => process.stderr.write(s),
    colorDefault: Boolean(process.stdout.isTTY) && !process.env.NO_COLOR,
  });
  process.exitCode = code;
}
