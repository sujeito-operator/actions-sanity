'use strict';
const vscode = require('vscode');
const path = require('path');
const { analyze } = require('./analyze.js');
// cli.js imports node built-ins only and guards its own `require.main` entry point, so
// importing it here costs nothing and keeps ONE implementation of owner detection. Two
// copies of this would drift, and a drifted copy silently suppresses findings.
const { ownerFromGit } = require('./cli.js');

// Resolved per workspace folder and cached: lint() runs on every save and open, and this
// walks the tree looking for .git. Cleared on configuration change, which is the only
// way the answer moves without the folder itself changing.
const ownerCache = new Map();

function ownerFor(doc) {
  // The setting is null by default, meaning "work it out from the clone". A string --
  // including the empty string, which turns the exemption off -- is taken as final and
  // nothing is detected. Null rather than "" as the default is what makes those two
  // cases distinguishable without inspecting where the value came from.
  const configured = vscode.workspace
    .getConfiguration('actionsSanity', doc.uri).get('repositoryOwner', null);
  if (typeof configured === 'string') return configured.trim() || null;

  const folder = vscode.workspace.getWorkspaceFolder(doc.uri);
  const root = folder ? folder.uri.fsPath : path.dirname(doc.uri.fsPath);
  if (ownerCache.has(root)) return ownerCache.get(root);
  let owner = null;
  try { owner = ownerFromGit(root); } catch (err) { owner = null; }
  ownerCache.set(root, owner);
  return owner;
}

const SEV = {
  error: vscode.DiagnosticSeverity.Error,
  warning: vscode.DiagnosticSeverity.Warning,
  info: vscode.DiagnosticSeverity.Information,
};

// Only files GitHub itself would run. A workflow-shaped YAML anywhere else in the tree
// (an Argo template, a Gitea config, a fixture) is not ours to lint, and a linter that
// reports on files the reader did not ask about is the fastest way to be uninstalled.
function isWorkflow(doc) {
  const p = doc.uri.fsPath.split(path.sep).join('/');
  return /\/\.github\/workflows\/[^/]+\.ya?ml$/.test(p);
}

function lint(doc, collection) {
  if (!isWorkflow(doc)) return 0;

  const cfg = vscode.workspace.getConfiguration('actionsSanity');
  const disabled = new Set(cfg.get('disabledRules', []));

  let problems;
  try {
    problems = analyze(doc.getText(), { owner: ownerFor(doc) });
  } catch (err) {
    // A linter that throws on a file it cannot understand is worse than one that says
    // nothing about it.
    console.error('actions-sanity: analyze failed', err);
    collection.delete(doc.uri);
    return 0;
  }

  const diags = [];
  for (const p of problems) {
    if (disabled.has(p.rule)) continue;
    const line = Math.min(p.line, Math.max(doc.lineCount - 1, 0));
    const range = doc.lineAt(line).range;
    const d = new vscode.Diagnostic(range, p.message, SEV[p.severity] || SEV.info);
    d.source = 'Actions Sanity';
    d.code = p.rule;
    diags.push(d);
  }
  collection.set(doc.uri, diags);
  return diags.length;
}

async function scanWorkspace(collection, output) {
  const files = await vscode.workspace.findFiles(
    '**/.github/workflows/*.{yml,yaml}', '**/node_modules/**', 500);
  if (!files.length) {
    vscode.window.showInformationMessage(
      'Actions Sanity: no workflow files found under .github/workflows.');
    return;
  }
  let total = 0;
  output.clear();
  for (const uri of files) {
    const doc = await vscode.workspace.openTextDocument(uri);
    const n = lint(doc, collection);
    total += n;
    if (n) output.appendLine(`${vscode.workspace.asRelativePath(uri)} — ${n} problem(s)`);
  }
  output.appendLine(`\n${files.length} workflow(s) scanned, ${total} problem(s).`);
  if (!total) {
    vscode.window.showInformationMessage(
      `Actions Sanity: ${files.length} workflow(s) scanned, nothing to report.`);
  } else {
    vscode.window
      .showWarningMessage(`Actions Sanity found ${total} problem(s).`, 'Show details')
      .then(choice => { if (choice) output.show(true); });
  }
}

function activate(context) {
  const collection = vscode.languages.createDiagnosticCollection('actionsSanity');
  const output = vscode.window.createOutputChannel('Actions Sanity');
  context.subscriptions.push(collection, output);

  context.subscriptions.push(
    vscode.commands.registerCommand('actionsSanity.scanWorkspace',
      () => scanWorkspace(collection, output)),
    vscode.workspace.onDidSaveTextDocument(doc => lint(doc, collection)),
    vscode.workspace.onDidOpenTextDocument(doc => lint(doc, collection)),
    vscode.workspace.onDidCloseTextDocument(doc => collection.delete(doc.uri)),
    // A changed setting or an added folder can move the owner, and a stale owner is a
    // suppressed finding. Both drop the cache; the next lint re-detects.
    vscode.workspace.onDidChangeConfiguration(e => {
      if (e.affectsConfiguration('actionsSanity')) ownerCache.clear();
    }),
    vscode.workspace.onDidChangeWorkspaceFolders(() => ownerCache.clear()),
  );

  for (const doc of vscode.workspace.textDocuments) lint(doc, collection);
}

function deactivate() {}

module.exports = { activate, deactivate, isWorkflow, ownerFor, ownerCache };
