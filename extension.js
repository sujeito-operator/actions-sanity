'use strict';
const vscode = require('vscode');
const path = require('path');
const { analyze } = require('./analyze.js');

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
    problems = analyze(doc.getText());
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
  );

  for (const doc of vscode.workspace.textDocuments) lint(doc, collection);
}

function deactivate() {}

module.exports = { activate, deactivate, isWorkflow };
