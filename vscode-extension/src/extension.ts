import * as vscode from "vscode";
import * as path from "path";
import { execFile } from "child_process";

// ---------------------------------------------------------------------------
// Types matching Vow CLI JSON output (--format json)
// ---------------------------------------------------------------------------

interface VowIssue {
  severity: "Critical" | "High" | "Medium" | "Low";
  message: string;
  line: number | null;
  rule: string | null;
  suggestion: string | null;
}

interface VowFileResult {
  path: string;
  file_type: string;
  issues: VowIssue[];
  trust_score: number;
}

interface VowProjectSummary {
  total_files: number;
  avg_score: number;
  total_issues: number;
  issues_by_severity: Record<string, number>;
}

interface VowOutput {
  files: VowFileResult[];
  summary: VowProjectSummary;
}

// ---------------------------------------------------------------------------
// Severity mapping: Critical→Error, High→Warning, Medium→Info, Low→Hint
// ---------------------------------------------------------------------------

function mapSeverity(s: string): vscode.DiagnosticSeverity {
  switch (s) {
    case "Critical":
      return vscode.DiagnosticSeverity.Error;
    case "High":
      return vscode.DiagnosticSeverity.Warning;
    case "Medium":
      return vscode.DiagnosticSeverity.Information;
    case "Low":
    default:
      return vscode.DiagnosticSeverity.Hint;
  }
}

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

function meetsMinSeverity(issue: string, minSev: string): boolean {
  return (SEVERITY_ORDER[issue.toLowerCase()] ?? 3) <= (SEVERITY_ORDER[minSev] ?? 3);
}

// ---------------------------------------------------------------------------
// Extension activation
// ---------------------------------------------------------------------------

export function activate(context: vscode.ExtensionContext) {
  const diagnostics = vscode.languages.createDiagnosticCollection("vow");
  const outputChannel = vscode.window.createOutputChannel("Vow");
  const statusBar = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    100
  );
  statusBar.command = "vow.checkFile";
  statusBar.text = "$(shield) Vow";
  statusBar.tooltip = "Click to run Vow check";
  statusBar.show();

  let lastOutput: VowOutput | null = null;

  // ------ helpers ------

  function cfg<T>(key: string, fallback: T): T {
    return vscode.workspace.getConfiguration("vow").get<T>(key, fallback);
  }

  function runVow(filePath: string): Promise<VowOutput> {
    return new Promise((resolve, reject) => {
      const bin = cfg<string>("executablePath", "vow");
      const args = ["check", filePath, "--format", "json"];

      const excludedAnalyzers = cfg<string[]>("excludedAnalyzers", []);
      for (const a of excludedAnalyzers) {
        args.push("--exclude-analyzer", a);
      }

      outputChannel.appendLine(`> ${bin} ${args.join(" ")}`);

      const cwd = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;

      execFile(bin, args, { cwd, maxBuffer: 10 * 1024 * 1024 }, (err, stdout, stderr) => {
        if (stderr) {
          outputChannel.appendLine(stderr);
        }
        // Vow exits non-zero when issues found — still has valid JSON on stdout
        if (stdout) {
          try {
            // The CLI may print non-JSON preamble (accountability check). 
            // Find the first '{' that starts the JSON object.
            const jsonStart = stdout.indexOf("{");
            if (jsonStart === -1) {
              reject(new Error("No JSON in vow output"));
              return;
            }
            const parsed = JSON.parse(stdout.slice(jsonStart)) as VowOutput;
            resolve(parsed);
            return;
          } catch (e) {
            outputChannel.appendLine(`JSON parse error: ${e}`);
          }
        }
        if (err) {
          reject(err);
        } else {
          reject(new Error("vow produced no output"));
        }
      });
    });
  }

  function updateDiagnostics(result: VowOutput) {
    diagnostics.clear();
    const minSev = cfg<string>("minSeverity", "low");
    const byUri = new Map<string, vscode.Diagnostic[]>();

    for (const file of result.files) {
      const uri = vscode.Uri.file(file.path).toString();
      for (const issue of file.issues) {
        if (!meetsMinSeverity(issue.severity, minSev)) continue;

        const line = Math.max(0, (issue.line ?? 1) - 1);
        const range = new vscode.Range(line, 0, line, Number.MAX_SAFE_INTEGER);

        const diag = new vscode.Diagnostic(range, issue.message, mapSeverity(issue.severity));
        diag.source = "vow";
        if (issue.rule) {
          diag.code = issue.rule;
        }
        // Stash suggestion in relatedInformation so CodeActionProvider can read it
        if (issue.suggestion) {
          diag.relatedInformation = [
            new vscode.DiagnosticRelatedInformation(
              new vscode.Location(vscode.Uri.file(file.path), range),
              issue.suggestion
            ),
          ];
        }

        const arr = byUri.get(uri) ?? [];
        arr.push(diag);
        byUri.set(uri, arr);
      }
    }

    for (const [uri, diags] of byUri) {
      diagnostics.set(vscode.Uri.parse(uri), diags);
    }
  }

  function updateStatusBar(result: VowOutput) {
    const score = result.summary.avg_score;
    const issues = result.summary.total_issues;
    if (issues === 0) {
      statusBar.text = `$(check) Vow: ${score}%`;
      statusBar.backgroundColor = undefined;
    } else {
      statusBar.text = `$(warning) Vow: ${score}% (${issues})`;
      statusBar.backgroundColor = new vscode.ThemeColor(
        score >= 70 ? "statusBarItem.warningBackground" : "statusBarItem.errorBackground"
      );
    }
    statusBar.tooltip = `Trust score ${score}% · ${issues} issue(s)`;
  }

  async function checkFile(filePath: string) {
    statusBar.text = "$(sync~spin) Vow…";
    statusBar.backgroundColor = undefined;
    try {
      const result = await runVow(filePath);
      lastOutput = result;
      updateDiagnostics(result);
      updateStatusBar(result);
      outputChannel.appendLine(
        `Checked ${result.summary.total_files} file(s): score=${result.summary.avg_score}%, issues=${result.summary.total_issues}`
      );
    } catch (e: any) {
      outputChannel.appendLine(`Error: ${e.message ?? e}`);
      statusBar.text = "$(error) Vow";
      statusBar.backgroundColor = new vscode.ThemeColor("statusBarItem.errorBackground");
    }
  }

  // ------ commands ------

  context.subscriptions.push(
    vscode.commands.registerCommand("vow.checkFile", async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showWarningMessage("Vow: no active file");
        return;
      }
      await checkFile(editor.document.fileName);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("vow.checkWorkspace", async () => {
      const ws = vscode.workspace.workspaceFolders?.[0];
      if (!ws) {
        vscode.window.showWarningMessage("Vow: no workspace open");
        return;
      }
      await checkFile(ws.uri.fsPath);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("vow.showReport", () => {
      if (!lastOutput) {
        vscode.window.showInformationMessage("Vow: run a check first");
        return;
      }
      const panel = vscode.window.createWebviewPanel(
        "vowReport",
        "Vow Report",
        vscode.ViewColumn.Two,
        { enableScripts: false }
      );
      panel.webview.html = buildReportHtml(lastOutput);
    })
  );

  // ------ on-save ------

  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(async (doc) => {
      if (!cfg<boolean>("runOnSave", true)) return;
      await checkFile(doc.fileName);
    })
  );

  // ------ code action provider (quick fixes + inline ignore) ------

  const codeActionProvider = vscode.languages.registerCodeActionsProvider(
    { scheme: "file" },
    new VowCodeActionProvider(diagnostics),
    { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
  );
  context.subscriptions.push(codeActionProvider);

  // ------ disposables ------

  context.subscriptions.push(diagnostics, outputChannel, statusBar);
}

// ---------------------------------------------------------------------------
// Code Action Provider – quick fixes + vow-ignore
// ---------------------------------------------------------------------------

class VowCodeActionProvider implements vscode.CodeActionProvider {
  constructor(private diagnostics: vscode.DiagnosticCollection) {}

  provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];

    for (const diag of context.diagnostics) {
      if (diag.source !== "vow") continue;

      // 1. Apply suggestion (quick fix)
      if (diag.relatedInformation?.length) {
        const suggestion = diag.relatedInformation[0].message;
        if (suggestion) {
          const fix = new vscode.CodeAction(
            `Vow: Apply fix — ${truncate(suggestion, 60)}`,
            vscode.CodeActionKind.QuickFix
          );
          fix.diagnostics = [diag];
          fix.isPreferred = true;

          const edit = new vscode.WorkspaceEdit();
          edit.replace(document.uri, diag.range, suggestion);
          fix.edit = edit;
          actions.push(fix);
        }
      }

      // 2. Inline ignore
      const ignoreLine = diag.range.start.line;
      const ignoreAction = new vscode.CodeAction(
        `Vow: Ignore this finding (// vow-ignore)`,
        vscode.CodeActionKind.QuickFix
      );
      ignoreAction.diagnostics = [diag];

      const ignoreEdit = new vscode.WorkspaceEdit();
      const indent = document.lineAt(ignoreLine).text.match(/^(\s*)/)?.[1] ?? "";
      const ruleTag = diag.code ? ` ${diag.code}` : "";
      ignoreEdit.insert(
        document.uri,
        new vscode.Position(ignoreLine, 0),
        `${indent}// vow-ignore${ruleTag}\n`
      );
      ignoreAction.edit = ignoreEdit;
      actions.push(ignoreAction);
    }

    return actions;
  }
}

function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

// ---------------------------------------------------------------------------
// HTML report
// ---------------------------------------------------------------------------

function buildReportHtml(result: VowOutput): string {
  const { summary, files } = result;

  const issueRows = files
    .flatMap((f) =>
      f.issues.map(
        (i) => `
      <tr class="sev-${i.severity.toLowerCase()}">
        <td>${i.severity}</td>
        <td>${escHtml(path.basename(f.path))}</td>
        <td>${i.line ?? "—"}</td>
        <td>${escHtml(i.message)}</td>
        <td>${i.suggestion ? escHtml(i.suggestion) : "—"}</td>
      </tr>`
      )
    )
    .join("\n");

  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<style>
  body { font-family: system-ui, sans-serif; margin: 1rem; color: #e0e0e0; background: #1e1e1e; }
  h1 { font-size: 1.4rem; }
  .summary { display: flex; gap: 1.5rem; margin-bottom: 1rem; }
  .card { background: #2d2d2d; padding: .8rem 1.2rem; border-radius: 6px; }
  table { width: 100%; border-collapse: collapse; font-size: .9rem; }
  th, td { text-align: left; padding: .4rem .6rem; border-bottom: 1px solid #333; }
  .sev-critical td:first-child { color: #f44; font-weight: bold; }
  .sev-high td:first-child { color: #fb8c00; }
  .sev-medium td:first-child { color: #29b6f6; }
  .sev-low td:first-child { color: #888; }
</style></head><body>
<h1>Vow Report</h1>
<div class="summary">
  <div class="card">Trust Score<br><strong>${summary.avg_score}%</strong></div>
  <div class="card">Files<br><strong>${summary.total_files}</strong></div>
  <div class="card">Issues<br><strong>${summary.total_issues}</strong></div>
</div>
${
  summary.total_issues > 0
    ? `<table><tr><th>Severity</th><th>File</th><th>Line</th><th>Message</th><th>Suggestion</th></tr>${issueRows}</table>`
    : "<p>No issues found.</p>"
}
</body></html>`;
}

function escHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// ---------------------------------------------------------------------------
export function deactivate() {}
