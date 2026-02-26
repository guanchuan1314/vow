import * as vscode from 'vscode';
import * as path from 'path';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

interface VowIssue {
    file: string;
    line: number;
    column?: number;
    severity: string;
    message: string;
    rule?: string;
    code?: string;
}

interface VowResult {
    issues: VowIssue[];
    summary: {
        total_issues: number;
        by_severity: Record<string, number>;
    };
}

export function activate(context: vscode.ExtensionContext) {
    console.log('Vow extension is now active!');

    const diagnosticCollection = vscode.languages.createDiagnosticCollection('vow');
    const statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    
    let isScanning = false;
    let lastResults: VowResult | null = null;

    // Update status bar
    function updateStatusBar() {
        if (isScanning) {
            statusBarItem.text = "$(sync~spin) Vow: Scanning...";
            statusBarItem.tooltip = "Vow is analyzing your code";
            statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
        } else if (lastResults) {
            const totalIssues = lastResults.summary.total_issues;
            if (totalIssues === 0) {
                statusBarItem.text = "$(check) Vow: Clean";
                statusBarItem.tooltip = "No issues found";
                statusBarItem.backgroundColor = undefined;
            } else {
                statusBarItem.text = `$(warning) Vow: ${totalIssues} issue${totalIssues > 1 ? 's' : ''}`;
                statusBarItem.tooltip = `Found ${totalIssues} issue(s)`;
                statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
            }
        } else {
            statusBarItem.text = "$(question) Vow: Ready";
            statusBarItem.tooltip = "Vow is ready to scan";
            statusBarItem.backgroundColor = undefined;
        }
        statusBarItem.show();
    }

    updateStatusBar();

    // Convert Vow severity to VS Code DiagnosticSeverity
    function mapSeverity(vowSeverity: string): vscode.DiagnosticSeverity {
        switch (vowSeverity.toLowerCase()) {
            case 'critical':
            case 'high':
                return vscode.DiagnosticSeverity.Error;
            case 'medium':
                return vscode.DiagnosticSeverity.Warning;
            case 'low':
                return vscode.DiagnosticSeverity.Information;
            default:
                return vscode.DiagnosticSeverity.Hint;
        }
    }

    // Run Vow check
    async function runVowCheck(target: string): Promise<VowResult | null> {
        const config = vscode.workspace.getConfiguration('vow');
        const executablePath = config.get<string>('executablePath', 'vow');
        const severity = config.get<string>('severity', 'medium');
        const exclude = config.get<string[]>('exclude', []);

        let command = `${executablePath} check "${target}" --json --severity ${severity}`;
        
        if (exclude.length > 0) {
            command += ` --exclude ${exclude.map(pattern => `"${pattern}"`).join(' --exclude ')}`;
        }

        try {
            isScanning = true;
            updateStatusBar();

            const { stdout } = await execAsync(command, {
                cwd: vscode.workspace.workspaceFolders?.[0]?.uri.fsPath
            });

            const result = JSON.parse(stdout) as VowResult;
            lastResults = result;
            return result;
        } catch (error) {
            console.error('Vow check failed:', error);
            vscode.window.showErrorMessage(`Vow check failed: ${error}`);
            return null;
        } finally {
            isScanning = false;
            updateStatusBar();
        }
    }

    // Update diagnostics
    function updateDiagnostics(result: VowResult) {
        // Clear all existing diagnostics
        diagnosticCollection.clear();

        const diagnosticsByFile = new Map<string, vscode.Diagnostic[]>();

        for (const issue of result.issues) {
            const uri = vscode.Uri.file(issue.file);
            const line = Math.max(0, issue.line - 1); // Convert to 0-based
            const column = issue.column ? Math.max(0, issue.column - 1) : 0;
            
            const range = new vscode.Range(
                new vscode.Position(line, column),
                new vscode.Position(line, column + 10) // Approximate range
            );

            const diagnostic = new vscode.Diagnostic(
                range,
                issue.message,
                mapSeverity(issue.severity)
            );

            diagnostic.source = 'vow';
            if (issue.code) {
                diagnostic.code = issue.code;
            }

            // Add code action for opening rule documentation
            if (issue.rule) {
                diagnostic.code = {
                    value: issue.rule,
                    target: vscode.Uri.parse(`https://github.com/warden-ai/vow/docs/rules/${issue.rule}`)
                };
            }

            const filePath = uri.toString();
            if (!diagnosticsByFile.has(filePath)) {
                diagnosticsByFile.set(filePath, []);
            }
            diagnosticsByFile.get(filePath)!.push(diagnostic);
        }

        // Set diagnostics for each file
        for (const [filePath, diagnostics] of diagnosticsByFile) {
            diagnosticCollection.set(vscode.Uri.parse(filePath), diagnostics);
        }
    }

    // Command: Check File
    const checkFileCommand = vscode.commands.registerCommand('vow.checkFile', async () => {
        const activeEditor = vscode.window.activeTextEditor;
        if (!activeEditor) {
            vscode.window.showWarningMessage('No active file to check');
            return;
        }

        const filePath = activeEditor.document.fileName;
        const result = await runVowCheck(filePath);
        
        if (result) {
            updateDiagnostics(result);
            const totalIssues = result.summary.total_issues;
            vscode.window.showInformationMessage(
                totalIssues === 0 
                    ? 'Vow: No issues found in this file' 
                    : `Vow: Found ${totalIssues} issue${totalIssues > 1 ? 's' : ''} in this file`
            );
        }
    });

    // Command: Check Workspace
    const checkWorkspaceCommand = vscode.commands.registerCommand('vow.checkWorkspace', async () => {
        const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
        if (!workspaceFolder) {
            vscode.window.showWarningMessage('No workspace open');
            return;
        }

        const result = await runVowCheck(workspaceFolder.uri.fsPath);
        
        if (result) {
            updateDiagnostics(result);
            const totalIssues = result.summary.total_issues;
            vscode.window.showInformationMessage(
                totalIssues === 0 
                    ? 'Vow: No issues found in workspace' 
                    : `Vow: Found ${totalIssues} issue${totalIssues > 1 ? 's' : ''} in workspace`
            );
        }
    });

    // Command: Show Report
    const showReportCommand = vscode.commands.registerCommand('vow.showReport', async () => {
        if (!lastResults) {
            vscode.window.showInformationMessage('No recent Vow results. Run a check first.');
            return;
        }

        const panel = vscode.window.createWebviewPanel(
            'vowReport',
            'Vow Report',
            vscode.ViewColumn.Two,
            { enableScripts: true }
        );

        panel.webview.html = generateReportHtml(lastResults);
    });

    // Generate HTML report
    function generateReportHtml(result: VowResult): string {
        const totalIssues = result.summary.total_issues;
        const severityCounts = result.summary.by_severity;

        let issuesHtml = '';
        for (const issue of result.issues) {
            issuesHtml += `
                <div class="issue issue-${issue.severity.toLowerCase()}">
                    <div class="issue-header">
                        <span class="severity">${issue.severity}</span>
                        <span class="file">${path.relative(vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || '', issue.file)}</span>
                        <span class="location">Line ${issue.line}${issue.column ? `:${issue.column}` : ''}</span>
                    </div>
                    <div class="message">${issue.message}</div>
                    ${issue.rule ? `<div class="rule">Rule: ${issue.rule}</div>` : ''}
                </div>
            `;
        }

        return `
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Vow Report</title>
                <style>
                    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 20px; }
                    .summary { background: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
                    .issue { border-left: 4px solid #ccc; padding: 10px; margin-bottom: 10px; }
                    .issue-critical, .issue-high { border-left-color: #d73a49; }
                    .issue-medium { border-left-color: #f66a0a; }
                    .issue-low { border-left-color: #0969da; }
                    .issue-header { display: flex; gap: 15px; font-weight: bold; margin-bottom: 5px; }
                    .severity { background: #e1e4e8; padding: 2px 6px; border-radius: 3px; font-size: 0.9em; }
                    .file { color: #0969da; }
                    .location { color: #656d76; }
                    .message { margin-bottom: 5px; }
                    .rule { color: #656d76; font-size: 0.9em; }
                </style>
            </head>
            <body>
                <h1>Vow Report</h1>
                <div class="summary">
                    <h2>Summary</h2>
                    <p>Total issues: ${totalIssues}</p>
                    ${Object.entries(severityCounts).map(([severity, count]) => 
                        `<p>${severity}: ${count}</p>`
                    ).join('')}
                </div>
                ${totalIssues > 0 ? `<h2>Issues</h2>${issuesHtml}` : '<p>No issues found!</p>'}
            </body>
            </html>
        `;
    }

    // Run on save
    const onSaveDisposable = vscode.workspace.onDidSaveTextDocument(async (document) => {
        const config = vscode.workspace.getConfiguration('vow');
        const runOnSave = config.get<boolean>('runOnSave', true);
        
        if (!runOnSave) {
            return;
        }

        // Only check supported file types
        const supportedLanguages = [
            'javascript', 'typescript', 'python', 'java', 'go', 'rust',
            'c', 'cpp', 'csharp', 'php', 'swift', 'kotlin', 'r', 'scala',
            'perl', 'lua', 'dart', 'haskell', 'ruby', 'markdown', 'plaintext'
        ];

        if (supportedLanguages.includes(document.languageId)) {
            const result = await runVowCheck(document.fileName);
            if (result) {
                updateDiagnostics(result);
            }
        }
    });

    // Register disposables
    context.subscriptions.push(
        diagnosticCollection,
        statusBarItem,
        checkFileCommand,
        checkWorkspaceCommand,
        showReportCommand,
        onSaveDisposable
    );
}

export function deactivate() {
    console.log('Vow extension deactivated');
}