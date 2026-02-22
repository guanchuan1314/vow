# CI/CD Integration

Integrating Vow into your CI/CD pipeline helps catch AI output issues before they reach production. This guide covers setup for major CI platforms and best practices for automated verification.

## GitHub Actions

### Basic Setup

Create `.github/workflows/vow-check.yml`:

```yaml
name: AI Output Verification
on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  vow-check:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        
      - name: Install Vow
        run: |
          curl -L https://github.com/guanchuan1314/vow/releases/latest/download/vow-linux-x86_64 -o vow
          chmod +x vow
          sudo mv vow /usr/local/bin/
          
      - name: Setup Vow models
        run: vow setup --models code,security
        
      - name: Check AI-generated content
        run: vow check . --format sarif --output vow-results.sarif
        
      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: vow-results.sarif
```

### Advanced Configuration

```yaml
name: Comprehensive AI Verification
on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  vow-check:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        check-type: [code, docs, security]
        
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # For changed files detection
          
      - name: Get changed files
        id: changed-files
        uses: tj-actions/changed-files@v40
        with:
          files: |
            **/*.py
            **/*.js
            **/*.ts
            **/*.md
            **/*.rst
            
      - name: Install Vow
        if: steps.changed-files.outputs.any_changed == 'true'
        run: |
          # Use cached binary if available
          curl -L https://github.com/guanchuan1314/vow/releases/latest/download/vow-linux-x86_64 -o vow
          chmod +x vow
          sudo mv vow /usr/local/bin/
          
      - name: Cache Vow models
        if: steps.changed-files.outputs.any_changed == 'true'
        uses: actions/cache@v3
        with:
          path: ~/.local/share/vow/models
          key: vow-models-${{ runner.os }}-${{ hashFiles('**/vow-version') }}
          restore-keys: vow-models-${{ runner.os }}-
          
      - name: Setup Vow
        if: steps.changed-files.outputs.any_changed == 'true'
        run: vow setup --models ${{ matrix.check-type }}
        
      - name: Check changed files
        if: steps.changed-files.outputs.any_changed == 'true'
        run: |
          echo "${{ steps.changed-files.outputs.all_changed_files }}" | \
          xargs vow check --analyzers ${{ matrix.check-type }} \
            --format sarif \
            --output vow-${{ matrix.check-type }}-results.sarif \
            --min-trust-score 0.7
            
      - name: Upload SARIF
        if: always() && steps.changed-files.outputs.any_changed == 'true'
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: vow-${{ matrix.check-type }}-results.sarif
          category: vow-${{ matrix.check-type }}
```

### Pull Request Comments

Add PR comments with Vow results:

```yaml
      - name: Run Vow check
        id: vow-check
        run: |
          vow check . --format json --output vow-results.json
          echo "results_file=vow-results.json" >> $GITHUB_OUTPUT
        continue-on-error: true
        
      - name: Comment PR
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v6
        with:
          script: |
            const fs = require('fs');
            const results = JSON.parse(fs.readFileSync('${{ steps.vow-check.outputs.results_file }}', 'utf8'));
            
            const summary = results.summary;
            const issues = results.files.flatMap(f => f.issues || []);
            
            let comment = `## 🤖 AI Output Verification Results\n\n`;
            comment += `**Trust Score**: ${summary.trust_score_avg.toFixed(2)}/1.0\n`;
            comment += `**Files Checked**: ${summary.total_files}\n`;
            comment += `**Issues Found**: ${issues.length}\n\n`;
            
            if (issues.length > 0) {
              comment += `### Issues Found\n\n`;
              issues.slice(0, 10).forEach(issue => {
                comment += `- **${issue.severity.toUpperCase()}**: ${issue.message} (${issue.rule})\n`;
              });
              
              if (issues.length > 10) {
                comment += `\n... and ${issues.length - 10} more issues.\n`;
              }
            } else {
              comment += `✅ No issues found! Good job on the AI output quality.\n`;
            }
            
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: comment
            });
```

## GitLab CI

### Basic Pipeline

`.gitlab-ci.yml`:

```yaml
stages:
  - test
  - security

variables:
  VOW_VERSION: "latest"

vow-check:
  stage: test
  image: ubuntu:22.04
  
  before_script:
    - apt-get update && apt-get install -y curl
    - curl -L "https://github.com/guanchuan1314/vow/releases/latest/download/vow-linux-x86_64" -o vow
    - chmod +x vow && mv vow /usr/local/bin/
    - vow setup --models code,text
    
  script:
    - vow check . --format json --output vow-results.json
    
  artifacts:
    reports:
      # GitLab will display SARIF results in security dashboard
      sast: vow-sarif-results.sarif
    paths:
      - vow-results.json
    expire_in: 1 week
    
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

### Advanced GitLab Setup

```yaml
# Include template for better SARIF support
include:
  - template: Security/SAST.gitlab-ci.yml

vow-security-scan:
  stage: test
  image: ubuntu:22.04
  
  variables:
    TRUST_SCORE_THRESHOLD: "0.7"
    
  script:
    - |
      # Install Vow
      curl -L "https://github.com/guanchuan1314/vow/releases/latest/download/vow-linux-x86_64" -o vow
      chmod +x vow && mv vow /usr/local/bin/
      
      # Setup with caching
      vow setup --models all
      
      # Check only changed files in MRs
      if [ "$CI_PIPELINE_SOURCE" = "merge_request_event" ]; then
        git diff --name-only $CI_MERGE_REQUEST_TARGET_BRANCH_SHA..$CI_COMMIT_SHA | \
        grep -E '\.(py|js|ts|md)$' | \
        xargs -r vow check --min-trust-score $TRUST_SCORE_THRESHOLD
      else
        vow check . --min-trust-score $TRUST_SCORE_THRESHOLD
      fi
      
  artifacts:
    reports:
      sast: vow-results.sarif
```

## Jenkins

### Declarative Pipeline

`Jenkinsfile`:

```groovy
pipeline {
    agent any
    
    environment {
        VOW_CACHE = "${WORKSPACE}/.vow-cache"
    }
    
    stages {
        stage('Setup') {
            steps {
                script {
                    // Download and cache Vow binary
                    sh '''
                        if [ ! -f vow ]; then
                            curl -L https://github.com/guanchuan1314/vow/releases/latest/download/vow-linux-x86_64 -o vow
                            chmod +x vow
                        fi
                        ./vow --version
                    '''
                }
            }
        }
        
        stage('Model Setup') {
            steps {
                // Cache models between runs
                cache(maxCacheSize: 500, caches: [
                    arbitraryFileCache(path: '.vow-models', fingerprinting: true)
                ]) {
                    sh './vow setup --models code,security'
                }
            }
        }
        
        stage('AI Output Check') {
            parallel {
                stage('Code Analysis') {
                    steps {
                        sh '''
                            ./vow check . --analyzers code \
                              --format json --output vow-code-results.json \
                              --min-trust-score 0.6
                        '''
                    }
                }
                
                stage('Security Analysis') {
                    steps {
                        sh '''
                            ./vow check . --analyzers security \
                              --format sarif --output vow-security-results.sarif \
                              --min-trust-score 0.8
                        '''
                    }
                }
            }
        }
        
        stage('Process Results') {
            steps {
                // Archive results
                archiveArtifacts artifacts: 'vow-*.json,vow-*.sarif'
                
                // Publish SARIF results (requires SARIF plugin)
                publishSarif sarifFiles: 'vow-security-results.sarif'
                
                // Create summary
                script {
                    def results = readJSON file: 'vow-code-results.json'
                    def summary = results.summary
                    
                    echo "Trust Score: ${summary.trust_score_avg}"
                    echo "Files with issues: ${summary.files_with_issues}/${summary.total_files}"
                    
                    // Fail build if trust score too low
                    if (summary.trust_score_avg < 0.5) {
                        error("Trust score ${summary.trust_score_avg} below minimum threshold 0.5")
                    }
                }
            }
        }
    }
    
    post {
        always {
            // Clean up
            sh 'rm -f vow'
        }
        
        failure {
            emailext (
                subject: "Vow Check Failed: ${env.JOB_NAME} - ${env.BUILD_NUMBER}",
                body: "AI output verification failed. Check the build logs for details.",
                to: "${env.CHANGE_AUTHOR_EMAIL}"
            )
        }
    }
}
```

## Azure DevOps

### Azure Pipelines YAML

`azure-pipelines.yml`:

```yaml
trigger:
  branches:
    include:
      - main
      - develop

pr:
  branches:
    include:
      - main

pool:
  vmImage: 'ubuntu-latest'

variables:
  vowVersion: 'latest'
  trustScoreThreshold: 0.7

stages:
- stage: AIVerification
  displayName: 'AI Output Verification'
  jobs:
  - job: VowCheck
    displayName: 'Run Vow Analysis'
    
    steps:
    - checkout: self
      fetchDepth: 0
      
    - task: Cache@2
      inputs:
        key: 'vow-models | "$(Agent.OS)" | "$(vowVersion)"'
        path: $(Pipeline.Workspace)/.vow-models
        cacheHitVar: MODELS_CACHE_RESTORED
        
    - bash: |
        curl -L https://github.com/guanchuan1314/vow/releases/latest/download/vow-linux-x86_64 -o vow
        chmod +x vow
        sudo mv vow /usr/local/bin/
      displayName: 'Install Vow'
      
    - bash: |
        vow setup --models all
      displayName: 'Setup Vow Models'
      condition: ne(variables.MODELS_CACHE_RESTORED, 'true')
      
    - bash: |
        # Check changed files only for PRs
        if [ "$(Build.Reason)" = "PullRequest" ]; then
          git diff --name-only HEAD~1 | grep -E '\.(py|js|ts|md)$' | xargs -r vow check
        else
          vow check .
        fi
        
        vow check . --format sarif --output $(Agent.TempDirectory)/vow-results.sarif
      displayName: 'Run Vow Analysis'
      
    - task: PublishTestResults@2
      condition: always()
      inputs:
        testResultsFormat: 'SARIF'
        testResultsFiles: '$(Agent.TempDirectory)/vow-results.sarif'
        mergeTestResults: true
        
    - bash: |
        # Generate summary for PR comment
        vow check . --format json --output vow-summary.json
        
        TRUST_SCORE=$(jq -r '.summary.trust_score_avg' vow-summary.json)
        ISSUES_COUNT=$(jq -r '.summary.files_with_issues' vow-summary.json)
        
        echo "##vso[task.setvariable variable=TrustScore]$TRUST_SCORE"
        echo "##vso[task.setvariable variable=IssuesCount]$ISSUES_COUNT"
        
        # Fail if below threshold
        if (( $(echo "$TRUST_SCORE < $(trustScoreThreshold)" | bc -l) )); then
          echo "##vso[task.logissue type=error]Trust score $TRUST_SCORE below threshold $(trustScoreThreshold)"
          exit 1
        fi
      displayName: 'Process Results'
```

## Docker Integration

### Dockerfile for CI

```dockerfile
# Multi-stage build for CI
FROM ubuntu:22.04 as vow-installer
RUN apt-get update && apt-get install -y curl
RUN curl -L https://github.com/guanchuan1314/vow/releases/latest/download/vow-linux-x86_64 -o /usr/local/bin/vow
RUN chmod +x /usr/local/bin/vow

FROM ubuntu:22.04
COPY --from=vow-installer /usr/local/bin/vow /usr/local/bin/vow

# Pre-download models
RUN vow setup --models all

# Set up entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
```

### Docker Compose for Local Testing

```yaml
# docker-compose.ci.yml
version: '3.8'

services:
  vow-check:
    build: 
      context: .
      dockerfile: Dockerfile.vow
    volumes:
      - .:/workspace
    working_dir: /workspace
    command: vow check . --format json --output /workspace/results.json
    
  vow-server:
    image: ghcr.io/guanchuan1314/vow:latest
    ports:
      - "8080:8080"
    command: vow daemon --port 8080 --bind 0.0.0.0
    volumes:
      - vow-models:/app/models
      
volumes:
  vow-models:
```

## Pre-commit Integration

### Pre-commit Hook

`.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: vow-check
        name: AI Output Verification
        entry: vow
        args: [check, --min-trust-score, "0.6", --format, table]
        language: system
        files: \.(py|js|ts|md)$
        pass_filenames: true
```

### Git Hook Script

`.git/hooks/pre-commit`:

```bash
#!/bin/sh
# AI output verification pre-commit hook

# Check if vow is installed
if ! command -v vow &> /dev/null; then
    echo "Warning: Vow not installed, skipping AI verification"
    exit 0
fi

# Get staged files
staged_files=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(py|js|ts|md)$')

if [ -z "$staged_files" ]; then
    echo "No relevant files to check"
    exit 0
fi

echo "Running AI output verification on staged files..."

# Run vow on staged files
echo "$staged_files" | xargs vow check --min-trust-score 0.5 --format table

result=$?

if [ $result -ne 0 ]; then
    echo ""
    echo "❌ AI output verification failed!"
    echo "Fix the issues above or use 'git commit --no-verify' to skip verification"
    exit 1
fi

echo "✅ AI output verification passed"
exit 0
```

## Best Practices

### 1. Gradual Adoption

Start with warnings, gradually enforce:

```yaml
# Week 1: Just collect data
- vow check . --format json --output results.json || true

# Week 2: Warn on low scores  
- vow check . --min-trust-score 0.3 --format table || true

# Week 3: Fail on very low scores
- vow check . --min-trust-score 0.5

# Week 4: Raise the bar
- vow check . --min-trust-score 0.7
```

### 2. Different Standards by File Type

```yaml
script:
  # Strict for production code
  - vow check src/ --min-trust-score 0.8 --analyzers code,security
  
  # Medium for documentation
  - vow check docs/ --min-trust-score 0.6 --analyzers text
  
  # Lenient for tests/examples
  - vow check test/ examples/ --min-trust-score 0.4 || true
```

### 3. Performance Optimization

```yaml
# Cache models between runs
- uses: actions/cache@v3
  with:
    path: ~/.local/share/vow/models
    key: vow-models-${{ hashFiles('vow-version') }}

# Only check changed files in PRs
- name: Get changed files
  if: github.event_name == 'pull_request'
  run: |
    git diff --name-only ${{ github.event.pull_request.base.sha }}..${{ github.sha }} > changed_files.txt
    
- name: Check changed files only
  if: github.event_name == 'pull_request'
  run: |
    cat changed_files.txt | grep -E '\.(py|js|ts)$' | xargs -r vow check
```

### 4. Results Integration

```yaml
# Multiple output formats for different consumers
- vow check . --format sarif --output security-results.sarif  # For GitHub Security
- vow check . --format json --output ci-results.json         # For processing
- vow check . --format html --output report.html             # For humans
```

## Troubleshooting

### Common Issues

**Model download timeouts:**
```yaml
- name: Setup with retry
  run: |
    for i in {1..3}; do
      if vow setup --models code,security; then
        break
      fi
      echo "Attempt $i failed, retrying..."
      sleep 10
    done
```

**Large repository performance:**
```yaml
# Use parallel processing and caching
- name: Fast check for large repos
  run: |
    vow check . --jobs 4 --cache --timeout 60 \
      --exclude "node_modules/**" \
      --exclude "vendor/**" \
      --max-file-size 1MB
```

**False positives in generated code:**
```yaml
# Skip auto-generated files
- name: Check only human-written code
  run: |
    vow check . \
      --exclude "**/generated/**" \
      --exclude "**/*.pb.py" \
      --exclude "**/*_pb2.py"
```

## Next Steps

- [Configuration File](../configuration/config-file.md) - Customize Vow behavior for CI
- [Output Formats](../reference/output-formats.md) - Understanding CI-friendly formats
- [Trust Score](../reference/trust-score.md) - Setting appropriate thresholds