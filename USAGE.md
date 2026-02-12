# Usage Guide

Complete guide to using the Kubernetes Security Scanner.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Command Line Options](#command-line-options)
- [Output Formats](#output-formats)
- [CI/CD Integration](#cicd-integration)
- [Advanced Usage](#advanced-usage)
- [Troubleshooting](#troubleshooting)

---

## Installation

### Prerequisites

- Python 3.9 or higher
- kubectl configured with cluster access
- Virtual environment (recommended)

### Steps
```bash
# Clone repository
git clone https://github.com/adityaupasani2/k8s-security-scanner.git
cd k8s-security-scanner

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Verify installation
python src/main.py --help
```

---

## Quick Start

### Basic Scan

Scan the default namespace:
```bash
python src/main.py
```

Or use the convenience script:
```bash
./scan.sh
```

### Scan Specific Namespace
```bash
python src/main.py --namespace production
```

### Scan All Namespaces
```bash
python src/main.py --all-namespaces
```

---

## Command Line Options

### Core Options

| Option | Short | Description | Example |
|--------|-------|-------------|---------|
| `--namespace` | `-n` | Namespace to scan (default: default) | `-n production` |
| `--all-namespaces` | `-A` | Scan all namespaces | `-A` |
| `--output` | `-o` | Output format: table, json | `-o json` |
| `--detailed` | `-d` | Show detailed tables | `-d` |
| `--save` | `-s` | Save report to file | `-s report.txt` |
| `--fail-on-critical` | | Exit code 1 if CRITICAL found | |
| `--min-score` | | Minimum score (0-100) | `--min-score 70` |

### Examples
```bash
# Standard table output
python src/main.py --namespace default

# Detailed view with tables
python src/main.py --namespace default --detailed

# JSON output for automation
python src/main.py --namespace default --output json

# Save report to file
python src/main.py --namespace default --save report.txt

# Fail build if critical issues found
python src/main.py --fail-on-critical

# Require minimum score
python src/main.py --min-score 80
```

---

## Output Formats

### 1. Table Output (Default)

Standard terminal output with colored text.
```bash
python src/main.py --namespace default
```

**Output:**
```
🔒 KUBERNETES SECURITY SCANNER v1.0 🔒

✓ Loaded 20 security scanners

📡 Scanning namespace: default
✓ Found 4 pods in namespace 'default'

============================================================
📊 SCAN RESULTS
============================================================

Total pods scanned: 4
Total issues found: 42

🚨 CRITICAL Issues: 7
⚠️  HIGH Issues: 8
🔵 MEDIUM Issues: 19
ℹ️  LOW Issues: 8

Security Score: 0/100 (Grade: F)
Risk Level: CRITICAL
```

### 2. Detailed Table Output

Enhanced tables with statistics.
```bash
python src/main.py --namespace default --detailed
```

Shows:
- Summary statistics table
- Top findings table
- Per-pod security scores
- Compliance status table

### 3. JSON Output

Machine-readable format for CI/CD.
```bash
python src/main.py --namespace default --output json
```

**JSON Structure:**
```json
{
  "metadata": {
    "scan_date": "2024-02-12T15:30:00Z",
    "scanner_version": "1.0.0",
    "namespace": "default",
    "total_pods_scanned": 4
  },
  "summary": {
    "security_score": 35,
    "grade": "F",
    "risk_level": "CRITICAL",
    "pass": false,
    "severity_breakdown": {
      "critical": 7,
      "high": 8,
      "medium": 19,
      "low": 8
    }
  },
  "findings": [...],
  "pod_scores": [...],
  "compliance": {...},
  "recommendations": [...]
}
```

### 4. Text File Export

Save any output to file:
```bash
# Save table output
python src/main.py --save report.txt

# Save JSON output
python src/main.py --output json --save results.json

# Save detailed tables
python src/main.py --detailed --save detailed-report.txt
```

---

## CI/CD Integration

### Exit Codes

- `0`: Scan passed (no critical issues, score ≥ threshold)
- `1`: Scan failed (critical issues or score too low)

### GitHub Actions
```yaml
# .github/workflows/k8s-security.yml
name: K8s Security Scan

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'
      
      - name: Install scanner
        run: |
          pip install -r requirements.txt
      
      - name: Run security scan
        run: |
          python src/main.py \
            --namespace default \
            --output json \
            --save scan-results.json \
            --fail-on-critical \
            --min-score 70
      
      - name: Upload results
        uses: actions/upload-artifact@v3
        with:
          name: security-scan
          path: scan-results.json
```

### GitLab CI
```yaml
# .gitlab-ci.yml
k8s-security-scan:
  stage: test
  image: python:3.9
  script:
    - pip install -r requirements.txt
    - python src/main.py --output json --fail-on-critical
  artifacts:
    paths:
      - scan-results.json
```

### Jenkins
```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh '''
                    python src/main.py \
                        --namespace production \
                        --output json \
                        --save results.json \
                        --fail-on-critical
                '''
            }
        }
    }
}
```

---

## Advanced Usage

### Parsing JSON Output

Extract specific data from JSON results:
```bash
# Get security score
python src/main.py --output json | jq '.summary.security_score'

# Count critical issues
python src/main.py --output json | jq '.summary.severity_breakdown.critical'

# Get all pod scores
python src/main.py --output json | jq '.pod_scores[]'

# List all CRITICAL findings
python src/main.py --output json | jq '.findings[] | select(.severity=="CRITICAL")'
```

### Filtering Results
```bash
# Only scan specific pods (using kubectl)
kubectl get pods -n default -l app=myapp -o name | while read pod; do
    python src/main.py --namespace default
done
```

### Combining with Other Tools
```bash
# Send to Slack
SCORE=$(python src/main.py --output json | jq '.summary.security_score')
curl -X POST -H 'Content-type: application/json' \
  --data "{\"text\":\"Security Score: $SCORE/100\"}" \
  $SLACK_WEBHOOK_URL

# Create Jira ticket on failure
python src/main.py --fail-on-critical || \
  curl -X POST -u $JIRA_USER:$JIRA_TOKEN \
    -H "Content-Type: application/json" \
    -d '{"fields":{"project":{"key":"SEC"},"summary":"K8s Security Issues"}}' \
    $JIRA_URL/rest/api/2/issue
```

---

## Interpreting Results

### Security Scores

| Score | Grade | Risk Level | Action |
|-------|-------|------------|--------|
| 95-100 | A+ | MINIMAL | Maintain current security |
| 90-94 | A | MINIMAL | Minor improvements |
| 85-89 | A- | LOW | Address medium issues |
| 80-84 | B+ | LOW | Review high issues |
| 75-79 | B | LOW | Fix high priority items |
| 70-74 | B- | MODERATE | Action required |
| 60-69 | C | MODERATE | Significant issues |
| 50-59 | D | HIGH | Major remediation needed |
| 0-49 | F | CRITICAL | **Immediate action required** |

### Severity Levels

**CRITICAL (Score -15 each)**
- Root user containers
- Privileged containers
- Hardcoded secrets

**HIGH (Score -8 each)**
- Privilege escalation allowed
- Missing CPU/memory limits
- Host network/path access

**MEDIUM (Score -3 each)**
- Writable filesystems
- Missing resource requests
- Image tag issues
- Default service accounts

**LOW (Score -1 each)**
- Missing AppArmor/SELinux
- Missing seccomp profiles

### Compliance Frameworks

Reports map to:
- **CIS Kubernetes Benchmark** (CIS-5.x.x)
- **PCI-DSS** (Payment Card Industry)
- **NIST 800-190** (Container Security)
- **GDPR** (Data Protection)
- **SOC 2** (Security Controls)

---

## Troubleshooting

### Common Issues

#### "Could not load Kubernetes config"

**Problem:** Scanner can't find kubeconfig

**Solution:**
```bash
# Verify kubectl works
kubectl get pods

# Check kubeconfig location
echo $KUBECONFIG

# Specify kubeconfig explicitly
export KUBECONFIG=~/.kube/config
```

#### "No such file or directory: 'src/main.py'"

**Problem:** Running from wrong directory

**Solution:**
```bash
# Navigate to project root
cd ~/k8s-security-scanner

# Activate virtual environment
source venv/bin/activate
```

#### "ModuleNotFoundError: No module named 'kubernetes'"

**Problem:** Dependencies not installed

**Solution:**
```bash
# Activate venv first
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

#### "Namespace 'xyz' not found"

**Problem:** Scanning non-existent namespace

**Solution:**
```bash
# List available namespaces
kubectl get namespaces

# Scan correct namespace
python src/main.py --namespace existing-namespace
```

### Debug Mode

Enable verbose output:
```bash
# Python debugging
python -v src/main.py --namespace default

# See full traceback on errors
python src/main.py --namespace default 2>&1 | tee error.log
```

---

## Best Practices

### Regular Scanning
```bash
# Daily automated scan
0 2 * * * cd /path/to/scanner && ./scan.sh --all-namespaces --save daily-scan.json

# Pre-deployment checks
python src/main.py --namespace staging --fail-on-critical --min-score 70
```

### Progressive Enforcement

1. **Week 1**: Scan and report (no failures)
```bash
   python src/main.py --namespace default
```

2. **Week 2**: Fail on CRITICAL only
```bash
   python src/main.py --fail-on-critical
```

3. **Week 3**: Require minimum score
```bash
   python src/main.py --min-score 60
```

4. **Week 4**: Raise score requirement
```bash
   python src/main.py --min-score 80
```

### Team Workflows
```bash
# Developers: Quick local check
./scan.sh

# Code review: Detailed analysis
./scan.sh --detailed --save pr-scan.txt

# CI/CD: Automated gating
./scan.sh --output json --fail-on-critical --min-score 70

# Security team: Full audit
./scan.sh --all-namespaces --detailed --save audit-$(date +%Y%m%d).txt
```

---

## Getting Help

### Documentation

- [CHECKS.md](CHECKS.md) - Detailed info on all 20 security checks
- [README.md](README.md) - Project overview and quick start
- [examples/ci-cd/](examples/ci-cd/) - CI/CD integration examples

### Support

- GitHub Issues: [Report bugs or request features]
- Questions: Check existing issues or open a new one

### Contributing

See [CONTRIBUTING.md] for guidelines on:
- Adding new scanners
- Improving documentation
- Submitting bug fixes
