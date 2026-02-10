# CI/CD Integration Examples

This directory contains examples for integrating the Kubernetes Security Scanner into your CI/CD pipelines.

## GitHub Actions

Copy `github-actions.yml` to `.github/workflows/k8s-security-scan.yml` in your repository.

### Features:
- ✅ Runs on push, PR, and daily schedule
- ✅ Scans Kubernetes manifests automatically
- ✅ Uploads scan results as artifacts
- ✅ Comments on PRs with security summary
- ✅ Fails build if critical issues found

### Configuration:
```yaml
# Customize these options:
--fail-on-critical    # Exit code 1 if CRITICAL issues found
--min-score 70        # Fail if score below 70
--all-namespaces      # Scan all namespaces
```

## GitLab CI/CD

Copy `gitlab-ci.yml` to `.gitlab-ci.yml` in your repository.

### Features:
- ✅ Automated security scanning on every commit
- ✅ Configurable minimum security score
- ✅ Artifacts stored for 30 days
- ✅ HTML report generation
- ✅ Fail pipeline on critical issues

### Variables:
```yaml
MIN_SECURITY_SCORE: "70"   # Minimum acceptable score
SCANNER_VERSION: "1.0.0"   # Scanner version to use
```

## Jenkins
```groovy
pipeline {
    agent any
    
    stages {
        stage('K8s Security Scan') {
            steps {
                script {
                    sh '''
                        python src/main.py \
                            --namespace production \
                            --output json \
                            --save scan-results.json \
                            --fail-on-critical
                    '''
                }
            }
        }
        
        stage('Archive Results') {
            steps {
                archiveArtifacts artifacts: 'scan-results.json'
            }
        }
    }
}
```

## Exit Codes

- `0`: Scan passed (no critical issues, score ≥ threshold)
- `1`: Scan failed (critical issues or score below threshold)

## Command Line Options for CI/CD
```bash
# Fail if any CRITICAL issues found
python src/main.py --fail-on-critical

# Fail if security score below 70
python src/main.py --min-score 70

# Combine both checks
python src/main.py --fail-on-critical --min-score 80

# JSON output for parsing
python src/main.py --output json --save results.json

# Scan all namespaces
python src/main.py --all-namespaces --output json
```

## Example: Parse Results in CI
```bash
# Extract security score
SCORE=$(cat scan-results.json | jq '.summary.security_score')

# Count critical issues
CRITICAL=$(cat scan-results.json | jq '.summary.severity_breakdown.critical')

# Check pass/fail status
PASSED=$(cat scan-results.json | jq '.summary.pass')

if [ "$PASSED" = "false" ]; then
    echo "Security scan failed!"
    exit 1
fi
```

## Integration with Other Tools

### Slack Notifications
```bash
# Send results to Slack
SCORE=$(cat scan-results.json | jq '.summary.security_score')
curl -X POST -H 'Content-type: application/json' \
  --data "{\"text\":\"Security Score: $SCORE/100\"}" \
  $SLACK_WEBHOOK_URL
```

### Jira Ticket Creation
```bash
# Create Jira ticket if critical issues found
CRITICAL=$(cat scan-results.json | jq '.summary.severity_breakdown.critical')
if [ "$CRITICAL" -gt 0 ]; then
    # Create Jira ticket via API
    curl -X POST -H "Content-Type: application/json" \
      -d '{"fields":{"project":{"key":"SEC"},"summary":"K8s Critical Issues"}}' \
      $JIRA_API_URL
fi
```
