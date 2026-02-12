# 🔒 Kubernetes Security Scanner

A comprehensive Python-based CLI tool that scans Kubernetes clusters for security misconfigurations and vulnerabilities.

![Status](https://img.shields.io/badge/Status-Production%20Ready-green)
![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![License](https://img.shields.io/badge/License-MIT-blue)
![Scanners](https://img.shields.io/badge/Security%20Checks-20-brightgreen)

## 🎯 Features

- ✅ **20 Security Checks** across 6 categories
- ✅ **CI/CD Ready** with JSON output and exit codes
- ✅ **Compliance Mapping** (CIS, PCI-DSS, NIST, GDPR, SOC2)
- ✅ **Security Scoring** (0-100 scale with letter grades)
- ✅ **Multiple Output Formats** (Terminal tables, JSON, Text)
- ✅ **Production Grade** with comprehensive remediation advice

---

## 📊 What It Detects

### Security Categories

| Category | Checks | Example Issues |
|----------|--------|----------------|
| **Pod Security** | 8 | Root users, privileged containers, missing security contexts |
| **Resource Management** | 3 | Missing CPU/memory limits and requests |
| **Image Security** | 3 | `:latest` tags, untrusted registries |
| **Secrets Management** | 1 | Hardcoded passwords, API keys in env vars |
| **Network Security** | 3 | Host network access, host path volumes |
| **RBAC** | 2 | Default service accounts, automounted tokens |

### Severity Levels

- 🚨 **CRITICAL** - Immediate risk (root users, privileged, hardcoded secrets)
- ⚠️ **HIGH** - Significant risk (missing limits, host access, privilege escalation)
- 🔵 **MEDIUM** - Moderate risk (image issues, default SAs, writable filesystems)
- ℹ️ **LOW** - Defense-in-depth (missing AppArmor, seccomp)

---

## 🚀 Quick Start

### Installation
```bash
# Clone repository
git clone https://github.com/adityaupasani2/k8s-security-scanner.git
cd k8s-security-scanner

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage
```bash
# Scan default namespace
python src/main.py

# Or use the shortcut
./scan.sh

# Scan specific namespace
python src/main.py --namespace production

# Scan all namespaces
python src/main.py --all-namespaces

# Show detailed tables
python src/main.py --detailed

# Output JSON for CI/CD
python src/main.py --output json
```

---

## 📋 Example Output
```
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║        🔒 KUBERNETES SECURITY SCANNER v1.0 🔒           ║
║                                                          ║
║     Detect security misconfigurations in K8s clusters   ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝

✓ Loaded 20 security scanners

📡 Scanning namespace: default

✓ Found 4 pods in namespace 'default'

============================================================
📊 SCAN RESULTS
============================================================

Total pods scanned: 4
Total issues found: 42

🚨 CRITICAL Issues: 7
  ├─ vulnerable-nginx/nginx
  │  Container running as root user
  ├─ vulnerable-nginx/nginx
  │  Hardcoded secret in environment variable: DATABASE_PASSWORD
  └─ ... and 5 more

⚠️  HIGH Issues: 8
  ├─ redis-with-hostpath/redis
  │  Missing CPU limit
  ├─ redis-with-hostpath/redis
  │  Missing memory limit
  └─ ... and 6 more

🔵 MEDIUM Issues: 19

ℹ️  LOW Issues: 8

============================================================
Security Score: 0/100 (Grade: F)
Risk Level: CRITICAL
============================================================

📋 Recommendations:
  🚨 URGENT: Fix 7 CRITICAL issues immediately
  ⚠️  HIGH Priority: Address 8 HIGH severity issues
  💥 Pod is extremely vulnerable - consider blocking deployment
```

---

## 🔍 Complete Security Checks

<details>
<summary><b>Pod Security (8 checks)</b></summary>

1. **Root User Detection** (CRITICAL) - Containers running as UID 0
2. **Privileged Containers** (CRITICAL) - Privileged mode enabled
3. **Privilege Escalation** (HIGH) - `allowPrivilegeEscalation` not blocked
4. **Read-Only Filesystem** (MEDIUM) - Writable root filesystem
5. **Dangerous Capabilities** (HIGH/MED) - Risky Linux capabilities
6. **Missing Security Context** (MEDIUM) - No security context defined
7. **AppArmor/SELinux** (LOW) - Missing MAC profiles
8. **Seccomp Profiles** (LOW) - Missing syscall filtering

</details>

<details>
<summary><b>Resource Management (3 checks)</b></summary>

9. **CPU Limits** (HIGH) - Missing CPU limits
10. **Memory Limits** (HIGH) - Missing memory limits
11. **Resource Requests** (MEDIUM) - Missing CPU/memory requests

</details>

<details>
<summary><b>Image Security (3 checks)</b></summary>

12. **Latest Tag** (MEDIUM) - Using `:latest` image tag
13. **Untagged Images** (MEDIUM) - No image tag specified
14. **Untrusted Registry** (MEDIUM) - Images from untrusted registries

</details>

<details>
<summary><b>Secrets Management (1 check)</b></summary>

15. **Hardcoded Secrets** (CRITICAL) - Secrets in environment variables

</details>

<details>
<summary><b>Network Security (3 checks)</b></summary>

16. **Host Network** (HIGH) - Using host network namespace
17. **Host Path Volumes** (HIGH) - Mounting host filesystem
18. **Host Namespaces** (MEDIUM) - Using host PID/IPC namespaces

</details>

<details>
<summary><b>RBAC (2 checks)</b></summary>

19. **Default Service Account** (MEDIUM) - Using default service account
20. **Automounted Tokens** (MEDIUM) - Service account tokens automounted

</details>

See [CHECKS.md](CHECKS.md) for detailed information on each check.

---

## 🛠️ Command Line Options

| Option | Short | Description | Example |
|--------|-------|-------------|---------|
| `--namespace` | `-n` | Namespace to scan | `-n production` |
| `--all-namespaces` | `-A` | Scan all namespaces | `-A` |
| `--output` | `-o` | Output format (table, json) | `-o json` |
| `--detailed` | `-d` | Show detailed tables | `-d` |
| `--save` | `-s` | Save report to file | `-s report.txt` |
| `--fail-on-critical` | | Exit code 1 if CRITICAL found | |
| `--min-score` | | Minimum score threshold | `--min-score 70` |

---

## 🔄 CI/CD Integration

### GitHub Actions
```yaml
name: K8s Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Security Scan
        run: |
          python src/main.py \
            --output json \
            --fail-on-critical \
            --min-score 70
```

### Exit Codes

- **0**: Scan passed ✅
- **1**: Scan failed (critical issues or low score) ❌

### JSON Output

Perfect for automation:
```bash
# Get security score
python src/main.py --output json | jq '.summary.security_score'

# Count critical issues
python src/main.py --output json | jq '.summary.severity_breakdown.critical'

# Check pass/fail
python src/main.py --output json | jq '.summary.pass'
```

See [examples/ci-cd/](examples/ci-cd/) for complete CI/CD examples.

---

## 📚 Documentation

- **[USAGE.md](USAGE.md)** - Complete usage guide with examples
- **[CHECKS.md](CHECKS.md)** - Detailed documentation of all 20 security checks
- **[examples/ci-cd/](examples/ci-cd/)** - GitHub Actions, GitLab CI, Jenkins examples

---

## 🏗️ Project Structure
```
k8s-security-scanner/
├── src/
│   ├── main.py                          # CLI entry point
│   ├── scanners/                        # Security check modules
│   │   ├── base_scanner.py              # Base scanner class
│   │   ├── root_user_scanner.py
│   │   ├── privileged_scanner.py
│   │   ├── secrets_in_env_scanner.py
│   │   └── ... (20 total scanners)
│   ├── utils/
│   │   ├── scanner_manager.py           # Coordinates all scanners
│   │   ├── scoring.py                   # Security scoring engine
│   │   └── compliance.py                # Compliance framework mapper
│   └── reports/
│       ├── table_reporter.py            # Terminal table output
│       └── json_reporter.py             # JSON export
├── test-workloads/
│   └── vulnerable-pods.yaml             # Test workloads
├── examples/
│   └── ci-cd/                           # CI/CD integration examples
├── CHECKS.md                            # Security checks documentation
├── USAGE.md                             # Usage guide
└── README.md                            # This file
```

---

## 🎓 How It Works

1. **Connect** to Kubernetes cluster via kubeconfig
2. **Discover** pods in specified namespace(s)
3. **Analyze** each pod with 20 security scanners
4. **Score** findings based on severity and risk
5. **Report** results in chosen format
6. **Exit** with appropriate code for CI/CD

Each scanner:
- Inherits from `BaseScanner` base class
- Implements specific security check logic
- Returns standardized findings with severity, description, remediation
- Maps to compliance frameworks (CIS, PCI-DSS, NIST, etc.)

---

## 🔧 Development

### Adding a New Scanner

1. Create scanner in `src/scanners/`:
```python
from .base_scanner import BaseScanner

class MyScanner(BaseScanner):
    def scan(self, pod):
        findings = []
        # Your check logic here
        return findings
```

2. Add to `ScannerManager` in `src/utils/scanner_manager.py`
3. Test with vulnerable workloads
4. Document in `CHECKS.md`

### Running Tests
```bash
# Deploy test workloads
kubectl apply -f test-workloads/vulnerable-pods.yaml

# Run scanner
python src/main.py --namespace default

# Verify findings
python src/main.py --output json | jq '.summary'
```

---

## 🎯 Use Cases

### Local Development
```bash
# Quick security check before commit
./scan.sh --namespace dev
```

### Code Review
```bash
# Detailed analysis for PR
./scan.sh --detailed --save pr-security-report.txt
```

### CI/CD Pipeline
```bash
# Automated security gate
python src/main.py --output json --fail-on-critical --min-score 70
```

### Security Audits
```bash
# Comprehensive cluster scan
python src/main.py --all-namespaces --detailed --save audit-$(date +%Y%m%d).txt
```

### Monitoring & Alerts
```bash
# Daily scan with Slack notification
./scan.sh --all-namespaces --output json | \
  jq '.summary.security_score' | \
  xargs -I {} curl -X POST $SLACK_WEBHOOK \
    -d '{"text":"Security Score: {}/100"}'
```

---

## 📊 Security Score Guide

| Score | Grade | Risk | Action Required |
|-------|-------|------|-----------------|
| 95-100 | A+ | Minimal | Maintain current posture |
| 90-94 | A | Minimal | Minor improvements |
| 80-89 | B | Low | Review medium issues |
| 70-79 | B- | Moderate | Action recommended |
| 60-69 | C | Moderate | Remediation needed |
| 50-59 | D | High | Major fixes required |
| 0-49 | F | Critical | **Immediate action!** |

---

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-scanner`)
3. Commit changes (`git commit -am 'Add new scanner'`)
4. Push to branch (`git push origin feature/new-scanner`)
5. Open a Pull Request

---

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

**Aditya Upasani**
- 🏆 CKA Certified Kubernetes Administrator
- 🎓 MSc in Computational Science & Data Science
- 💼 DevOps Engineer with expertise in K8s, Docker, CI/CD
- 📧 adityaupasani29@gmail.com
- 🔗 [LinkedIn](https://linkedin.com/in/aditya-upasani)
- 🐙 [GitHub](https://github.com/adityaupasani2)

---

## 🙏 Acknowledgments

- Inspired by tools like kube-bench, kubeaudit, and Falco
- Built following CIS Kubernetes Benchmark guidelines
- Compliance mappings based on industry standards

---

## ⭐ Support

If you find this tool useful:
- ⭐ Star this repository
- 🐛 Report bugs via GitHub Issues
- 💡 Suggest features or improvements
- 📢 Share with your team

---

## 📈 Roadmap

- [x] 20 core security scanners
- [x] CI/CD integration
- [x] JSON export
- [x] Compliance framework mapping
- [ ] YAML/Helm chart scanning (pre-deployment)
- [ ] Custom scanner plugins
- [ ] Web dashboard (optional)
- [ ] Prometheus metrics export

---

**Built with ❤️ for the Kubernetes security community**
