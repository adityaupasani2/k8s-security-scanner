# 🔒 Kubernetes Security Scanner

A Python-based CLI tool that scans Kubernetes clusters for security misconfigurations and vulnerabilities.

![Scanner Demo](https://img.shields.io/badge/Status-In%20Development-yellow)
![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Kubernetes](https://img.shields.io/badge/Kubernetes-1.27%2B-blue)

## 🎯 What It Does

Automatically scans your Kubernetes clusters and detects critical security issues:

- ✅ Containers running as root
- ✅ Privileged containers
- ✅ Privilege escalation vulnerabilities
- ✅ Writable root filesystems
- 🔄 Missing resource limits (coming soon)
- 🔄 Insecure image tags (coming soon)
- 🔄 Exposed secrets (coming soon)
- 🔄 Network security issues (coming soon)

## ✨ Features

- **4 Active Security Scanners** (20+ planned)
- **Severity-Based Reporting** (Critical, High, Medium, Low)
- **Security Score** (0-100 grading system)
- **Compliance Mapping** (CIS Benchmarks, PCI-DSS, NIST)
- **Beautiful Terminal UI** with colors and formatting
- **Actionable Remediation** advice for every finding

## 🚀 Quick Start

### Prerequisites

- Python 3.9+
- Kubernetes cluster (local or remote)
- kubectl configured

### Installation
```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/k8s-security-scanner.git
cd k8s-security-scanner

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Usage
```bash
# Scan default namespace
python src/main.py --namespace default

# Scan all namespaces
python src/main.py --all-namespaces

# Use shortcut script
./scan.sh --namespace production
```

## 📊 Example Output
```
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║        🔒 KUBERNETES SECURITY SCANNER v1.0 🔒           ║
║                                                          ║
║     Detect security misconfigurations in K8s clusters   ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝

✓ Loaded 4 security scanners

📡 Scanning namespace: production

✓ Found 12 pods in namespace 'production'

============================================================
📊 SCAN RESULTS
============================================================

Total pods scanned: 12
Total issues found: 23

🚨 CRITICAL Issues: 8
  ├─ payment-api/app
  │  Container running as root user
  ├─ auth-service/redis
  │  Container running in privileged mode
  ...

⚠️  HIGH Issues: 5
🔵 MEDIUM Issues: 10

============================================================
Security Score: 35/100 (Grade: F)
============================================================

💡 Run with --output json or --output html for detailed reports
```

## 🔍 Security Checks

### Currently Implemented

| Check | Severity | Description |
|-------|----------|-------------|
| Root User | CRITICAL | Detects containers running as UID 0 |
| Privileged Containers | CRITICAL | Finds containers with privileged mode |
| Privilege Escalation | HIGH | Checks allowPrivilegeEscalation setting |
| Read-Only Filesystem | MEDIUM | Validates readOnlyRootFilesystem |

### Coming Soon (Days 3-5)

- [ ] Missing CPU/memory limits
- [ ] Missing resource requests
- [ ] Using :latest image tags
- [ ] Secrets in environment variables
- [ ] Host network/PID/IPC access
- [ ] Host path volumes
- [ ] Dangerous Linux capabilities
- [ ] Default service accounts
- [ ] Missing network policies
- [ ] Pod Security Standards violations
- _...and more_

## 🛠️ Development

### Project Structure
```
k8s-security-scanner/
├── src/
│   ├── main.py                          # CLI entry point
│   ├── scanners/
│   │   ├── base_scanner.py              # Base class for all scanners
│   │   ├── root_user_scanner.py         # Root user detection
│   │   ├── privileged_scanner.py        # Privileged container detection
│   │   ├── privilege_escalation_scanner.py
│   │   └── readonly_filesystem_scanner.py
│   ├── reports/                         # Report generators (coming soon)
│   └── utils/
│       └── scanner_manager.py           # Coordinates all scanners
├── test-workloads/
│   └── vulnerable-pods.yaml             # Test vulnerable workloads
├── requirements.txt
└── README.md
```

### Running Tests
```bash
# Test individual scanner
python test_root_scanner.py

# Run full scan
python src/main.py --namespace default
```

### Adding a New Scanner

1. Create new scanner in `src/scanners/`
2. Inherit from `BaseScanner`
3. Implement `scan()` method
4. Add to `ScannerManager` in `src/utils/scanner_manager.py`
5. Test with vulnerable workloads

Example:
```python
from .base_scanner import BaseScanner

class MyScanner(BaseScanner):
    def scan(self, pod):
        findings = []
        # Your scan logic here
        return findings
```

## 📈 Development Roadmap

- [x] **Day 1:** Project setup and framework ✅
- [x] **Day 2:** Core security scanners (4 checks) ✅
- [ ] **Day 3:** Resource and image scanners (6 checks)
- [ ] **Day 4:** Secrets and network scanners (5 checks)
- [ ] **Day 5:** Advanced scanners (5 checks)
- [ ] **Days 6-7:** Scoring system and remediation
- [ ] **Days 8-10:** Report generation (Table, JSON, HTML)
- [ ] **Days 11-14:** Testing, documentation, and launch

## 🎓 Technologies Used

- **Python 3.9+** - Core language
- **Kubernetes Python Client** - K8s API interaction
- **Click** - CLI framework
- **Colorama** - Terminal colors
- **Tabulate** - Table formatting
- **Jinja2** - HTML report templates (planned)

## 🤝 Contributing

Contributions are welcome! This project is actively being developed.

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📄 License

MIT License

## 👨‍💻 Author

**Aditya Upasani**
- 🏆 CKA Certified
- 🔐 DevOps & Cloud Security Enthusiast
- 📧 adityaupasani29@gmail.com
- 💼 [LinkedIn](https://linkedin.com/in/aditya-upasani)

## 🙏 Acknowledgments

- Inspired by tools like kube-bench, kubeaudit, and Falco
- Built with guidance from Kubernetes security best practices
- CIS Kubernetes Benchmark compliance

---

⭐ **Star this repo if you find it useful!**

🐛 **Found a bug? Open an issue!**

💡 **Have ideas? Start a discussion!**
