# 🔒 Kubernetes Security Scanner

A Python-based CLI tool that scans Kubernetes clusters for security misconfigurations and vulnerabilities.

## Features

- ✅ Scans pods for security issues (root user, privileged containers, etc.)
- ✅ Checks resource limits and requests
- ✅ Validates image tags and sources
- ✅ Detects exposed secrets
- ✅ Multiple output formats (table, JSON, HTML)
- ✅ Beautiful terminal UI with colors

## Installation
```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/k8s-security-scanner.git
cd k8s-security-scanner

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## Usage
```bash
# Scan default namespace
python src/main.py --namespace default

# Scan all namespaces
python src/main.py --all-namespaces

# Use shortcut script
./scan.sh --namespace production
```

## Security Checks

- [ ] Container running as root
- [ ] Privileged containers
- [ ] Missing resource limits
- [ ] Using :latest image tags
- [ ] Secrets in environment variables
- [ ] Host network access
- [ ] Host path mounts
- [ ] Missing network policies
- _More checks coming soon..._

## Development Status

🚧 **Work in Progress** - Currently in active development

- ✅ Day 1: Project setup and framework complete
- 🔄 Day 2-7: Implementing security scanners
- 📅 Day 8-10: Report generation
- 📅 Day 11-14: Documentation and polish

## Requirements

- Python 3.9+
- Kubernetes cluster (local or remote)
- kubectl configured

## Author

**Aditya Upasani**
- CKA Certified
- DevOps & Cloud Security Enthusiast

## License

MIT License

---

⭐ Star this repo if you find it useful!
