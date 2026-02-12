# Contributing to Kubernetes Security Scanner

Thank you for your interest in contributing! 🎉

## Ways to Contribute

- 🐛 Report bugs via GitHub Issues
- 💡 Suggest new security checks
- 📝 Improve documentation
- 🔧 Submit bug fixes
- ✨ Add new features

## Development Setup
```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/k8s-security-scanner.git
cd k8s-security-scanner

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create test cluster
kind create cluster --name security-test
kubectl apply -f test-workloads/vulnerable-pods.yaml

# Run scanner
python src/main.py --namespace default
```

## Adding a New Scanner

1. Create scanner file in `src/scanners/`:
```python
from .base_scanner import BaseScanner
from typing import List, Dict, Any

class MyNewScanner(BaseScanner):
    """
    Description of what this scanner checks
    """
    
    def scan(self, pod) -> List[Dict[str, Any]]:
        findings = []
        
        # Your check logic here
        
        return findings
    
    def _get_category(self) -> str:
        return "category_name"
```

2. Add to `ScannerManager` in `src/utils/scanner_manager.py`:
```python
from src.scanners.my_new_scanner import MyNewScanner

# In __init__:
self.scanners = [
    # ... existing scanners
    MyNewScanner(),
]
```

3. Test with vulnerable workloads
4. Document in `CHECKS.md`
5. Update README count

## Pull Request Process

1. Create a feature branch
```bash
   git checkout -b feature/new-scanner
```

2. Make your changes
   - Follow existing code style
   - Add docstrings
   - Keep it simple

3. Test your changes
```bash
   python src/main.py --namespace default
```

4. Commit with clear message
```bash
   git commit -am "Add scanner for X"
```

5. Push and open PR
```bash
   git push origin feature/new-scanner
```

6. Describe what your PR does and why

## Code Style

- Follow PEP 8
- Use type hints
- Write clear docstrings
- Keep functions focused
- Add comments for complex logic

## Testing

Run against test workloads:
```bash
# Deploy vulnerable pods
kubectl apply -f test-workloads/vulnerable-pods.yaml

# Run scanner
python src/main.py --namespace default --detailed

# Verify your scanner detects the issue
python src/main.py --output json | jq '.findings[] | select(.issue | contains("YOUR_ISSUE"))'
```

## Questions?

Open an issue or reach out:
- GitHub Issues: adityaupasani2
- Email: adityaupasani29@gmail.com

Thank you for contributing! 🙏
