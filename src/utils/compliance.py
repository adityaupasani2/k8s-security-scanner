"""
Compliance Framework Mapper
Maps findings to compliance frameworks
"""

from typing import List, Dict, Any
from collections import defaultdict


class ComplianceMapper:
    """
    Maps security findings to compliance frameworks
    """
    
    # Common compliance frameworks
    FRAMEWORKS = {
        'CIS': 'CIS Kubernetes Benchmark',
        'PCI-DSS': 'PCI Data Security Standard',
        'NIST': 'NIST 800-190 Container Security',
        'GDPR': 'General Data Protection Regulation',
        'SOC2': 'SOC 2 Type II',
        'HIPAA': 'Health Insurance Portability and Accountability Act'
    }
    
    def analyze_compliance(
        self, 
        findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Analyze findings for compliance violations
        
        Args:
            findings: List of all findings
            
        Returns:
            Compliance analysis summary
        """
        # Group findings by compliance framework
        framework_violations = defaultdict(list)
        
        for finding in findings:
            compliance_refs = finding.get('compliance', [])
            for ref in compliance_refs:
                # Extract framework prefix (e.g., "CIS-5.2.1" -> "CIS")
                framework = ref.split('-')[0] if '-' in ref else ref
                framework_violations[framework].append({
                    'reference': ref,
                    'issue': finding['issue'],
                    'severity': finding['severity'],
                    'pod': finding['pod_name']
                })
        
        # Calculate compliance scores per framework
        framework_scores = {}
        for framework, violations in framework_violations.items():
            # Count by severity
            critical = sum(1 for v in violations if v['severity'] == 'CRITICAL')
            high = sum(1 for v in violations if v['severity'] == 'HIGH')
            
            # Simple compliance calculation
            # More critical issues = lower compliance
            if critical > 0:
                compliance_pct = max(0, 60 - (critical * 10) - (high * 5))
            elif high > 0:
                compliance_pct = max(0, 80 - (high * 5))
            else:
                compliance_pct = 90
            
            framework_scores[framework] = {
                'compliance_percentage': compliance_pct,
                'total_violations': len(violations),
                'critical_violations': critical,
                'high_violations': high,
                'status': self._get_compliance_status(compliance_pct)
            }
        
        return {
            'framework_scores': framework_scores,
            'framework_violations': dict(framework_violations),
            'total_frameworks_affected': len(framework_violations)
        }
    
    def _get_compliance_status(self, percentage: int) -> str:
        """Get compliance status from percentage"""
        if percentage >= 90:
            return 'COMPLIANT'
        elif percentage >= 70:
            return 'MOSTLY_COMPLIANT'
        elif percentage >= 50:
            return 'PARTIALLY_COMPLIANT'
        else:
            return 'NON_COMPLIANT'
    
    def get_framework_name(self, framework_code: str) -> str:
        """Get full framework name from code"""
        return self.FRAMEWORKS.get(framework_code, framework_code)
