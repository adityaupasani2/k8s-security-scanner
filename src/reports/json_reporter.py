"""
JSON Reporter
Generates JSON output for CI/CD integration
"""

import json
from typing import List, Dict, Any
from datetime import datetime


class JSONReporter:
    """
    Generates JSON reports for automation and CI/CD
    """
    
    def __init__(
        self,
        findings: List[Dict[str, Any]],
        pod_scores: List[Dict[str, Any]],
        overall_score: Dict[str, Any],
        compliance_data: Dict[str, Any],
        namespace: str,
        total_pods: int
    ):
        """
        Initialize JSON reporter
        
        Args:
            findings: All security findings
            pod_scores: Per-pod security scores
            overall_score: Overall security score
            compliance_data: Compliance analysis
            namespace: Scanned namespace
            total_pods: Total number of pods scanned
        """
        self.findings = findings
        self.pod_scores = pod_scores
        self.overall_score = overall_score
        self.compliance_data = compliance_data
        self.namespace = namespace
        self.total_pods = total_pods
    
    def generate_report(self) -> Dict[str, Any]:
        """
        Generate complete JSON report
        
        Returns:
            Dictionary containing full report
        """
        # Count findings by severity
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        
        for finding in self.findings:
            severity = finding.get('severity', 'LOW').lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Build report structure
        report = {
            'metadata': {
                'scan_date': datetime.utcnow().isoformat() + 'Z',
                'scanner_version': '1.0.0',
                'namespace': self.namespace,
                'total_pods_scanned': self.total_pods,
                'total_issues_found': len(self.findings)
            },
            'summary': {
                'security_score': self.overall_score['score'],
                'grade': self.overall_score['grade'],
                'risk_level': self.overall_score['risk_level'],
                'findings_count': len(self.findings),
                'severity_breakdown': severity_counts,
                'pods_analyzed': len(self.pod_scores),
                'pass': self._determine_pass_fail()
            },
            'findings': self._format_findings(),
            'pod_scores': self._format_pod_scores(),
            'compliance': self._format_compliance(),
            'recommendations': self._generate_recommendations()
        }
        
        return report
    
    def _format_findings(self) -> List[Dict[str, Any]]:
        """Format findings for JSON output"""
        formatted = []
        
        for finding in self.findings:
            formatted.append({
                'id': f"{finding['pod_name']}-{finding['container_name']}-{hash(finding['issue']) % 10000}",
                'severity': finding.get('severity', 'LOW'),
                'category': finding.get('category', 'unknown'),
                'issue': finding['issue'],
                'description': finding.get('description', ''),
                'remediation': finding.get('remediation', ''),
                'pod': {
                    'name': finding['pod_name'],
                    'namespace': finding['namespace'],
                    'container': finding['container_name']
                },
                'compliance': finding.get('compliance', [])
            })
        
        return formatted
    
    def _format_pod_scores(self) -> List[Dict[str, Any]]:
        """Format pod scores for JSON output"""
        formatted = []
        
        for pod_data in self.pod_scores:
            formatted.append({
                'name': pod_data['name'],
                'namespace': pod_data['namespace'],
                'security_score': pod_data['score'],
                'grade': pod_data['grade'],
                'risk_level': pod_data['risk_level'],
                'findings_count': pod_data['findings_count'],
                'severity_breakdown': pod_data['severity_breakdown']
            })
        
        return formatted
    
    def _format_compliance(self) -> Dict[str, Any]:
        """Format compliance data for JSON output"""
        framework_scores = self.compliance_data.get('framework_scores', {})
        
        formatted = {}
        for framework, data in framework_scores.items():
            formatted[framework] = {
                'compliance_percentage': data['compliance_percentage'],
                'status': data['status'],
                'total_violations': data['total_violations'],
                'critical_violations': data['critical_violations'],
                'high_violations': data['high_violations']
            }
        
        return formatted
    
    def _generate_recommendations(self) -> List[Dict[str, Any]]:
        """Generate prioritized recommendations"""
        recommendations = []
        
        severity_counts = self.overall_score['severity_breakdown']
        
        if severity_counts['CRITICAL'] > 0:
            recommendations.append({
                'priority': 'URGENT',
                'action': f"Fix {severity_counts['CRITICAL']} CRITICAL issues immediately",
                'impact': 'HIGH'
            })
        
        if severity_counts['HIGH'] > 0:
            recommendations.append({
                'priority': 'HIGH',
                'action': f"Address {severity_counts['HIGH']} HIGH severity issues",
                'impact': 'MEDIUM'
            })
        
        if severity_counts['MEDIUM'] > 3:
            recommendations.append({
                'priority': 'MEDIUM',
                'action': f"Remediate {severity_counts['MEDIUM']} MEDIUM severity issues",
                'impact': 'LOW'
            })
        
        if self.overall_score['score'] < 70:
            recommendations.append({
                'priority': 'HIGH',
                'action': 'Consider blocking deployment until security score improves',
                'impact': 'HIGH'
            })
        
        return recommendations
    
    def _determine_pass_fail(self) -> bool:
        """
        Determine if scan passes based on findings
        
        Returns:
            True if pass, False if fail
        """
        # Fail if there are critical issues
        severity_counts = self.overall_score['severity_breakdown']
        
        if severity_counts['CRITICAL'] > 0:
            return False
        
        # Fail if score is below 60
        if self.overall_score['score'] < 60:
            return False
        
        return True
    
    def save_to_file(self, filename: str) -> bool:
        """
        Save JSON report to file
        
        Args:
            filename: Output filename
            
        Returns:
            True if successful
        """
        try:
            report = self.generate_report()
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"Error saving JSON file: {e}")
            return False
    
    def get_exit_code(self) -> int:
        """
        Get appropriate exit code for CI/CD
        
        Returns:
            0 if pass, 1 if fail
        """
        report = self.generate_report()
        return 0 if report['summary']['pass'] else 1
