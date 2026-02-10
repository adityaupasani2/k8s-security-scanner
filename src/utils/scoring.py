"""
Security Scoring Engine
Calculates security scores for pods, namespaces, and clusters
"""

from typing import List, Dict, Any


class SecurityScorer:
    """
    Calculates security scores based on findings
    """
    
    # Point deductions by severity
    SEVERITY_WEIGHTS = {
        'CRITICAL': 15,
        'HIGH': 8,
        'MEDIUM': 3,
        'LOW': 1
    }
    
    # Multipliers for specific issue types (extra dangerous)
    ISSUE_MULTIPLIERS = {
        'Hardcoded secret': 1.5,        # Secrets are extra bad
        'Container running as root': 1.3,
        'Container running in privileged mode': 1.3,
        'Pod using host network': 1.2,
    }
    
    def calculate_pod_score(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate security score for a single pod
        
        Args:
            findings: List of findings for the pod
            
        Returns:
            Dictionary with score details
        """
        if not findings:
            return {
                'score': 100,
                'grade': 'A+',
                'total_deductions': 0,
                'findings_count': 0,
                'risk_level': 'MINIMAL'
            }
        
        # Count findings by severity
        severity_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0
        }
        
        total_deductions = 0
        
        for finding in findings:
            severity = finding.get('severity', 'LOW')
            issue = finding.get('issue', '')
            
            # Base deduction
            deduction = self.SEVERITY_WEIGHTS.get(severity, 1)
            
            # Apply multiplier if issue type is extra dangerous
            multiplier = 1.0
            for issue_type, mult in self.ISSUE_MULTIPLIERS.items():
                if issue_type.lower() in issue.lower():
                    multiplier = mult
                    break
            
            total_deductions += deduction * multiplier
            severity_counts[severity] += 1
        
        # Calculate score (max deduction cap at 100)
        score = max(0, 100 - int(total_deductions))
        
        # Determine grade
        grade = self._score_to_grade(score)
        
        # Determine risk level
        risk_level = self._determine_risk_level(severity_counts)
        
        return {
            'score': score,
            'grade': grade,
            'total_deductions': int(total_deductions),
            'findings_count': len(findings),
            'severity_breakdown': severity_counts,
            'risk_level': risk_level
        }
    
    def calculate_namespace_score(
        self, 
        pod_scores: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Calculate aggregate score for a namespace
        
        Args:
            pod_scores: List of pod score dictionaries
            
        Returns:
            Namespace score summary
        """
        if not pod_scores:
            return {
                'average_score': 100,
                'grade': 'A+',
                'total_pods': 0,
                'pods_at_risk': 0
            }
        
        # Calculate average score
        total_score = sum(ps['score'] for ps in pod_scores)
        avg_score = total_score / len(pod_scores)
        
        # Count pods at risk (score < 70)
        pods_at_risk = sum(1 for ps in pod_scores if ps['score'] < 70)
        
        # Count critical pods (score < 40)
        critical_pods = sum(1 for ps in pod_scores if ps['score'] < 40)
        
        return {
            'average_score': round(avg_score, 1),
            'grade': self._score_to_grade(avg_score),
            'total_pods': len(pod_scores),
            'pods_at_risk': pods_at_risk,
            'critical_pods': critical_pods,
            'best_score': max(ps['score'] for ps in pod_scores),
            'worst_score': min(ps['score'] for ps in pod_scores)
        }
    
    def _score_to_grade(self, score: float) -> str:
        """Convert numeric score to letter grade"""
        if score >= 95:
            return 'A+'
        elif score >= 90:
            return 'A'
        elif score >= 85:
            return 'A-'
        elif score >= 80:
            return 'B+'
        elif score >= 75:
            return 'B'
        elif score >= 70:
            return 'B-'
        elif score >= 65:
            return 'C+'
        elif score >= 60:
            return 'C'
        elif score >= 55:
            return 'C-'
        elif score >= 50:
            return 'D'
        else:
            return 'F'
    
    def _determine_risk_level(self, severity_counts: Dict[str, int]) -> str:
        """
        Determine overall risk level based on severity distribution
        
        Args:
            severity_counts: Count of findings by severity
            
        Returns:
            Risk level string
        """
        if severity_counts['CRITICAL'] >= 3:
            return 'CRITICAL'
        elif severity_counts['CRITICAL'] >= 1 or severity_counts['HIGH'] >= 5:
            return 'HIGH'
        elif severity_counts['HIGH'] >= 2 or severity_counts['MEDIUM'] >= 8:
            return 'MODERATE'
        elif severity_counts['MEDIUM'] >= 3 or severity_counts['LOW'] >= 10:
            return 'LOW'
        else:
            return 'MINIMAL'
    
    def get_recommendations(
        self, 
        score: int,
        severity_counts: Dict[str, int]
    ) -> List[str]:
        """
        Get prioritized recommendations based on score
        
        Args:
            score: Security score
            severity_counts: Findings by severity
            
        Returns:
            List of recommendation strings
        """
        recommendations = []
        
        if severity_counts['CRITICAL'] > 0:
            recommendations.append(
                f"🚨 URGENT: Fix {severity_counts['CRITICAL']} CRITICAL "
                f"issue{'s' if severity_counts['CRITICAL'] > 1 else ''} immediately"
            )
        
        if severity_counts['HIGH'] > 0:
            recommendations.append(
                f"⚠️  HIGH Priority: Address {severity_counts['HIGH']} HIGH "
                f"severity issue{'s' if severity_counts['HIGH'] > 1 else ''}"
            )
        
        if score < 50:
            recommendations.append(
                "💥 Pod is extremely vulnerable - consider blocking deployment"
            )
        elif score < 70:
            recommendations.append(
                "⚠️  Pod has significant security issues - remediate before production"
            )
        elif score < 85:
            recommendations.append(
                "📋 Pod meets minimum security - improvements recommended"
            )
        else:
            recommendations.append(
                "✅ Pod has good security posture - minor improvements possible"
            )
        
        return recommendations
