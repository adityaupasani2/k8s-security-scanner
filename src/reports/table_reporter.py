"""
Table Reporter
Generates formatted terminal output with tables
"""

from typing import List, Dict, Any
from tabulate import tabulate
from colorama import Fore, Style


class TableReporter:
    """
    Generates formatted table reports for terminal
    """
    
    def __init__(self, findings: List[Dict[str, Any]]):
        """
        Initialize reporter with findings
        
        Args:
            findings: List of all findings
        """
        self.findings = findings
        self.severity_colors = {
            'CRITICAL': Fore.RED,
            'HIGH': Fore.YELLOW,
            'MEDIUM': Fore.BLUE,
            'LOW': Fore.WHITE
        }
    
    def generate_summary_table(self) -> str:
        """
        Generate summary statistics table
        
        Returns:
            Formatted table string
        """
        # Count by severity
        severity_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0
        }
        
        # Count by category
        category_counts = {}
        
        for finding in self.findings:
            severity = finding.get('severity', 'LOW')
            category = finding.get('category', 'unknown')
            
            severity_counts[severity] += 1
            category_counts[category] = category_counts.get(category, 0) + 1
        
        # Create severity table
        severity_data = []
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = severity_counts[severity]
            color = self.severity_colors[severity]
            
            # Add visual bar
            bar_length = min(count, 20)
            bar = '█' * bar_length
            
            severity_data.append([
                f"{color}{severity}{Style.RESET_ALL}",
                count,
                f"{color}{bar}{Style.RESET_ALL}"
            ])
        
        severity_table = tabulate(
            severity_data,
            headers=['Severity', 'Count', 'Distribution'],
            tablefmt='grid'
        )
        
        # Create category table
        category_data = []
        for category, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True):
            category_name = category.replace('_', ' ').title()
            category_data.append([category_name, count])
        
        category_table = tabulate(
            category_data,
            headers=['Category', 'Findings'],
            tablefmt='grid'
        )
        
        return f"\n{Fore.CYAN}Findings by Severity:{Style.RESET_ALL}\n{severity_table}\n\n{Fore.CYAN}Findings by Category:{Style.RESET_ALL}\n{category_table}"
    
    def generate_findings_table(self, max_rows: int = 20) -> str:
        """
        Generate detailed findings table
        
        Args:
            max_rows: Maximum rows to display
            
        Returns:
            Formatted table string
        """
        if not self.findings:
            return f"{Fore.GREEN}No security issues found! ✓{Style.RESET_ALL}"
        
        # Sort by severity (CRITICAL first)
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        sorted_findings = sorted(
            self.findings,
            key=lambda x: severity_order.get(x.get('severity', 'LOW'), 4)
        )
        
        # Limit rows
        display_findings = sorted_findings[:max_rows]
        
        # Create table data
        table_data = []
        for i, finding in enumerate(display_findings, 1):
            severity = finding.get('severity', 'LOW')
            color = self.severity_colors[severity]
            
            # Truncate long issues
            issue = finding.get('issue', 'Unknown')
            if len(issue) > 50:
                issue = issue[:47] + '...'
            
            pod = finding.get('pod_name', 'Unknown')
            container = finding.get('container_name', 'Unknown')
            
            table_data.append([
                i,
                f"{color}{severity}{Style.RESET_ALL}",
                pod,
                container,
                issue
            ])
        
        table = tabulate(
            table_data,
            headers=['#', 'Severity', 'Pod', 'Container', 'Issue'],
            tablefmt='grid'
        )
        
        result = f"\n{Fore.CYAN}Top {len(display_findings)} Findings:{Style.RESET_ALL}\n{table}"
        
        if len(sorted_findings) > max_rows:
            remaining = len(sorted_findings) - max_rows
            result += f"\n\n{Fore.YELLOW}... and {remaining} more issues{Style.RESET_ALL}"
        
        return result
    
    def generate_pod_table(self, pod_scores: List[Dict[str, Any]]) -> str:
        """
        Generate per-pod security scores table
        
        Args:
            pod_scores: List of pod score dictionaries
            
        Returns:
            Formatted table string
        """
        if not pod_scores:
            return ""
        
        # Sort by score (worst first)
        sorted_pods = sorted(pod_scores, key=lambda x: x['score'])
        
        table_data = []
        for pod_data in sorted_pods:
            score = pod_data['score']
            grade = pod_data['grade']
            risk = pod_data['risk_level']
            findings = pod_data['findings_count']
            
            # Color based on score
            if score >= 80:
                color = Fore.GREEN
            elif score >= 60:
                color = Fore.YELLOW
            else:
                color = Fore.RED
            
            # Create score bar
            bar_length = int(score / 5)  # 100 / 5 = 20 chars max
            bar = '█' * bar_length
            
            table_data.append([
                pod_data['name'],
                f"{color}{score}/100{Style.RESET_ALL}",
                f"{color}{grade}{Style.RESET_ALL}",
                risk,
                findings,
                f"{color}{bar}{Style.RESET_ALL}"
            ])
        
        table = tabulate(
            table_data,
            headers=['Pod Name', 'Score', 'Grade', 'Risk', 'Issues', 'Score Visual'],
            tablefmt='grid'
        )
        
        return f"\n{Fore.CYAN}Per-Pod Security Scores:{Style.RESET_ALL}\n{table}"
    
    def generate_compliance_table(self, compliance_data: Dict[str, Any]) -> str:
        """
        Generate compliance framework table
        
        Args:
            compliance_data: Compliance analysis data
            
        Returns:
            Formatted table string
        """
        framework_scores = compliance_data.get('framework_scores', {})
        
        if not framework_scores:
            return ""
        
        table_data = []
        for framework, data in sorted(framework_scores.items()):
            pct = data['compliance_percentage']
            status = data['status']
            violations = data['total_violations']
            
            # Color based on compliance
            if status == 'COMPLIANT':
                color = Fore.GREEN
            elif status == 'MOSTLY_COMPLIANT':
                color = Fore.YELLOW
            else:
                color = Fore.RED
            
            # Create compliance bar
            bar_length = int(pct / 5)  # 100 / 5 = 20 chars max
            bar = '█' * bar_length
            
            # Format status
            status_display = status.replace('_', ' ')
            
            table_data.append([
                framework,
                f"{color}{pct}%{Style.RESET_ALL}",
                f"{color}{status_display}{Style.RESET_ALL}",
                violations,
                f"{color}{bar}{Style.RESET_ALL}"
            ])
        
        table = tabulate(
            table_data,
            headers=['Framework', 'Compliance', 'Status', 'Violations', 'Visual'],
            tablefmt='grid'
        )
        
        return f"\n{Fore.CYAN}Compliance Status:{Style.RESET_ALL}\n{table}"
    
    def save_to_file(self, filename: str, content: str):
        """
        Save report to text file
        
        Args:
            filename: Output filename
            content: Report content
        """
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                # Remove color codes for file output
                import re
                clean_content = re.sub(r'\x1b\[[0-9;]*m', '', content)
                f.write(clean_content)
            return True
        except Exception as e:
            print(f"Error saving file: {e}")
            return False
