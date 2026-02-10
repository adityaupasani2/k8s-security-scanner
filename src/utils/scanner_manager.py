"""
Scanner Manager
Coordinates running multiple scanners
"""

from typing import List, Dict, Any
from src.scanners import (
    RootUserScanner,
    PrivilegedScanner,
    PrivilegeEscalationScanner,
    ReadOnlyFilesystemScanner,
)
from src.scanners.cpu_limits_scanner import CPULimitsScanner
from src.scanners.memory_limits_scanner import MemoryLimitsScanner
from src.scanners.resource_requests_scanner import ResourceRequestsScanner
from src.scanners.latest_tag_scanner import LatestTagScanner
from src.scanners.untagged_image_scanner import UntaggedImageScanner
from src.scanners.image_registry_scanner import ImageRegistryScanner


class ScannerManager:
    """
    Manages and runs all security scanners
    """
    
    def __init__(self):
        # Initialize all scanners
        self.scanners = [
            # Pod Security (Day 2)
            RootUserScanner(),
            PrivilegedScanner(),
            PrivilegeEscalationScanner(),
            ReadOnlyFilesystemScanner(),
            
            # Resource Management (Day 3)
            CPULimitsScanner(),
            MemoryLimitsScanner(),
            ResourceRequestsScanner(),
            
            # Image Security (Day 3)
            LatestTagScanner(),
            UntaggedImageScanner(),
            ImageRegistryScanner(),
        ]
    
    def scan_pod(self, pod) -> List[Dict[str, Any]]:
        """
        Run all scanners on a single pod
        
        Args:
            pod: Kubernetes pod object
            
        Returns:
            List of all findings from all scanners
        """
        all_findings = []
        
        for scanner in self.scanners:
            findings = scanner.scan(pod)
            all_findings.extend(findings)
        
        return all_findings
    
    def scan_pods(self, pods) -> Dict[str, Any]:
        """
        Run all scanners on multiple pods
        
        Args:
            pods: List of Kubernetes pod objects
            
        Returns:
            Dictionary with findings organized by severity
        """
        all_findings = []
        
        for pod in pods:
            findings = self.scan_pod(pod)
            all_findings.extend(findings)
        
        # Organize findings by severity
        findings_by_severity = {
            'CRITICAL': [],
            'HIGH': [],
            'MEDIUM': [],
            'LOW': []
        }
        
        for finding in all_findings:
            severity = finding.get('severity', 'LOW')
            if severity in findings_by_severity:
                findings_by_severity[severity].append(finding)
        
        return {
            'total_findings': len(all_findings),
            'findings_by_severity': findings_by_severity,
            'all_findings': all_findings
        }
    
    def get_scanner_count(self) -> int:
        """Get number of active scanners"""
        return len(self.scanners)
    
    def get_scanner_names(self) -> List[str]:
        """Get list of scanner names"""
        return [scanner.__class__.__name__ for scanner in self.scanners]
