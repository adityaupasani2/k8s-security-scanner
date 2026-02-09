"""
Base Scanner Class
All security scanners inherit from this
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any


class BaseScanner(ABC):
    """
    Abstract base class for all security scanners
    """
    
    def __init__(self):
        self.name = self.__class__.__name__
        self.findings = []
    
    @abstractmethod
    def scan(self, pod) -> List[Dict[str, Any]]:
        """
        Scan a pod for security issues
        
        Args:
            pod: Kubernetes pod object
            
        Returns:
            List of findings (dictionaries with issue details)
        """
        pass
    
    def create_finding(
        self,
        severity: str,
        pod_name: str,
        namespace: str,
        container_name: str,
        issue: str,
        description: str,
        remediation: str,
        compliance: List[str] = None
    ) -> Dict[str, Any]:
        """
        Create a standardized finding dictionary
        
        Args:
            severity: CRITICAL, HIGH, MEDIUM, or LOW
            pod_name: Name of the pod
            namespace: Namespace of the pod
            container_name: Name of the container
            issue: Short issue title
            description: Detailed description
            remediation: How to fix it
            compliance: Compliance frameworks (CIS, PCI-DSS, etc.)
            
        Returns:
            Dictionary with finding details
        """
        return {
            'scanner': self.name,
            'severity': severity,
            'pod_name': pod_name,
            'namespace': namespace,
            'container_name': container_name,
            'issue': issue,
            'description': description,
            'remediation': remediation,
            'compliance': compliance or [],
            'category': self._get_category()
        }
    
    def _get_category(self) -> str:
        """
        Get the category of this scanner
        Override in subclasses if needed
        """
        return "security"
    
    def get_findings(self) -> List[Dict[str, Any]]:
        """
        Get all findings from this scanner
        """
        return self.findings
    
    def clear_findings(self):
        """
        Clear all findings
        """
        self.findings = []
