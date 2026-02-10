"""
Resource Requests Scanner
Detects containers without resource requests
"""

from typing import List, Dict, Any
from .base_scanner import BaseScanner


class ResourceRequestsScanner(BaseScanner):
    """
    Scans for containers without resource requests
    
    Missing requests cause:
    - Poor scheduling decisions
    - Oversubscribed nodes
    - Performance issues
    """
    
    def scan(self, pod) -> List[Dict[str, Any]]:
        """
        Check if containers have resource requests
        
        Args:
            pod: Kubernetes pod object
            
        Returns:
            List of findings for containers without requests
        """
        findings = []
        
        pod_name = pod.metadata.name
        namespace = pod.metadata.namespace
        
        for container in pod.spec.containers:
            container_name = container.name
            
            missing_requests = []
            
            if container.resources:
                if container.resources.requests:
                    # Check individual requests
                    if container.resources.requests.get('cpu') is None:
                        missing_requests.append('cpu')
                    if container.resources.requests.get('memory') is None:
                        missing_requests.append('memory')
                else:
                    # No requests section
                    missing_requests = ['cpu', 'memory']
            else:
                # No resources section
                missing_requests = ['cpu', 'memory']
            
            if missing_requests:
                findings.append(self._create_requests_finding(
                    pod_name, namespace, container_name, missing_requests
                ))
        
        return findings
    
    def _create_requests_finding(
        self,
        pod_name: str,
        namespace: str,
        container_name: str,
        missing: List[str]
    ) -> Dict[str, Any]:
        """Create finding for missing resource requests"""
        
        missing_str = " and ".join(missing)
        
        return self.create_finding(
            severity="MEDIUM",
            pod_name=pod_name,
            namespace=namespace,
            container_name=container_name,
            issue=f"Missing resource requests: {missing_str}",
            description=f"""
Container '{container_name}' in pod '{pod_name}' is missing resource requests.

Missing: {missing_str}

Resource requests tell the scheduler:
- How much CPU/memory to guarantee
- Which node has enough resources
- How to distribute workloads

Without requests:
- Scheduler makes poor placement decisions
- Nodes can become oversubscribed
- Unpredictable performance
- No resource guarantees
- Pod QoS is BestEffort (lowest priority)

Requests vs Limits:
- REQUESTS: Guaranteed minimum resources
- LIMITS: Maximum allowed resources

Best practice: Always set BOTH requests AND limits.
""".strip(),
            remediation="""
Add resource requests to your container:

resources:
  requests:
    cpu: "500m"       # Guaranteed CPU
    memory: "256Mi"   # Guaranteed memory
  limits:
    cpu: "1000m"      # Max CPU (can burst to this)
    memory: "512Mi"   # Max memory (hard limit)

Guidelines:
- Set requests to typical usage (80-90% percentile)
- Set limits to peak usage + buffer
- Requests should be <= Limits
- Both are required for Guaranteed QoS

Example for a web app:
requests:
  cpu: "250m"
  memory: "256Mi"
limits:
  cpu: "500m"
  memory: "512Mi"
""".strip(),
            compliance=[
                "CIS-5.2.9",
                "Resource Management Best Practices",
                "Kubernetes QoS Classes"
            ]
        )
    
    def _get_category(self) -> str:
        return "resource_management"
