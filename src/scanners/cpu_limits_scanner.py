"""
CPU Limits Scanner
Detects containers without CPU limits
"""

from typing import List, Dict, Any
from .base_scanner import BaseScanner


class CPULimitsScanner(BaseScanner):
    """
    Scans for containers without CPU limits
    
    Missing CPU limits allows:
    - One container to consume all CPU
    - Noisy neighbor problems
    - Cluster-wide performance degradation
    """
    
    def scan(self, pod) -> List[Dict[str, Any]]:
        """
        Check if containers have CPU limits
        
        Args:
            pod: Kubernetes pod object
            
        Returns:
            List of findings for containers without CPU limits
        """
        findings = []
        
        pod_name = pod.metadata.name
        namespace = pod.metadata.namespace
        
        for container in pod.spec.containers:
            container_name = container.name
            
            # Check if resources are defined
            if container.resources:
                # Check if limits are defined
                if container.resources.limits:
                    cpu_limit = container.resources.limits.get('cpu')
                    
                    if cpu_limit is None:
                        findings.append(self._create_cpu_finding(
                            pod_name, namespace, container_name,
                            "CPU limit not defined"
                        ))
                else:
                    # No limits section at all
                    findings.append(self._create_cpu_finding(
                        pod_name, namespace, container_name,
                        "No resource limits section"
                    ))
            else:
                # No resources section at all
                findings.append(self._create_cpu_finding(
                    pod_name, namespace, container_name,
                    "No resources defined"
                ))
        
        return findings
    
    def _create_cpu_finding(
        self,
        pod_name: str,
        namespace: str,
        container_name: str,
        reason: str
    ) -> Dict[str, Any]:
        """Create finding for missing CPU limit"""
        
        return self.create_finding(
            severity="HIGH",
            pod_name=pod_name,
            namespace=namespace,
            container_name=container_name,
            issue="Missing CPU limit",
            description=f"""
Container '{container_name}' in pod '{pod_name}' has no CPU limit defined.

Reason: {reason}

Without CPU limits:
- Container can consume 100% of node CPU
- Can starve other pods on the same node
- Causes "noisy neighbor" problems
- Makes cluster capacity planning impossible
- Can lead to node instability

CPU limits ensure fair resource distribution and prevent 
one container from impacting others.

Best practice: Always set both CPU requests AND limits.
""".strip(),
            remediation="""
Add CPU limits to your container:

resources:
  limits:
    cpu: "1000m"      # 1 CPU core (1000 millicores)
    # OR
    cpu: "500m"       # 0.5 CPU cores
    # OR  
    cpu: "2"          # 2 CPU cores
  requests:
    cpu: "500m"       # Guaranteed CPU allocation

Common values:
- Small workloads: 100m - 250m
- Medium workloads: 500m - 1000m  
- Large workloads: 2000m - 4000m

Set limits based on actual usage (check metrics first).
Limits should be higher than requests to allow bursting.
""".strip(),
            compliance=[
                "CIS-5.2.7",
                "PCI-DSS-2.2",
                "Resource Management Best Practices"
            ]
        )
    
    def _get_category(self) -> str:
        return "resource_management"
