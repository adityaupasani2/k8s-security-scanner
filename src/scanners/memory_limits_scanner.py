"""
Memory Limits Scanner
Detects containers without memory limits
"""

from typing import List, Dict, Any
from .base_scanner import BaseScanner


class MemoryLimitsScanner(BaseScanner):
    """
    Scans for containers without memory limits
    
    Missing memory limits can cause:
    - Out of Memory (OOM) kills
    - Node crashes
    - Cascading failures
    """
    
    def scan(self, pod) -> List[Dict[str, Any]]:
        """
        Check if containers have memory limits
        
        Args:
            pod: Kubernetes pod object
            
        Returns:
            List of findings for containers without memory limits
        """
        findings = []
        
        pod_name = pod.metadata.name
        namespace = pod.metadata.namespace
        
        for container in pod.spec.containers:
            container_name = container.name
            
            if container.resources:
                if container.resources.limits:
                    memory_limit = container.resources.limits.get('memory')
                    
                    if memory_limit is None:
                        findings.append(self._create_memory_finding(
                            pod_name, namespace, container_name,
                            "Memory limit not defined"
                        ))
                else:
                    findings.append(self._create_memory_finding(
                        pod_name, namespace, container_name,
                        "No resource limits section"
                    ))
            else:
                findings.append(self._create_memory_finding(
                    pod_name, namespace, container_name,
                    "No resources defined"
                ))
        
        return findings
    
    def _create_memory_finding(
        self,
        pod_name: str,
        namespace: str,
        container_name: str,
        reason: str
    ) -> Dict[str, Any]:
        """Create finding for missing memory limit"""
        
        return self.create_finding(
            severity="HIGH",
            pod_name=pod_name,
            namespace=namespace,
            container_name=container_name,
            issue="Missing memory limit",
            description=f"""
Container '{container_name}' in pod '{pod_name}' has no memory limit defined.

Reason: {reason}

Without memory limits:
- Container can consume all node memory
- Triggers Out of Memory (OOM) killer
- Can crash the entire node
- Causes cascading pod evictions
- Makes capacity planning impossible

Memory limits are CRITICAL for cluster stability.
A single memory leak can bring down an entire node.
""".strip(),
            remediation="""
Add memory limits to your container:

resources:
  limits:
    memory: "512Mi"     # 512 Mebibytes
    # OR
    memory: "1Gi"       # 1 Gibibyte
    # OR
    memory: "2Gi"       # 2 Gibibytes
  requests:
    memory: "256Mi"     # Guaranteed memory allocation

Common values:
- Small workloads: 128Mi - 512Mi
- Medium workloads: 512Mi - 2Gi
- Large workloads: 2Gi - 8Gi

Important:
- Use Mi (Mebibytes) or Gi (Gibibytes), not MB/GB
- Set limits based on actual usage + 20-30% buffer
- Memory limits are HARD limits (OOM kill if exceeded)
- Unlike CPU, memory cannot be throttled
""".strip(),
            compliance=[
                "CIS-5.2.8",
                "PCI-DSS-2.2",
                "Resource Management Best Practices"
            ]
        )
    
    def _get_category(self) -> str:
        return "resource_management"
