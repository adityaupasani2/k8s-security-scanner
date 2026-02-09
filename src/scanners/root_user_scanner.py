"""
Root User Scanner
Detects containers running as root (UID 0)
"""

from typing import List, Dict, Any
from .base_scanner import BaseScanner


class RootUserScanner(BaseScanner):
    """
    Scans for containers running as root user
    
    Running as root is dangerous because:
    - If container is compromised, attacker has root privileges
    - Can modify system files inside container
    - Increases attack surface for container escape
    """
    
    def scan(self, pod) -> List[Dict[str, Any]]:
        """
        Check if any containers are running as root
        
        Args:
            pod: Kubernetes pod object
            
        Returns:
            List of findings for containers running as root
        """
        findings = []
        
        pod_name = pod.metadata.name
        namespace = pod.metadata.namespace
        
        # Check each container in the pod
        for container in pod.spec.containers:
            container_name = container.name
            
            # Check security context
            if container.security_context:
                run_as_user = container.security_context.run_as_user
                run_as_non_root = container.security_context.run_as_non_root
                
                # If explicitly set to root (UID 0)
                if run_as_user == 0:
                    findings.append(self._create_root_finding(
                        pod_name, namespace, container_name, 
                        "Explicitly running as root (runAsUser: 0)"
                    ))
                
                # If runAsNonRoot is not set or is False
                elif run_as_non_root is None or run_as_non_root is False:
                    # Check pod-level security context
                    pod_run_as_user = None
                    if pod.spec.security_context:
                        pod_run_as_user = pod.spec.security_context.run_as_user
                    
                    # If pod level also allows root
                    if pod_run_as_user is None or pod_run_as_user == 0:
                        findings.append(self._create_root_finding(
                            pod_name, namespace, container_name,
                            "Not enforcing non-root user (runAsNonRoot not set)"
                        ))
            else:
                # No security context at all - defaults to root
                findings.append(self._create_root_finding(
                    pod_name, namespace, container_name,
                    "No security context defined (defaults to root)"
                ))
        
        return findings
    
    def _create_root_finding(
        self, 
        pod_name: str, 
        namespace: str, 
        container_name: str,
        reason: str
    ) -> Dict[str, Any]:
        """Create a finding for root user issue"""
        
        return self.create_finding(
            severity="CRITICAL",
            pod_name=pod_name,
            namespace=namespace,
            container_name=container_name,
            issue=f"Container running as root user",
            description=f"""
Container '{container_name}' in pod '{pod_name}' is running as root (UID 0).

Reason: {reason}

This is a critical security risk because:
- If the container is compromised, attackers gain root privileges
- Root can modify system files and configurations
- Increases the risk of container escape attacks
- Violates the principle of least privilege

Best practice: Always run containers as non-root users.
""".strip(),
            remediation="""
Add security context to your pod spec:

spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000      # Use a non-root UID
    runAsGroup: 3000
    fsGroup: 2000
  containers:
  - name: your-container
    securityContext:
      allowPrivilegeEscalation: false
      runAsNonRoot: true
      runAsUser: 1000

If your application requires specific permissions, use capabilities 
instead of running as root.
""".strip(),
            compliance=[
                "CIS-5.2.6",      # CIS Kubernetes Benchmark
                "PCI-DSS-2.2.5",  # PCI DSS
                "NIST-800-190"    # NIST Container Security
            ]
        )
    
    def _get_category(self) -> str:
        return "pod_security"
