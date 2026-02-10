"""
Missing Security Context Scanner
Detects containers without security context defined
"""

from typing import List, Dict, Any
from .base_scanner import BaseScanner


class MissingSecurityContextScanner(BaseScanner):
    """
    Scans for containers without security context
    
    Security context is essential for defining security constraints.
    """
    
    def scan(self, pod) -> List[Dict[str, Any]]:
        """
        Check if containers have security context
        
        Args:
            pod: Kubernetes pod object
            
        Returns:
            List of findings for missing security context
        """
        findings = []
        
        pod_name = pod.metadata.name
        namespace = pod.metadata.namespace
        
        for container in pod.spec.containers:
            container_name = container.name
            
            # Check if security context is defined
            if not container.security_context:
                findings.append(self._create_missing_sc_finding(
                    pod_name, namespace, container_name
                ))
        
        return findings
    
    def _create_missing_sc_finding(
        self,
        pod_name: str,
        namespace: str,
        container_name: str
    ) -> Dict[str, Any]:
        """Create finding for missing security context"""
        
        return self.create_finding(
            severity="MEDIUM",
            pod_name=pod_name,
            namespace=namespace,
            container_name=container_name,
            issue="No security context defined",
            description=f"""
Container '{container_name}' in pod '{pod_name}' has no security context.

Without security context, you cannot control:
- User/group IDs (may run as root)
- Privilege escalation
- Capabilities
- SELinux/AppArmor profiles
- Read-only root filesystem
- Seccomp profiles

This means the container uses default settings which are often insecure.

Best practice: Always define security context explicitly.
""".strip(),
            remediation="""
Add a security context to your container:

containers:
- name: myapp
  image: myapp:1.0
  securityContext:           # ✅ Always define this
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 3000
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    capabilities:
      drop:
        - ALL

Minimum security context (baseline):
securityContext:
  runAsNonRoot: true
  allowPrivilegeEscalation: false
  capabilities:
    drop:
      - ALL

Recommended security context (hardened):
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL
  seccompProfile:
    type: RuntimeDefault
""".strip(),
            compliance=[
                "CIS-5.2.6",
                "Pod Security Standards"
            ]
        )
    
    def _get_category(self) -> str:
        return "pod_security"
