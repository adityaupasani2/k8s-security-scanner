"""
Privilege Escalation Scanner
Detects containers that allow privilege escalation
"""

from typing import List, Dict, Any
from .base_scanner import BaseScanner


class PrivilegeEscalationScanner(BaseScanner):
    """
    Scans for containers that allow privilege escalation
    
    allowPrivilegeEscalation controls whether a process can gain 
    more privileges than its parent process.
    """
    
    def scan(self, pod) -> List[Dict[str, Any]]:
        """
        Check if containers allow privilege escalation
        
        Args:
            pod: Kubernetes pod object
            
        Returns:
            List of findings for containers allowing privilege escalation
        """
        findings = []
        
        pod_name = pod.metadata.name
        namespace = pod.metadata.namespace
        
        for container in pod.spec.containers:
            container_name = container.name
            
            # Check security context
            if container.security_context:
                allow_priv_esc = container.security_context.allow_privilege_escalation
                
                # If explicitly set to true OR not set (defaults to true if privileged)
                if allow_priv_esc is True:
                    findings.append(self._create_finding_esc(
                        pod_name, namespace, container_name,
                        "Explicitly allows privilege escalation"
                    ))
                elif allow_priv_esc is None:
                    # Check if container is privileged
                    if container.security_context.privileged:
                        # Privileged containers implicitly allow escalation
                        findings.append(self._create_finding_esc(
                            pod_name, namespace, container_name,
                            "Privileged container (implicitly allows escalation)"
                        ))
                    else:
                        # Not set and not privileged - could be dangerous
                        # In older K8s versions, this defaults to true
                        findings.append(self._create_finding_esc(
                            pod_name, namespace, container_name,
                            "allowPrivilegeEscalation not explicitly set to false"
                        ))
            else:
                # No security context - defaults allow escalation
                findings.append(self._create_finding_esc(
                    pod_name, namespace, container_name,
                    "No security context (defaults allow escalation)"
                ))
        
        return findings
    
    def _create_finding_esc(
        self,
        pod_name: str,
        namespace: str,
        container_name: str,
        reason: str
    ) -> Dict[str, Any]:
        """Create finding for privilege escalation"""
        
        return self.create_finding(
            severity="HIGH",
            pod_name=pod_name,
            namespace=namespace,
            container_name=container_name,
            issue="Privilege escalation allowed",
            description=f"""
Container '{container_name}' in pod '{pod_name}' allows privilege escalation.

Reason: {reason}

When allowPrivilegeEscalation is true (or not set), processes can:
- Gain additional privileges via setuid/setgid binaries
- Use sudo or su to become root
- Escalate capabilities beyond what was granted initially

This violates the principle of least privilege and can be exploited 
by attackers to gain higher permissions.

Best practice: Always set allowPrivilegeEscalation: false unless 
absolutely necessary.
""".strip(),
            remediation="""
Explicitly disable privilege escalation:

securityContext:
  allowPrivilegeEscalation: false  # ✅ Always set this
  runAsNonRoot: true
  capabilities:
    drop:
      - ALL

This prevents processes from gaining more privileges than 
their parent process, even if setuid binaries exist in the container.
""".strip(),
            compliance=[
                "CIS-5.2.5",
                "PCI-DSS-2.2.4",
                "NIST-800-190"
            ]
        )
    
    def _get_category(self) -> str:
        return "pod_security"
