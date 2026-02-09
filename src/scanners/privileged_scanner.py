"""
Privileged Container Scanner
Detects containers running in privileged mode
"""

from typing import List, Dict, Any
from .base_scanner import BaseScanner


class PrivilegedScanner(BaseScanner):
    """
    Scans for containers running in privileged mode
    
    Privileged mode is extremely dangerous because:
    - Container has ALL Linux capabilities
    - Can access ALL host devices
    - Can modify kernel parameters
    - Easy container escape to host
    """
    
    def scan(self, pod) -> List[Dict[str, Any]]:
        """
        Check if any containers are privileged
        
        Args:
            pod: Kubernetes pod object
            
        Returns:
            List of findings for privileged containers
        """
        findings = []
        
        pod_name = pod.metadata.name
        namespace = pod.metadata.namespace
        
        # Check each container
        for container in pod.spec.containers:
            container_name = container.name
            
            # Check if privileged mode is enabled
            if container.security_context and container.security_context.privileged:
                findings.append(self._create_privileged_finding(
                    pod_name, namespace, container_name
                ))
        
        return findings
    
    def _create_privileged_finding(
        self,
        pod_name: str,
        namespace: str,
        container_name: str
    ) -> Dict[str, Any]:
        """Create a finding for privileged container"""
        
        return self.create_finding(
            severity="CRITICAL",
            pod_name=pod_name,
            namespace=namespace,
            container_name=container_name,
            issue="Container running in privileged mode",
            description=f"""
Container '{container_name}' in pod '{pod_name}' is running with privileged: true.

This is EXTREMELY DANGEROUS because privileged containers:
- Have ALL Linux capabilities (CAP_SYS_ADMIN, etc.)
- Can access ALL host devices (/dev/*)
- Can load kernel modules
- Can modify kernel parameters (sysctl)
- Can easily escape to the host system
- Bypass ALL container security boundaries

Privileged mode should ONLY be used for:
- System-level workloads (CNI plugins, storage drivers)
- Containers that truly need host-level access

For most applications, this is unnecessary and creates severe security risks.
""".strip(),
            remediation="""
Remove privileged mode from your container:

# BEFORE (Insecure):
securityContext:
  privileged: true    # ❌ REMOVE THIS

# AFTER (Secure):
securityContext:
  privileged: false   # ✅ Or omit entirely (defaults to false)
  allowPrivilegeEscalation: false
  runAsNonRoot: true
  capabilities:
    drop:
      - ALL
    add:
      - NET_BIND_SERVICE  # Only add specific capabilities you need

If you need specific capabilities, use 'capabilities.add' instead 
of privileged mode. For example:
- NET_ADMIN for network configuration
- SYS_TIME for clock adjustments
- NET_BIND_SERVICE for binding to ports < 1024
""".strip(),
            compliance=[
                "CIS-5.2.1",      # Minimize privileged containers
                "PCI-DSS-2.2",    # Security configurations
                "NIST-800-190"    # Container security
            ]
        )
    
    def _get_category(self) -> str:
        return "pod_security"
