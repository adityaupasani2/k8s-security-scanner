"""
Seccomp Scanner
Detects containers without seccomp profiles
"""

from typing import List, Dict, Any
from .base_scanner import BaseScanner


class SeccompScanner(BaseScanner):
    """
    Scans for missing seccomp profiles
    
    Seccomp restricts system calls a container can make.
    """
    
    def scan(self, pod) -> List[Dict[str, Any]]:
        """
        Check if containers have seccomp profiles
        
        Args:
            pod: Kubernetes pod object
            
        Returns:
            List of findings for missing seccomp
        """
        findings = []
        
        pod_name = pod.metadata.name
        namespace = pod.metadata.namespace
        
        for container in pod.spec.containers:
            container_name = container.name
            
            has_seccomp = False
            
            # Check container-level seccomp
            if container.security_context and container.security_context.seccomp_profile:
                has_seccomp = True
            
            # Check pod-level seccomp
            elif pod.spec.security_context and pod.spec.security_context.seccomp_profile:
                has_seccomp = True
            
            if not has_seccomp:
                findings.append(self._create_seccomp_finding(
                    pod_name, namespace, container_name
                ))
        
        return findings
    
    def _create_seccomp_finding(
        self,
        pod_name: str,
        namespace: str,
        container_name: str
    ) -> Dict[str, Any]:
        """Create finding for missing seccomp"""
        
        return self.create_finding(
            severity="LOW",
            pod_name=pod_name,
            namespace=namespace,
            container_name=container_name,
            issue="No seccomp profile defined",
            description=f"""
Container '{container_name}' in pod '{pod_name}' has no seccomp profile.

Seccomp (Secure Computing Mode) restricts system calls.

Without seccomp:
- Container can make any system call
- Larger attack surface
- Kernel exploits easier

With seccomp:
- Only allowed syscalls work
- Blocks dangerous syscalls
- Reduces kernel attack surface

Example blocked syscalls:
- reboot()
- swapon()
- mount()
- ptrace()
- perf_event_open()

Most applications work fine with RuntimeDefault profile.
""".strip(),
            remediation="""
Add seccomp profile:

# Container-level (recommended):
containers:
- name: myapp
  securityContext:
    seccompProfile:
      type: RuntimeDefault  # ✅ Use default profile

# Pod-level (applies to all containers):
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault

# Custom profile (advanced):
securityContext:
  seccompProfile:
    type: Localhost
    localhostProfile: profiles/custom.json

Profile types:
- RuntimeDefault: Use container runtime's default
- Unconfined: No restrictions (insecure)
- Localhost: Custom profile from node

Recommendation:
1. Start with RuntimeDefault
2. Test your application
3. Create custom profile only if needed

99% of apps work with RuntimeDefault!
""".strip(),
            compliance=[
                "CIS-5.7.2",
                "System Call Filtering"
            ]
        )
    
    def _get_category(self) -> str:
        return "pod_security"
