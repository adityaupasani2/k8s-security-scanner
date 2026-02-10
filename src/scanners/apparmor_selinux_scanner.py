"""
AppArmor/SELinux Scanner
Detects containers without MAC (Mandatory Access Control) profiles
"""

from typing import List, Dict, Any
from .base_scanner import BaseScanner


class AppArmorSELinuxScanner(BaseScanner):
    """
    Scans for missing AppArmor or SELinux profiles
    
    MAC provides additional security layer beyond standard permissions.
    """
    
    def scan(self, pod) -> List[Dict[str, Any]]:
        """
        Check if containers use AppArmor or SELinux
        
        Args:
            pod: Kubernetes pod object
            
        Returns:
            List of findings for missing MAC profiles
        """
        findings = []
        
        pod_name = pod.metadata.name
        namespace = pod.metadata.namespace
        
        for container in pod.spec.containers:
            container_name = container.name
            
            has_apparmor = False
            has_selinux = False
            
            # Check for AppArmor annotation
            if pod.metadata.annotations:
                apparmor_key = f"container.apparmor.security.beta.kubernetes.io/{container_name}"
                if apparmor_key in pod.metadata.annotations:
                    has_apparmor = True
            
            # Check for SELinux context
            if container.security_context and container.security_context.se_linux_options:
                has_selinux = True
            
            # If neither is set, create finding
            if not has_apparmor and not has_selinux:
                findings.append(self._create_mac_finding(
                    pod_name, namespace, container_name
                ))
        
        return findings
    
    def _create_mac_finding(
        self,
        pod_name: str,
        namespace: str,
        container_name: str
    ) -> Dict[str, Any]:
        """Create finding for missing MAC profile"""
        
        return self.create_finding(
            severity="LOW",
            pod_name=pod_name,
            namespace=namespace,
            container_name=container_name,
            issue="No AppArmor or SELinux profile",
            description=f"""
Container '{container_name}' in pod '{pod_name}' has no MAC profile.

MAC (Mandatory Access Control) provides an extra security layer:
- AppArmor (common on Ubuntu/Debian)
- SELinux (common on RHEL/CentOS)

Benefits of MAC:
- Limits what processes can do
- Restricts file access
- Controls network access
- Defense-in-depth

Without MAC:
- Relying only on standard permissions
- Missing security layer
- Less protection if container is compromised

Note: This is LOW severity because MAC is defense-in-depth,
not the primary security control.
""".strip(),
            remediation="""
Add AppArmor or SELinux profile:

Option 1: AppArmor (Ubuntu/Debian)
metadata:
  annotations:
    container.apparmor.security.beta.kubernetes.io/myapp: runtime/default

Option 2: SELinux (RHEL/CentOS)
containers:
- name: myapp
  securityContext:
    seLinuxOptions:
      level: "s0:c123,c456"
      role: "system_r"
      type: "container_t"
      user: "system_u"

Recommended approach:
1. Start with default profiles (runtime/default)
2. Test your application
3. Create custom profiles if needed
4. Use Pod Security Standards for enforcement

Note: Check your cluster's OS:
- Ubuntu/Debian → Use AppArmor
- RHEL/CentOS/Fedora → Use SELinux
- Other → May support both or neither
""".strip(),
            compliance=[
                "CIS-5.7.2",
                "Defense-in-Depth"
            ]
        )
    
    def _get_category(self) -> str:
        return "pod_security"
