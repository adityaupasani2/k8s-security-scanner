"""
Automount Service Account Token Scanner
Detects pods with automounted service account tokens
"""

from typing import List, Dict, Any
from .base_scanner import BaseScanner


class AutomountTokenScanner(BaseScanner):
    """
    Scans for pods that automount service account tokens
    when they don't need Kubernetes API access
    """
    
    def scan(self, pod) -> List[Dict[str, Any]]:
        """
        Check if pods automount service account tokens unnecessarily
        
        Args:
            pod: Kubernetes pod object
            
        Returns:
            List of findings for automounted tokens
        """
        findings = []
        
        pod_name = pod.metadata.name
        namespace = pod.metadata.namespace
        
        # Check if automountServiceAccountToken is explicitly set to false
        automount = pod.spec.automount_service_account_token
        
        # If not explicitly set to false, it defaults to true
        if automount is None or automount is True:
            findings.append(self._create_automount_finding(
                pod_name, namespace
            ))
        
        return findings
    
    def _create_automount_finding(
        self,
        pod_name: str,
        namespace: str
    ) -> Dict[str, Any]:
        """Create finding for automounted token"""
        
        return self.create_finding(
            severity="MEDIUM",
            pod_name=pod_name,
            namespace=namespace,
            container_name="<all>",
            issue="Service account token automounted",
            description=f"""
Pod '{pod_name}' automatically mounts the service account token.

The token is mounted at:
/var/run/secrets/kubernetes.io/serviceaccount/token

This token allows making API calls to Kubernetes.

If your application doesn't need Kubernetes API access:
- The token is unnecessary
- Increases attack surface
- If compromised, attacker can use it
- Violates least privilege

Questions to ask:
- Does my app call kubectl?
- Does my app use Kubernetes API?
- Does my app need to list/create resources?

If answer is NO to all: Disable automounting!
""".strip(),
            remediation="""
Disable automounting if not needed:

# If app doesn't use Kubernetes API:
spec:
  automountServiceAccountToken: false  # ✅ Disable mounting
  containers:
  - name: myapp
    ...

# If app DOES need Kubernetes API:
spec:
  serviceAccountName: myapp-sa        # Use dedicated SA
  automountServiceAccountToken: true  # Explicitly enable
  containers:
  - name: myapp
    ...

Default behavior:
- automountServiceAccountToken defaults to true
- Token is mounted in every container
- Even if you don't use it!

Security guideline:
1. Most apps DON'T need Kubernetes API access
2. Disable automounting for those apps
3. Only enable for apps that need it
4. Use dedicated service accounts (not default)
""".strip(),
            compliance=[
                "CIS-5.1.6",
                "Least Privilege"
            ]
        )
    
    def _get_category(self) -> str:
        return "rbac"
