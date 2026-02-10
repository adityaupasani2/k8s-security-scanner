"""
Default Service Account Scanner
Detects pods using default service account
"""

from typing import List, Dict, Any
from .base_scanner import BaseScanner


class DefaultServiceAccountScanner(BaseScanner):
    """
    Scans for pods using default service account
    
    Default service accounts have unnecessary permissions
    and should not be used.
    """
    
    def scan(self, pod) -> List[Dict[str, Any]]:
        """
        Check if pods use default service account
        
        Args:
            pod: Kubernetes pod object
            
        Returns:
            List of findings for default service account usage
        """
        findings = []
        
        pod_name = pod.metadata.name
        namespace = pod.metadata.namespace
        
        # Check service account name
        service_account = pod.spec.service_account_name or pod.spec.service_account
        
        # If not specified, it defaults to "default"
        if not service_account or service_account == "default":
            findings.append(self._create_sa_finding(
                pod_name, namespace, service_account or "default"
            ))
        
        return findings
    
    def _create_sa_finding(
        self,
        pod_name: str,
        namespace: str,
        service_account: str
    ) -> Dict[str, Any]:
        """Create finding for default service account usage"""
        
        return self.create_finding(
            severity="MEDIUM",
            pod_name=pod_name,
            namespace=namespace,
            container_name="<all>",
            issue="Using default service account",
            description=f"""
Pod '{pod_name}' is using the default service account.

Service account: {service_account}

Problems with default service account:
- Has unnecessary API permissions
- Shared across many pods (blast radius)
- Cannot track which pod made API calls
- Violates least privilege principle
- Makes RBAC audit difficult

Every pod gets a service account token mounted at:
/var/run/secrets/kubernetes.io/serviceaccount/token

With default service account, this token can:
- List resources in the namespace
- Potentially escalate privileges
- Make API calls you didn't intend

Best practice: Create dedicated service accounts for each application.
""".strip(),
            remediation="""
Create and use a dedicated service account:

Step 1: Create ServiceAccount
apiVersion: v1
kind: ServiceAccount
metadata:
  name: myapp-sa
  namespace: default

Step 2: Create Role (minimal permissions)
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: myapp-role
  namespace: default
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list"]

Step 3: Create RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: myapp-binding
  namespace: default
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: myapp-role
subjects:
- kind: ServiceAccount
  name: myapp-sa
  namespace: default

Step 4: Use in Pod
spec:
  serviceAccountName: myapp-sa  # ✅ Use dedicated SA
  containers:
  - name: myapp
    ...

If your app doesn't need Kubernetes API access at all:
spec:
  automountServiceAccountToken: false  # Don't mount token
  containers:
  - name: myapp
    ...
""".strip(),
            compliance=[
                "CIS-5.1.5",
                "RBAC Best Practices"
            ]
        )
    
    def _get_category(self) -> str:
        return "rbac"
