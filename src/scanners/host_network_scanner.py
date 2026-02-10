"""
Host Network Scanner
Detects pods using host network
"""

from typing import List, Dict, Any
from .base_scanner import BaseScanner


class HostNetworkScanner(BaseScanner):
    """
    Scans for pods using host network
    
    hostNetwork: true is dangerous because:
    - Pod can see ALL network traffic on the node
    - Can intercept traffic from other pods
    - Can bind to privileged ports
    - Breaks network isolation
    """
    
    def scan(self, pod) -> List[Dict[str, Any]]:
        """
        Check if pods use host network
        
        Args:
            pod: Kubernetes pod object
            
        Returns:
            List of findings for host network usage
        """
        findings = []
        
        pod_name = pod.metadata.name
        namespace = pod.metadata.namespace
        
        # Check if hostNetwork is enabled
        if pod.spec.host_network:
            findings.append(self._create_host_network_finding(
                pod_name, namespace
            ))
        
        return findings
    
    def _create_host_network_finding(
        self,
        pod_name: str,
        namespace: str
    ) -> Dict[str, Any]:
        """Create finding for host network usage"""
        
        return self.create_finding(
            severity="HIGH",
            pod_name=pod_name,
            namespace=namespace,
            container_name="<all>",
            issue="Pod using host network",
            description=f"""
Pod '{pod_name}' is using the host network (hostNetwork: true).

This is a HIGH security risk because:
- Pod shares the node's network namespace
- Can see ALL network traffic on the node
- Can intercept traffic from other pods
- Can bind to any port on the node (including privileged ports)
- Breaks Kubernetes network isolation model
- Can perform man-in-the-middle attacks
- Bypasses Network Policies

Host network should ONLY be used for:
- CNI plugins (networking infrastructure)
- Node-level monitoring tools
- System daemons that require host network access

For normal applications, this is almost never needed.
""".strip(),
            remediation="""
Remove hostNetwork from your pod spec:

# BEFORE (Bad):
spec:
  hostNetwork: true    # ❌ REMOVE THIS
  containers:
  - name: myapp
    ...

# AFTER (Good):
spec:
  # hostNetwork removed - uses pod network
  containers:
  - name: myapp
    ports:
    - containerPort: 8080  # Use pod network

If you need specific networking features:
1. Use Services for external access
2. Use NetworkPolicies for isolation
3. Use Ingress for HTTP routing
4. Use specific capabilities if needed

Valid use cases for hostNetwork:
- kube-proxy (needs to configure node networking)
- CNI plugins (calico, flannel, weave)
- Node metrics exporters
- DaemonSets that manage node networking

For 99% of applications: DO NOT use hostNetwork!
""".strip(),
            compliance=[
                "CIS-5.2.4",
                "PCI-DSS-1.2.1",
                "Network Isolation Best Practices"
            ]
        )
    
    def _get_category(self) -> str:
        return "network_security"
