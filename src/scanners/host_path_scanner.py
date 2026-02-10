"""
Host Path Volumes Scanner
Detects containers mounting host filesystem
"""

from typing import List, Dict, Any
from .base_scanner import BaseScanner


class HostPathScanner(BaseScanner):
    """
    Scans for host path volume mounts
    
    hostPath volumes are dangerous because:
    - Direct access to host filesystem
    - Can read/modify node files
    - Container escape vector
    - Data persistence issues
    """
    
    def scan(self, pod) -> List[Dict[str, Any]]:
        """
        Check if pods use hostPath volumes
        
        Args:
            pod: Kubernetes pod object
            
        Returns:
            List of findings for hostPath usage
        """
        findings = []
        
        pod_name = pod.metadata.name
        namespace = pod.metadata.namespace
        
        if pod.spec.volumes:
            for volume in pod.spec.volumes:
                if volume.host_path:
                    # Find which containers use this volume
                    containers_using = []
                    for container in pod.spec.containers:
                        if container.volume_mounts:
                            for mount in container.volume_mounts:
                                if mount.name == volume.name:
                                    containers_using.append(container.name)
                    
                    findings.append(self._create_hostpath_finding(
                        pod_name, namespace, volume.name,
                        volume.host_path.path,
                        containers_using
                    ))
        
        return findings
    
    def _create_hostpath_finding(
        self,
        pod_name: str,
        namespace: str,
        volume_name: str,
        host_path: str,
        containers: List[str]
    ) -> Dict[str, Any]:
        """Create finding for hostPath volume"""
        
        containers_str = ", ".join(containers) if containers else "none"
        
        return self.create_finding(
            severity="HIGH",
            pod_name=pod_name,
            namespace=namespace,
            container_name=containers_str,
            issue=f"Using hostPath volume: {host_path}",
            description=f"""
Pod '{pod_name}' mounts host filesystem using hostPath volume.

Volume name: {volume_name}
Host path: {host_path}
Used by containers: {containers_str}

hostPath volumes are HIGH security risks:
- Direct access to node's filesystem
- Can read sensitive files (/etc/shadow, kubelet certs, etc.)
- Can modify node configuration
- Container escape vector
- Bypasses pod isolation
- Data can persist after pod deletion
- No quotas or limits
- Not portable across nodes

Common attack scenarios:
1. Read node's /etc/shadow → crack passwords
2. Read /var/lib/kubelet/config.yaml → steal credentials
3. Modify /etc/systemd → persist malware
4. Access Docker socket → escape container

hostPath should ONLY be used for:
- DaemonSets that manage nodes
- Log collection agents
- Monitoring agents that need node metrics
""".strip(),
            remediation=f"""
Replace hostPath with safer alternatives:

# BEFORE (Bad):
volumes:
- name: {volume_name}
  hostPath:
    path: {host_path}      # ❌ Direct host access

# AFTER - Option 1: Use emptyDir (temporary storage)
volumes:
- name: {volume_name}
  emptyDir: {{}}            # ✅ Temporary pod storage

# AFTER - Option 2: Use PersistentVolumeClaim
volumes:
- name: {volume_name}
  persistentVolumeClaim:   # ✅ Managed storage
    claimName: my-pvc

# AFTER - Option 3: Use ConfigMap/Secret
volumes:
- name: {volume_name}
  configMap:               # ✅ Configuration data
    name: my-config

Safer storage options:
1. emptyDir - Temporary storage, cleaned on pod delete
2. PersistentVolume - Managed, portable storage
3. ConfigMap - Configuration data
4. Secret - Sensitive data
5. CSI volumes - Cloud provider storage

Valid use cases for hostPath:
- Reading node logs (/var/log)
- Accessing Docker socket (monitoring only)
- Node metrics collection
- DaemonSets managing node resources

For 99% of applications: Use PersistentVolumes!

If you MUST use hostPath:
- Make volume mount readOnly: true
- Use specific subdirectories, not /
- Document why it's necessary
- Use Pod Security Policies to restrict
""".strip(),
            compliance=[
                "CIS-5.2.3",
                "Container Isolation",
                "Data Security Best Practices"
            ]
        )
    
    def _get_category(self) -> str:
        return "host_access"
