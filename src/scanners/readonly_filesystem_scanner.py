"""
Read-Only Filesystem Scanner
Detects containers without read-only root filesystems
"""

from typing import List, Dict, Any
from .base_scanner import BaseScanner


class ReadOnlyFilesystemScanner(BaseScanner):
    """
    Scans for containers without read-only root filesystems
    
    Read-only filesystems prevent:
    - Attackers from modifying binaries
    - Malware persistence
    - Unauthorized file changes
    """
    
    def scan(self, pod) -> List[Dict[str, Any]]:
        """
        Check if containers have read-only root filesystems
        
        Args:
            pod: Kubernetes pod object
            
        Returns:
            List of findings for writable filesystems
        """
        findings = []
        
        pod_name = pod.metadata.name
        namespace = pod.metadata.namespace
        
        for container in pod.spec.containers:
            container_name = container.name
            
            # Check security context
            if container.security_context:
                read_only_fs = container.security_context.read_only_root_filesystem
                
                # If not set or explicitly False
                if read_only_fs is None or read_only_fs is False:
                    findings.append(self._create_readonly_finding(
                        pod_name, namespace, container_name,
                        read_only_fs is False
                    ))
            else:
                # No security context - defaults to writable
                findings.append(self._create_readonly_finding(
                    pod_name, namespace, container_name,
                    False
                ))
        
        return findings
    
    def _create_readonly_finding(
        self,
        pod_name: str,
        namespace: str,
        container_name: str,
        explicitly_false: bool
    ) -> Dict[str, Any]:
        """Create finding for writable filesystem"""
        
        if explicitly_false:
            reason = "Explicitly set to writable (readOnlyRootFilesystem: false)"
        else:
            reason = "Not configured (defaults to writable)"
        
        return self.create_finding(
            severity="MEDIUM",
            pod_name=pod_name,
            namespace=namespace,
            container_name=container_name,
            issue="Root filesystem is writable",
            description=f"""
Container '{container_name}' in pod '{pod_name}' has a writable root filesystem.

Reason: {reason}

Writable filesystems allow attackers to:
- Modify application binaries and libraries
- Install malware or backdoors
- Create persistence mechanisms
- Tamper with configuration files
- Plant rootkits

Read-only filesystems provide defense-in-depth by preventing 
unauthorized file modifications, even if the container is compromised.

Best practice: Use read-only root filesystems and mount writable 
volumes only where necessary (logs, cache, temp files).
""".strip(),
            remediation="""
Set the root filesystem to read-only:

securityContext:
  readOnlyRootFilesystem: true  # ✅ Enable this

# If your app needs to write to specific directories:
volumeMounts:
  - name: tmp
    mountPath: /tmp         # Writable temp directory
  - name: cache
    mountPath: /var/cache   # Writable cache directory

volumes:
  - name: tmp
    emptyDir: {}           # Ephemeral writable volume
  - name: cache
    emptyDir: {}

This allows writes only to explicitly mounted volumes, 
while keeping the root filesystem immutable.

Common directories that need to be writable:
- /tmp
- /var/cache
- /var/log
- /var/run
""".strip(),
            compliance=[
                "CIS-5.2.6",
                "NIST-800-190",
                "PCI-DSS-2.2.5"
            ]
        )
    
    def _get_category(self) -> str:
        return "pod_security"
