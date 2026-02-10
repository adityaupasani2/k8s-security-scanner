"""
Capabilities Scanner
Detects containers with dangerous Linux capabilities
"""

from typing import List, Dict, Any
from .base_scanner import BaseScanner


class CapabilitiesScanner(BaseScanner):
    """
    Scans for dangerous Linux capabilities
    
    Capabilities grant specific privileges without full root access.
    Some capabilities are extremely dangerous.
    """
    
    # Dangerous capabilities that should almost never be granted
    DANGEROUS_CAPABILITIES = [
        'SYS_ADMIN',      # Perform system administration operations
        'SYS_MODULE',     # Load/unload kernel modules
        'SYS_RAWIO',      # Perform raw I/O operations
        'SYS_PTRACE',     # Trace arbitrary processes
        'SYS_BOOT',       # Reboot the system
        'MAC_ADMIN',      # Override MAC (SELinux/AppArmor)
        'MAC_OVERRIDE',   # Override MAC
        'DAC_READ_SEARCH', # Bypass file read permission checks
        'DAC_OVERRIDE',   # Bypass file permission checks
        'NET_ADMIN',      # Network administration (sometimes needed)
        'NET_RAW',        # Use RAW and PACKET sockets
    ]
    
    def scan(self, pod) -> List[Dict[str, Any]]:
        """
        Check for dangerous capabilities
        
        Args:
            pod: Kubernetes pod object
            
        Returns:
            List of findings for dangerous capabilities
        """
        findings = []
        
        pod_name = pod.metadata.name
        namespace = pod.metadata.namespace
        
        for container in pod.spec.containers:
            container_name = container.name
            
            if container.security_context and container.security_context.capabilities:
                caps = container.security_context.capabilities
                
                # Check added capabilities
                if caps.add:
                    dangerous_caps = []
                    for cap in caps.add:
                        cap_upper = cap.upper()
                        # Remove CAP_ prefix if present
                        cap_clean = cap_upper.replace('CAP_', '')
                        
                        if cap_clean in self.DANGEROUS_CAPABILITIES:
                            dangerous_caps.append(cap_clean)
                    
                    if dangerous_caps:
                        findings.append(self._create_caps_finding(
                            pod_name, namespace, container_name,
                            dangerous_caps
                        ))
        
        return findings
    
    def _create_caps_finding(
        self,
        pod_name: str,
        namespace: str,
        container_name: str,
        capabilities: List[str]
    ) -> Dict[str, Any]:
        """Create finding for dangerous capabilities"""
        
        caps_str = ", ".join(capabilities)
        
        # Determine severity based on capabilities
        if 'SYS_ADMIN' in capabilities or 'SYS_MODULE' in capabilities:
            severity = "HIGH"
        else:
            severity = "MEDIUM"
        
        return self.create_finding(
            severity=severity,
            pod_name=pod_name,
            namespace=namespace,
            container_name=container_name,
            issue=f"Dangerous capabilities granted: {caps_str}",
            description=f"""
Container '{container_name}' in pod '{pod_name}' has dangerous Linux capabilities.

Granted capabilities: {caps_str}

What these capabilities allow:
- SYS_ADMIN: Almost full root access (mount, quotas, etc.)
- SYS_MODULE: Load kernel modules (install rootkits)
- SYS_RAWIO: Direct hardware access
- SYS_PTRACE: Debug any process (steal data)
- SYS_BOOT: Reboot/halt the system
- NET_ADMIN: Modify network stack
- NET_RAW: Craft raw packets (spoofing)
- DAC_OVERRIDE: Bypass all file permissions
- DAC_READ_SEARCH: Read any file

These capabilities can be used for:
- Container escape
- Privilege escalation
- Data exfiltration
- System compromise

Best practice: Drop ALL capabilities, add only what's needed.
""".strip(),
            remediation=f"""
Remove dangerous capabilities and use least privilege:

# BEFORE (Bad):
securityContext:
  capabilities:
    add:
      - {capabilities[0]}  # ❌ Too dangerous

# AFTER (Good - Drop all, add specific):
securityContext:
  capabilities:
    drop:
      - ALL              # ✅ Drop everything first
    add:
      - NET_BIND_SERVICE # ✅ Only add what you need

Common safe capabilities:
- NET_BIND_SERVICE: Bind to ports < 1024
- CHOWN: Change file ownership
- SETUID/SETGID: Change user/group IDs
- KILL: Send signals to processes

Guidelines:
1. Always drop ALL capabilities first
2. Add back ONLY what you need
3. Document why each capability is needed
4. Avoid SYS_ADMIN at all costs
5. Use specific capabilities instead of privileged mode

Alternative solutions:
- Use init containers for privileged operations
- Run privileged tasks outside the container
- Use Kubernetes operators instead
- Redesign to avoid needing capabilities
""".strip(),
            compliance=[
                "CIS-5.2.9",
                "Linux Capabilities Best Practices"
            ]
        )
    
    def _get_category(self) -> str:
        return "pod_security"
