"""
Host Namespaces Scanner
Detects pods using host PID or IPC namespaces
"""

from typing import List, Dict, Any
from .base_scanner import BaseScanner


class HostNamespacesScanner(BaseScanner):
    """
    Scans for pods using host PID or IPC namespaces
    
    hostPID and hostIPC are dangerous because:
    - Can see all processes on the node
    - Can signal/kill node processes
    - Can access shared memory
    - Breaks process isolation
    """
    
    def scan(self, pod) -> List[Dict[str, Any]]:
        """
        Check if pods use host namespaces
        
        Args:
            pod: Kubernetes pod object
            
        Returns:
            List of findings for host namespace usage
        """
        findings = []
        
        pod_name = pod.metadata.name
        namespace = pod.metadata.namespace
        
        # Check hostPID
        if pod.spec.host_pid:
            findings.append(self._create_host_pid_finding(
                pod_name, namespace
            ))
        
        # Check hostIPC
        if pod.spec.host_ipc:
            findings.append(self._create_host_ipc_finding(
                pod_name, namespace
            ))
        
        return findings
    
    def _create_host_pid_finding(
        self,
        pod_name: str,
        namespace: str
    ) -> Dict[str, Any]:
        """Create finding for hostPID usage"""
        
        return self.create_finding(
            severity="MEDIUM",
            pod_name=pod_name,
            namespace=namespace,
            container_name="<all>",
            issue="Pod using host PID namespace",
            description=f"""
Pod '{pod_name}' is using the host PID namespace (hostPID: true).

This is a security risk because:
- Pod can see ALL processes on the node (ps aux shows host processes)
- Can signal or kill host processes
- Can read /proc files from other processes
- Breaks process isolation
- Can inspect other containers' processes
- Access to sensitive process information

With hostPID, a container can:
1. See kubelet processes
2. Kill node-critical processes
3. Read environment variables of other processes
4. Perform privilege escalation attacks

hostPID should ONLY be used for:
- System monitoring tools (node exporter, cAdvisor)
- Debugging DaemonSets
- Process management tools

For regular applications, this is unnecessary.
""".strip(),
            remediation="""
Remove hostPID from your pod spec:

# BEFORE (Bad):
spec:
  hostPID: true    # ❌ REMOVE THIS
  containers:
  - name: myapp
    ...

# AFTER (Good):
spec:
  # hostPID removed - uses pod PID namespace
  containers:
  - name: myapp
    ...

If you need to interact with processes:
1. Use proper APIs instead of direct process access
2. Use sidecar containers for monitoring
3. Use Kubernetes metrics APIs
4. Use pod-level resource metrics

Valid use cases for hostPID:
- node-exporter (Prometheus metrics)
- Process monitoring DaemonSets
- Debugging tools (temporary)

For normal apps: Never use hostPID!
""".strip(),
            compliance=[
                "CIS-5.2.2",
                "Process Isolation",
                "Container Security Best Practices"
            ]
        )
    
    def _create_host_ipc_finding(
        self,
        pod_name: str,
        namespace: str
    ) -> Dict[str, Any]:
        """Create finding for hostIPC usage"""
        
        return self.create_finding(
            severity="MEDIUM",
            pod_name=pod_name,
            namespace=namespace,
            container_name="<all>",
            issue="Pod using host IPC namespace",
            description=f"""
Pod '{pod_name}' is using the host IPC namespace (hostIPC: true).

This is a security risk because:
- Pod can access host's shared memory
- Can read/write IPC resources (semaphores, message queues)
- Can communicate with host processes via shared memory
- Breaks IPC isolation
- Can leak sensitive data through shared memory

Inter-Process Communication (IPC) includes:
- Shared memory segments
- Semaphores
- Message queues
- Shared memory from other pods/processes

With hostIPC, containers can:
1. Read shared memory from other applications
2. Inject data into other processes
3. Steal sensitive information
4. Cause denial of service

hostIPC should ONLY be used for:
- Applications specifically requiring host IPC
- Legacy applications with IPC dependencies
- System-level monitoring

This is rarely needed for modern applications.
""".strip(),
            remediation="""
Remove hostIPC from your pod spec:

# BEFORE (Bad):
spec:
  hostIPC: true    # ❌ REMOVE THIS
  containers:
  - name: myapp
    ...

# AFTER (Good):
spec:
  # hostIPC removed - uses pod IPC namespace
  containers:
  - name: myapp
    ...

If you need inter-process communication:
1. Use network sockets (TCP/UDP)
2. Use shared volumes (emptyDir)
3. Use message queues (RabbitMQ, Kafka)
4. Use gRPC or REST APIs
5. Use Kubernetes Services

Modern IPC alternatives:
- Network-based: gRPC, HTTP, WebSockets
- File-based: Shared volumes, Unix sockets
- Queue-based: Message brokers

Valid use cases for hostIPC:
- Legacy apps requiring System V IPC
- Specific monitoring tools
- Database with shared memory requirements

For 99% of apps: Use network-based communication!
""".strip(),
            compliance=[
                "CIS-5.2.3",
                "IPC Isolation",
                "Container Security Best Practices"
            ]
        )
    
    def _get_category(self) -> str:
        return "host_access"
