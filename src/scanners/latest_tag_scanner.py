"""
Latest Tag Scanner
Detects containers using :latest image tag
"""

from typing import List, Dict, Any
from .base_scanner import BaseScanner


class LatestTagScanner(BaseScanner):
    """
    Scans for containers using :latest image tag
    
    :latest tag is dangerous because:
    - You don't know what version is running
    - Can change without warning
    - Breaks reproducibility
    """
    
    def scan(self, pod) -> List[Dict[str, Any]]:
        """
        Check if containers use :latest tag
        
        Args:
            pod: Kubernetes pod object
            
        Returns:
            List of findings for containers using :latest
        """
        findings = []
        
        pod_name = pod.metadata.name
        namespace = pod.metadata.namespace
        
        for container in pod.spec.containers:
            container_name = container.name
            image = container.image
            
            # Check if image ends with :latest or has :latest explicitly
            if image.endswith(':latest') or ':latest' in image:
                findings.append(self._create_latest_finding(
                    pod_name, namespace, container_name, image
                ))
        
        return findings
    
    def _create_latest_finding(
        self,
        pod_name: str,
        namespace: str,
        container_name: str,
        image: str
    ) -> Dict[str, Any]:
        """Create finding for :latest tag usage"""
        
        # Extract image name without tag
        image_base = image.split(':')[0]
        
        return self.create_finding(
            severity="MEDIUM",
            pod_name=pod_name,
            namespace=namespace,
            container_name=container_name,
            issue="Using :latest image tag",
            description=f"""
Container '{container_name}' in pod '{pod_name}' uses :latest tag.

Image: {image}

The :latest tag is unpredictable because:
- It changes every time a new image is pushed
- You don't know which version is actually running
- Different nodes may pull different versions
- Breaks deployment reproducibility
- Makes rollbacks impossible
- Causes "works on my machine" issues

In production, :latest can pull a broken image without warning.

Best practice: ALWAYS use specific version tags.
""".strip(),
            remediation=f"""
Replace :latest with a specific version tag:

# BEFORE (Bad):
image: {image}

# AFTER (Good):
image: {image_base}:1.21.6
# OR
image: {image_base}:v2.3.1
# OR
image: {image_base}:sha256-abc123...  # Most secure - immutable

Version tag strategies:
1. Semantic versioning: nginx:1.21.6
2. Git commit SHA: myapp:a1b2c3d
3. Build number: myapp:build-1234
4. Image digest: nginx@sha256:abc123... (immutable)

Recommended: Use semantic versioning for readability, 
or image digests for maximum security.
""".strip(),
            compliance=[
                "CIS-5.4.1",
                "Image Security Best Practices",
                "Deployment Reproducibility"
            ]
        )
    
    def _get_category(self) -> str:
        return "image_security"
