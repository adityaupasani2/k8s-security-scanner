"""
Untagged Image Scanner
Detects containers with no image tag specified
"""

from typing import List, Dict, Any
from .base_scanner import BaseScanner


class UntaggedImageScanner(BaseScanner):
    """
    Scans for containers without image tags
    
    No tag defaults to :latest (even worse!)
    """
    
    def scan(self, pod) -> List[Dict[str, Any]]:
        """
        Check if containers have image tags
        """
        findings = []
        
        pod_name = pod.metadata.name
        namespace = pod.metadata.namespace
        
        for container in pod.spec.containers:
            container_name = container.name
            image = container.image
            
            # Check if image has no tag or digest
            if ':' not in image and '@' not in image:
                findings.append(self._create_untagged_finding(
                    pod_name, namespace, container_name, image
                ))
        
        return findings
    
    def _create_untagged_finding(self, pod_name, namespace, container_name, image):
        
        return self.create_finding(
            severity="MEDIUM",
            pod_name=pod_name,
            namespace=namespace,
            container_name=container_name,
            issue="Image has no tag specified",
            description=f"""
Container '{container_name}' in pod '{pod_name}' uses an image without a tag.

Image: {image}

When no tag is specified, Kubernetes defaults to :latest.

This is dangerous because:
- You don't know what version is running
- Different nodes may pull different versions
- No reproducibility
- No guaranteed rollback
""".strip(),
            remediation=f"""
Specify a version tag explicitly:

# BEFORE:
image: {image}

# AFTER:
image: {image}:1.21.6
# OR:
image: {image}:stable
# OR:
image: {image}@sha256:abc123...
""".strip(),
            compliance=[
                "CIS-5.4.1",
                "Image Security Best Practices",
                "Configuration Management"
            ]
        )
    
    def _get_category(self):
        return "image_security"
