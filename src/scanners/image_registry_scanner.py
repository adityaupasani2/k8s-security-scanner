"""
Image Registry Scanner
Detects images from untrusted/public registries
"""

from typing import List, Dict, Any
from .base_scanner import BaseScanner


class ImageRegistryScanner(BaseScanner):
    """
    Scans for images from untrusted registries
    
    Public registries can contain:
    - Malicious images
    - Vulnerable images
    - Backdoored images
    """
    
    # Trusted registries (commonly approved)
    TRUSTED_REGISTRIES = [
        'gcr.io',           # Google Container Registry
        'us.gcr.io',
        'eu.gcr.io',
        'asia.gcr.io',
        'registry.k8s.io',  # Kubernetes official
        'k8s.gcr.io',       # Kubernetes (old)
        'quay.io',          # Red Hat Quay
        'ghcr.io',          # GitHub Container Registry
        'mcr.microsoft.com', # Microsoft Container Registry
        'docker.io/library', # Docker Official Images only
    ]
    
    def scan(self, pod) -> List[Dict[str, Any]]:
        """
        Check if containers use trusted registries
        
        Args:
            pod: Kubernetes pod object
            
        Returns:
            List of findings for untrusted registries
        """
        findings = []
        
        pod_name = pod.metadata.name
        namespace = pod.metadata.namespace
        
        for container in pod.spec.containers:
            container_name = container.name
            image = container.image
            
            # Extract registry from image
            registry = self._extract_registry(image)
            
            # Check if registry is trusted
            if not self._is_trusted_registry(registry):
                findings.append(self._create_registry_finding(
                    pod_name, namespace, container_name, image, registry
                ))
        
        return findings
    
    def _extract_registry(self, image: str) -> str:
        """Extract registry from image string"""
        
        # Format: registry.com/repo/image:tag
        # OR: image:tag (defaults to docker.io)
        
        parts = image.split('/')
        
        if len(parts) == 1:
            # No registry specified - defaults to Docker Hub
            return 'docker.io'
        elif '.' in parts[0] or ':' in parts[0]:
            # First part contains . or : - it's a registry
            return parts[0]
        else:
            # No registry - defaults to Docker Hub
            return 'docker.io'
    
    def _is_trusted_registry(self, registry: str) -> bool:
        """Check if registry is in trusted list"""
        
        for trusted in self.TRUSTED_REGISTRIES:
            if registry.startswith(trusted):
                return True
        
        return False
    
    def _create_registry_finding(
        self,
        pod_name: str,
        namespace: str,
        container_name: str,
        image: str,
        registry: str
    ) -> Dict[str, Any]:
        """Create finding for untrusted registry"""
        
        return self.create_finding(
            severity="MEDIUM",
            pod_name=pod_name,
            namespace=namespace,
            container_name=container_name,
            issue=f"Image from untrusted registry: {registry}",
            description=f"""
Container '{container_name}' in pod '{pod_name}' uses image from untrusted registry.

Image: {image}
Registry: {registry}

Public registries like Docker Hub can contain:
- Malicious images with backdoors
- Vulnerable or outdated images
- Images that violate licensing
- Unverified or typosquatted images

Best practices:
- Use private registries for internal apps
- Use trusted public registries for open source
- Scan all images before deployment
- Verify image signatures

Trusted registries (examples):
- gcr.io (Google)
- registry.k8s.io (Kubernetes official)
- quay.io (Red Hat)
- ghcr.io (GitHub)
- Your private registry

Note: Even trusted registries should have images scanned!
""".strip(),
            remediation=f"""
Options to fix:

1. Use a private registry:
   image: myregistry.company.com/myapp:1.0.0

2. Use a trusted public registry:
   image: gcr.io/my-project/myapp:1.0.0

3. Mirror public images to your registry:
   # Instead of: nginx:1.21.6
   # Use: myregistry.com/nginx:1.21.6

4. Use official images with full path:
   image: docker.io/library/nginx:1.21.6

Additional security:
- Enable image scanning (Trivy, Clair)
- Verify image signatures (cosign, Notary)
- Use admission controllers to enforce registry policy
- Implement image provenance tracking

Recommended setup:
1. Mirror all external images to private registry
2. Scan images during CI/CD
3. Block untrusted registries via policy
""".strip(),
            compliance=[
                "CIS-5.4.2",
                "Supply Chain Security",
                "Image Provenance"
            ]
        )
    
    def _get_category(self) -> str:
        return "image_security"
