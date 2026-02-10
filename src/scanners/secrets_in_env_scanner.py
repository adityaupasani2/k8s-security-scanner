"""
Secrets in Environment Variables Scanner
Detects hardcoded secrets in environment variables
"""

from typing import List, Dict, Any
import re
from .base_scanner import BaseScanner


class SecretsInEnvScanner(BaseScanner):
    """
    Scans for secrets hardcoded in environment variables
    
    Hardcoded secrets are dangerous because:
    - Visible in pod specs
    - Stored in etcd unencrypted
    - Visible in kubectl describe
    - Logged in various places
    """
    
    # Patterns that suggest secrets
    SECRET_PATTERNS = [
        'PASSWORD', 'PASSWD', 'PWD',
        'SECRET', 'API_KEY', 'APIKEY',
        'TOKEN', 'AUTH', 'CREDENTIAL',
        'PRIVATE_KEY', 'PRIV_KEY',
        'ACCESS_KEY', 'SECRET_KEY',
        'DATABASE_URL', 'DB_PASSWORD',
        'ENCRYPTION_KEY', 'CIPHER_KEY',
    ]
    
    # Patterns that are probably NOT secrets (false positives)
    SAFE_PATTERNS = [
        'PATH', 'HOME', 'SHELL', 'LANG',
        'TZ', 'TERM', 'USER', 'HOSTNAME',
        'PORT', 'HOST', 'REPLICAS',
    ]
    
    def scan(self, pod) -> List[Dict[str, Any]]:
        """
        Check if containers have secrets in environment variables
        
        Args:
            pod: Kubernetes pod object
            
        Returns:
            List of findings for hardcoded secrets
        """
        findings = []
        
        pod_name = pod.metadata.name
        namespace = pod.metadata.namespace
        
        for container in pod.spec.containers:
            container_name = container.name
            
            if container.env:
                for env_var in container.env:
                    var_name = env_var.name
                    
                    # Check if this looks like a secret
                    if self._is_likely_secret(var_name):
                        # Check if it's using valueFrom (good)
                        if env_var.value_from:
                            # Using secretKeyRef or configMapKeyRef - GOOD
                            continue
                        elif env_var.value:
                            # Has a hardcoded value - BAD
                            findings.append(self._create_secret_finding(
                                pod_name, namespace, container_name,
                                var_name, env_var.value
                            ))
        
        return findings
    
    def _is_likely_secret(self, var_name: str) -> bool:
        """
        Check if environment variable name suggests it contains a secret
        
        Args:
            var_name: Environment variable name
            
        Returns:
            True if likely a secret
        """
        var_upper = var_name.upper()
        
        # Check safe patterns first (avoid false positives)
        for safe in self.SAFE_PATTERNS:
            if safe in var_upper:
                return False
        
        # Check secret patterns
        for pattern in self.SECRET_PATTERNS:
            if pattern in var_upper:
                return True
        
        return False
    
    def _create_secret_finding(
        self,
        pod_name: str,
        namespace: str,
        container_name: str,
        var_name: str,
        value: str
    ) -> Dict[str, Any]:
        """Create finding for hardcoded secret"""
        
        # Mask the value for security
        masked_value = self._mask_value(value)
        
        return self.create_finding(
            severity="CRITICAL",
            pod_name=pod_name,
            namespace=namespace,
            container_name=container_name,
            issue=f"Hardcoded secret in environment variable: {var_name}",
            description=f"""
Container '{container_name}' in pod '{pod_name}' has a hardcoded secret 
in environment variable '{var_name}'.

Value: {masked_value}

Hardcoded secrets are CRITICAL security risks:
- Visible in pod specifications (kubectl describe)
- Stored unencrypted in etcd database
- Visible in container inspect output
- Logged in various system logs
- Included in crash dumps and error reports
- Visible to anyone with pod read access
- Cannot be rotated without redeployment
- May be committed to Git repositories

This is one of the most common security mistakes in Kubernetes!

NEVER hardcode secrets in environment variables.
""".strip(),
            remediation=f"""
Use Kubernetes Secrets instead of hardcoded values:

Step 1: Create a Secret
kubectl create secret generic app-secrets \\
  --from-literal={var_name}='your-secret-value'

Step 2: Reference the Secret in your pod
# BEFORE (Bad - Hardcoded):
env:
- name: {var_name}
  value: "{masked_value}"  # ❌ NEVER DO THIS

# AFTER (Good - Using Secret):
env:
- name: {var_name}
  valueFrom:
    secretKeyRef:
      name: app-secrets      # ✅ Reference Secret
      key: {var_name}

Alternative: Use external secret managers
- AWS Secrets Manager
- HashiCorp Vault
- Azure Key Vault
- Google Secret Manager

With external secrets operator:
env:
- name: {var_name}
  valueFrom:
    secretKeyRef:
      name: external-secret-name
      key: {var_name}

Best practices:
1. Never commit secrets to Git
2. Use different secrets per environment
3. Rotate secrets regularly
4. Use RBAC to control Secret access
5. Enable encryption at rest for etcd
""".strip(),
            compliance=[
                "CIS-5.4.3",
                "PCI-DSS-3.4",
                "GDPR-Article-32",
                "SOC2-CC6.1"
            ]
        )
    
    def _mask_value(self, value: str) -> str:
        """
        Mask secret value for security
        
        Args:
            value: Secret value
            
        Returns:
            Masked value
        """
        if len(value) <= 4:
            return "****"
        else:
            # Show first 2 and last 2 chars
            return f"{value[:2]}...{value[-2:]}"
    
    def _get_category(self) -> str:
        return "secrets_management"
