#!/usr/bin/env python3
"""
Kubernetes Security Scanner
Scans K8s clusters for security misconfigurations
"""

import click
from kubernetes import client, config
from colorama import init, Fore, Style
import sys

# Initialize colorama for cross-platform color support
init(autoreset=True)


@click.command()
@click.option('--namespace', '-n', default='default', 
              help='Namespace to scan (default: default)')
@click.option('--output', '-o', 
              type=click.Choice(['table', 'json', 'html'], case_sensitive=False),
              default='table',
              help='Output format (default: table)')
@click.option('--all-namespaces', '-A', is_flag=True,
              help='Scan all namespaces')
def scan(namespace, output, all_namespaces):
    """
    Scan Kubernetes cluster for security issues
    
    Examples:
        python src/main.py --namespace default
        python src/main.py --all-namespaces --output json
    """
    
    # Print banner
    print_banner()
    
    try:
        # Load Kubernetes configuration
        config.load_kube_config()
        v1 = client.CoreV1Api()
        
        # Determine which namespaces to scan
        if all_namespaces:
            click.echo(f"{Fore.CYAN}📡 Scanning ALL namespaces...{Style.RESET_ALL}\n")
            namespaces = [ns.metadata.name for ns in v1.list_namespace().items]
        else:
            click.echo(f"{Fore.CYAN}📡 Scanning namespace: {namespace}{Style.RESET_ALL}\n")
            namespaces = [namespace]
        
        # Collect all findings
        all_findings = []
        total_pods = 0
        
        # Scan each namespace
        for ns in namespaces:
            try:
                pods = v1.list_namespaced_pod(namespace=ns)
                
                if len(pods.items) == 0:
                    continue
                    
                total_pods += len(pods.items)
                
                click.echo(f"{Fore.GREEN}✓ Connected to cluster{Style.RESET_ALL}")
                click.echo(f"{Fore.GREEN}✓ Found {len(pods.items)} pods in namespace '{ns}'{Style.RESET_ALL}\n")
                
                # List pods
                click.echo(f"{Fore.YELLOW}Pods discovered:{Style.RESET_ALL}")
                for pod in pods.items:
                    status_icon = "🟢" if pod.status.phase == "Running" else "🔴"
                    click.echo(f"  {status_icon} {pod.metadata.name} ({pod.status.phase})")
                
            except client.exceptions.ApiException as e:
                if e.status == 404:
                    click.echo(f"{Fore.RED}✗ Namespace '{ns}' not found{Style.RESET_ALL}")
                else:
                    click.echo(f"{Fore.RED}✗ Error accessing namespace '{ns}': {e}{Style.RESET_ALL}")
                continue
        
        click.echo(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        click.echo(f"{Fore.YELLOW}📊 Scan Summary{Style.RESET_ALL}")
        click.echo(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        click.echo(f"Total namespaces scanned: {len(namespaces)}")
        click.echo(f"Total pods found: {total_pods}")
        click.echo(f"\n{Fore.YELLOW}⚠️  Security scanning logic coming in Day 2-7...{Style.RESET_ALL}")
        click.echo(f"{Fore.GREEN}✓ Scanner framework is working!{Style.RESET_ALL}\n")
        
    except config.ConfigException:
        click.echo(f"{Fore.RED}✗ Could not load Kubernetes config{Style.RESET_ALL}")
        click.echo(f"{Fore.YELLOW}💡 Make sure you have a valid ~/.kube/config file{Style.RESET_ALL}")
        sys.exit(1)
        
    except Exception as e:
        click.echo(f"{Fore.RED}✗ Unexpected error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)


def print_banner():
    """Print ASCII banner"""
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════╗
║                                                          ║
║        🔒 KUBERNETES SECURITY SCANNER v1.0 🔒           ║
║                                                          ║
║     Detect security misconfigurations in K8s clusters   ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    click.echo(banner)


if __name__ == '__main__':
    scan()
