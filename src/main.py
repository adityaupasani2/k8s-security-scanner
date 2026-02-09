#!/usr/bin/env python3
"""
Kubernetes Security Scanner
Scans K8s clusters for security misconfigurations
"""

import click
from kubernetes import client, config
from colorama import init, Fore, Style
import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.utils.scanner_manager import ScannerManager

# Initialize colorama
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
    """
    
    # Print banner
    print_banner()
    
    try:
        # Load Kubernetes configuration
        config.load_kube_config()
        v1 = client.CoreV1Api()
        
        # Initialize scanner manager
        scanner_mgr = ScannerManager()
        click.echo(f"{Fore.GREEN}✓ Loaded {scanner_mgr.get_scanner_count()} security scanners{Style.RESET_ALL}\n")
        
        # Determine namespaces to scan
        if all_namespaces:
            click.echo(f"{Fore.CYAN}📡 Scanning ALL namespaces...{Style.RESET_ALL}\n")
            namespaces = [ns.metadata.name for ns in v1.list_namespace().items]
        else:
            click.echo(f"{Fore.CYAN}📡 Scanning namespace: {namespace}{Style.RESET_ALL}\n")
            namespaces = [namespace]
        
        # Collect all findings
        all_results = {
            'CRITICAL': [],
            'HIGH': [],
            'MEDIUM': [],
            'LOW': []
        }
        total_pods = 0
        
        # Scan each namespace
        for ns in namespaces:
            try:
                pods = v1.list_namespaced_pod(namespace=ns)
                
                if len(pods.items) == 0:
                    continue
                
                total_pods += len(pods.items)
                
                click.echo(f"{Fore.GREEN}✓ Found {len(pods.items)} pods in namespace '{ns}'{Style.RESET_ALL}")
                
                # Scan all pods in namespace
                results = scanner_mgr.scan_pods(pods.items)
                
                # Merge results
                for severity in all_results.keys():
                    all_results[severity].extend(
                        results['findings_by_severity'][severity]
                    )
                
            except client.exceptions.ApiException as e:
                if e.status == 404:
                    click.echo(f"{Fore.RED}✗ Namespace '{ns}' not found{Style.RESET_ALL}")
                else:
                    click.echo(f"{Fore.RED}✗ Error accessing namespace '{ns}': {e}{Style.RESET_ALL}")
                continue
        
        # Display results
        print_results(all_results, total_pods)
        
    except config.ConfigException:
        click.echo(f"{Fore.RED}✗ Could not load Kubernetes config{Style.RESET_ALL}")
        click.echo(f"{Fore.YELLOW}💡 Make sure you have a valid ~/.kube/config file{Style.RESET_ALL}")
        sys.exit(1)
        
    except Exception as e:
        click.echo(f"{Fore.RED}✗ Unexpected error: {str(e)}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()
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


def print_results(findings_by_severity, total_pods):
    """Print scan results to terminal"""
    
    # Calculate totals
    total_findings = sum(len(findings) for findings in findings_by_severity.values())
    
    click.echo(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    click.echo(f"{Fore.YELLOW}📊 SCAN RESULTS{Style.RESET_ALL}")
    click.echo(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    click.echo(f"Total pods scanned: {total_pods}")
    click.echo(f"Total issues found: {total_findings}\n")
    
    # Print findings by severity
    severity_colors = {
        'CRITICAL': Fore.RED,
        'HIGH': Fore.YELLOW,
        'MEDIUM': Fore.BLUE,
        'LOW': Fore.WHITE
    }
    
    severity_icons = {
        'CRITICAL': '🚨',
        'HIGH': '⚠️ ',
        'MEDIUM': '🔵',
        'LOW': 'ℹ️ '
    }
    
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        findings = findings_by_severity[severity]
        count = len(findings)
        
        if count > 0:
            color = severity_colors[severity]
            icon = severity_icons[severity]
            
            click.echo(f"{color}{icon} {severity} Issues: {count}{Style.RESET_ALL}")
            
            # Show first 3 findings of each severity
            for finding in findings[:3]:
                click.echo(f"  {color}├─{Style.RESET_ALL} {finding['pod_name']}/{finding['container_name']}")
                click.echo(f"  {color}│{Style.RESET_ALL}  {finding['issue']}")
            
            if count > 3:
                click.echo(f"  {color}└─{Style.RESET_ALL} ... and {count - 3} more")
            
            click.echo()
    
    # Security score (simple calculation for now)
    if total_findings == 0:
        score = 100
        grade = "A+"
        color = Fore.GREEN
    else:
        # Deduct points based on severity
        deductions = (
            len(findings_by_severity['CRITICAL']) * 15 +
            len(findings_by_severity['HIGH']) * 8 +
            len(findings_by_severity['MEDIUM']) * 3 +
            len(findings_by_severity['LOW']) * 1
        )
        score = max(0, 100 - deductions)
        
        if score >= 90:
            grade = "A"
            color = Fore.GREEN
        elif score >= 75:
            grade = "B"
            color = Fore.CYAN
        elif score >= 60:
            grade = "C"
            color = Fore.YELLOW
        else:
            grade = "F"
            color = Fore.RED
    
    click.echo(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    click.echo(f"{color}Security Score: {score}/100 (Grade: {grade}){Style.RESET_ALL}")
    click.echo(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    if total_findings > 0:
        click.echo(f"{Fore.YELLOW}💡 Run with --output json or --output html for detailed reports{Style.RESET_ALL}\n")


if __name__ == '__main__':
    scan()
