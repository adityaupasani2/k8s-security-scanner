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
import json
from datetime import datetime

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.utils.scanner_manager import ScannerManager
from src.utils.scoring import SecurityScorer
from src.utils.compliance import ComplianceMapper
from src.reports.table_reporter import TableReporter
from src.reports.json_reporter import JSONReporter

# Initialize colorama
init(autoreset=True)


@click.command()
@click.option('--namespace', '-n', default='default', 
              help='Namespace to scan (default: default)')
@click.option('--output', '-o', 
              type=click.Choice(['table', 'json'], case_sensitive=False),
              default='table',
              help='Output format (default: table)')
@click.option('--all-namespaces', '-A', is_flag=True,
              help='Scan all namespaces')
@click.option('--detailed', '-d', is_flag=True,
              help='Show detailed tables')
@click.option('--save', '-s', type=str,
              help='Save report to file')
@click.option('--fail-on-critical', is_flag=True,
              help='Exit with code 1 if CRITICAL issues found')
@click.option('--min-score', type=int, default=0,
              help='Minimum security score (0-100), fail if below')
def scan(namespace, output, all_namespaces, detailed, save, fail_on_critical, min_score):
    """
    Scan Kubernetes cluster for security issues
    """
    
    # Print banner (skip for JSON output)
    if output != 'json':
        print_banner()
    
    try:
        # Load Kubernetes configuration
        config.load_kube_config()
        v1 = client.CoreV1Api()
        
        # Initialize scanner manager and scorer
        scanner_mgr = ScannerManager()
        scorer = SecurityScorer()
        
        if output != 'json':
            click.echo(f"{Fore.GREEN}✓ Loaded {scanner_mgr.get_scanner_count()} security scanners{Style.RESET_ALL}\n")
        
        # Determine namespaces to scan
        if all_namespaces:
            if output != 'json':
                click.echo(f"{Fore.CYAN}📡 Scanning ALL namespaces...{Style.RESET_ALL}\n")
            namespaces = [ns.metadata.name for ns in v1.list_namespace().items]
        else:
            if output != 'json':
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
        pod_scores = []
        
        # Scan each namespace
        for ns in namespaces:
            try:
                pods = v1.list_namespaced_pod(namespace=ns)
                
                if len(pods.items) == 0:
                    continue
                
                total_pods += len(pods.items)
                
                if output != 'json':
                    click.echo(f"{Fore.GREEN}✓ Found {len(pods.items)} pods in namespace '{ns}'{Style.RESET_ALL}")
                
                # Scan all pods in namespace
                results = scanner_mgr.scan_pods(pods.items)
                
                # Calculate pod scores
                for pod in pods.items:
                    pod_findings = scanner_mgr.scan_pod(pod)
                    pod_score = scorer.calculate_pod_score(pod_findings)
                    pod_scores.append({
                        'name': pod.metadata.name,
                        'namespace': ns,
                        **pod_score
                    })
                
                # Merge results
                for severity in all_results.keys():
                    all_results[severity].extend(
                        results['findings_by_severity'][severity]
                    )
                
            except client.exceptions.ApiException as e:
                if e.status == 404:
                    if output != 'json':
                        click.echo(f"{Fore.RED}✗ Namespace '{ns}' not found{Style.RESET_ALL}")
                else:
                    if output != 'json':
                        click.echo(f"{Fore.RED}✗ Error accessing namespace '{ns}': {e}{Style.RESET_ALL}")
                continue
        
        # Calculate overall scores
        all_findings_list = (all_results['CRITICAL'] + all_results['HIGH'] + 
                            all_results['MEDIUM'] + all_results['LOW'])
        
        overall_score = scorer.calculate_pod_score(all_findings_list)
        
        # Get compliance data
        mapper = ComplianceMapper()
        compliance_data = mapper.analyze_compliance(all_findings_list)
        
        # Handle output format
        if output == 'json':
            json_reporter = JSONReporter(
                all_findings_list,
                pod_scores,
                overall_score,
                compliance_data,
                namespace if not all_namespaces else 'all',
                total_pods
            )
            
            report = json_reporter.generate_report()
            
            # Print JSON to stdout
            print(json.dumps(report, indent=2))
            
            # Save to file if requested
            if save:
                json_reporter.save_to_file(save)
            
            # Exit with appropriate code
            exit_code = json_reporter.get_exit_code()
            
            # Override exit code based on flags
            if fail_on_critical and len(all_results['CRITICAL']) > 0:
                sys.exit(1)
            if min_score > 0 and overall_score['score'] < min_score:
                sys.exit(1)
            
            sys.exit(exit_code)
        
        # HTML output would go here (skipped for this version)
        
        else:  # table output
            if detailed:
                print_detailed_results(
                    all_results, total_pods, overall_score, scorer,
                    pod_scores, compliance_data, all_findings_list
                )
            else:
                print_results(all_results, total_pods, overall_score, scorer)
                print_compliance_summary(all_results)
            
            # Save to file if requested
            if save:
                reporter = TableReporter(all_findings_list)
                content = generate_full_report(
                    all_results, total_pods, overall_score,
                    pod_scores, compliance_data, all_findings_list, reporter
                )
                if reporter.save_to_file(save, content):
                    click.echo(f"\n{Fore.GREEN}✓ Report saved to {save}{Style.RESET_ALL}")
            
            # Exit with code based on flags
            if fail_on_critical and len(all_results['CRITICAL']) > 0:
                click.echo(f"\n{Fore.RED}✗ Exiting with code 1 (CRITICAL issues found){Style.RESET_ALL}")
                sys.exit(1)
            if min_score > 0 and overall_score['score'] < min_score:
                click.echo(f"\n{Fore.RED}✗ Exiting with code 1 (score {overall_score['score']} < {min_score}){Style.RESET_ALL}")
                sys.exit(1)
        
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


def print_results(findings_by_severity, total_pods, overall_score, scorer):
    """Print standard scan results"""
    
    total_findings = sum(len(findings) for findings in findings_by_severity.values())
    
    click.echo(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    click.echo(f"{Fore.YELLOW}📊 SCAN RESULTS{Style.RESET_ALL}")
    click.echo(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    click.echo(f"Total pods scanned: {total_pods}")
    click.echo(f"Total issues found: {total_findings}\n")
    
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
            
            for finding in findings[:3]:
                click.echo(f"  {color}├─{Style.RESET_ALL} {finding['pod_name']}/{finding['container_name']}")
                click.echo(f"  {color}│{Style.RESET_ALL}  {finding['issue']}")
            
            if count > 3:
                click.echo(f"  {color}└─{Style.RESET_ALL} ... and {count - 3} more")
            
            click.echo()
    
    score = overall_score['score']
    grade = overall_score['grade']
    risk_level = overall_score['risk_level']
    
    if score >= 80:
        score_color = Fore.GREEN
    elif score >= 60:
        score_color = Fore.YELLOW
    else:
        score_color = Fore.RED
    
    click.echo(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    click.echo(f"{score_color}Security Score: {score}/100 (Grade: {grade}){Style.RESET_ALL}")
    click.echo(f"{score_color}Risk Level: {risk_level}{Style.RESET_ALL}")
    click.echo(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    recommendations = scorer.get_recommendations(score, overall_score['severity_breakdown'])
    
    if recommendations:
        click.echo(f"{Fore.YELLOW}📋 Recommendations:{Style.RESET_ALL}")
        for rec in recommendations:
            click.echo(f"  {rec}")
        click.echo()


def print_detailed_results(
    findings_by_severity, total_pods, overall_score, scorer,
    pod_scores, compliance_data, all_findings
):
    """Print detailed results with tables"""
    
    reporter = TableReporter(all_findings)
    
    click.echo(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    click.echo(f"{Fore.YELLOW}📊 DETAILED SCAN RESULTS{Style.RESET_ALL}")
    click.echo(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    
    click.echo(reporter.generate_summary_table())
    click.echo(reporter.generate_findings_table(max_rows=30))
    click.echo(reporter.generate_pod_table(pod_scores))
    click.echo(reporter.generate_compliance_table(compliance_data))
    
    score = overall_score['score']
    grade = overall_score['grade']
    risk_level = overall_score['risk_level']
    
    if score >= 80:
        score_color = Fore.GREEN
    elif score >= 60:
        score_color = Fore.YELLOW
    else:
        score_color = Fore.RED
    
    click.echo(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    click.echo(f"{score_color}Overall Security Score: {score}/100 (Grade: {grade}){Style.RESET_ALL}")
    click.echo(f"{score_color}Risk Level: {risk_level}{Style.RESET_ALL}")
    click.echo(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")


def print_compliance_summary(findings_by_severity):
    """Print compliance framework summary"""
    mapper = ComplianceMapper()
    
    all_findings = []
    for findings in findings_by_severity.values():
        all_findings.extend(findings)
    
    if not all_findings:
        return
    
    compliance = mapper.analyze_compliance(all_findings)
    
    if compliance['total_frameworks_affected'] == 0:
        return
    
    click.echo(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    click.echo(f"{Fore.YELLOW}📋 COMPLIANCE SUMMARY{Style.RESET_ALL}")
    click.echo(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    for framework, data in compliance['framework_scores'].items():
        full_name = mapper.get_framework_name(framework)
        pct = data['compliance_percentage']
        status = data['status']
        
        if status == 'COMPLIANT':
            color = Fore.GREEN
        elif status == 'MOSTLY_COMPLIANT':
            color = Fore.YELLOW
        else:
            color = Fore.RED
        
        click.echo(f"{color}{framework}{Style.RESET_ALL} - {full_name}")
        click.echo(f"  Compliance: {color}{pct}%{Style.RESET_ALL} ({status})")
        click.echo(f"  Violations: {data['total_violations']} "
                   f"(Critical: {data['critical_violations']}, "
                   f"High: {data['high_violations']})")
        click.echo()
    
    click.echo(f"{Fore.YELLOW}💡 Run with --detailed for enhanced tables{Style.RESET_ALL}")
    click.echo(f"{Fore.YELLOW}💡 Run with --output html for visual report{Style.RESET_ALL}\n")


def generate_full_report(
    findings_by_severity, total_pods, overall_score,
    pod_scores, compliance_data, all_findings, reporter
):
    """Generate complete report text"""
    
    report_parts = [
        "KUBERNETES SECURITY SCAN REPORT",
        "=" * 60,
        "",
        f"Total pods scanned: {total_pods}",
        f"Total issues found: {len(all_findings)}",
        "",
        reporter.generate_summary_table(),
        "",
        reporter.generate_findings_table(max_rows=50),
        "",
        reporter.generate_pod_table(pod_scores),
        "",
        reporter.generate_compliance_table(compliance_data),
        "",
        f"Overall Security Score: {overall_score['score']}/100 (Grade: {overall_score['grade']})",
        f"Risk Level: {overall_score['risk_level']}",
        ""
    ]
    
    return "\n".join(report_parts)


if __name__ == '__main__':
    scan()
