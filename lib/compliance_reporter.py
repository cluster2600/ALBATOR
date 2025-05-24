#!/usr/bin/env python3
"""
Albator Compliance Reporter
Generates compliance reports for various security frameworks
"""

import os
import sys
import json
import yaml
import subprocess
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict

# Add lib directory to path for imports
sys.path.insert(0, os.path.dirname(__file__))
from logger import get_logger, log_operation_start, log_operation_success, log_operation_failure
from config_manager import ConfigurationManager

@dataclass
class ComplianceCheck:
    """Represents a single compliance check"""
    check_id: str
    title: str
    description: str
    category: str
    severity: str  # low, medium, high, critical
    framework: str  # nist, cis, iso27001, custom
    command: str
    expected_result: str
    remediation: str
    status: str = "pending"  # pending, pass, fail, error, not_applicable
    actual_result: str = ""
    error_message: str = ""
    timestamp: str = ""

@dataclass
class ComplianceReport:
    """Represents a compliance report"""
    report_id: str
    framework: str
    system_info: Dict[str, Any]
    checks: List[ComplianceCheck]
    summary: Dict[str, Any]
    generated_at: str
    profile: str = "basic"

class ComplianceReporter:
    """Generates compliance reports for security frameworks"""
    
    def __init__(self, config_path: str = "config/albator.yaml"):
        """Initialize the compliance reporter"""
        self.logger = get_logger("compliance_reporter")
        self.config_manager = ConfigurationManager(config_path)
        self.frameworks = self._load_frameworks()
    
    def _load_frameworks(self) -> Dict[str, Any]:
        """Load compliance framework definitions"""
        frameworks = {
            "nist_800_53": {
                "name": "NIST 800-53 Security Controls",
                "version": "Rev 5",
                "description": "NIST Special Publication 800-53 Security and Privacy Controls",
                "checks": self._get_nist_800_53_checks()
            },
            "cis_macos": {
                "name": "CIS Apple macOS Benchmark",
                "version": "v3.0.0",
                "description": "Center for Internet Security macOS Benchmark",
                "checks": self._get_cis_macos_checks()
            },
            "iso27001": {
                "name": "ISO 27001:2013",
                "version": "2013",
                "description": "Information Security Management System",
                "checks": self._get_iso27001_checks()
            },
            "custom": {
                "name": "Custom Security Baseline",
                "version": "1.0",
                "description": "Organization-specific security requirements",
                "checks": self._get_custom_checks()
            }
        }
        return frameworks
    
    def _get_nist_800_53_checks(self) -> List[Dict[str, Any]]:
        """Get NIST 800-53 compliance checks"""
        return [
            {
                "check_id": "AC-2",
                "title": "Account Management",
                "description": "Verify account management controls are in place",
                "category": "Access Control",
                "severity": "high",
                "command": "dscl . -list /Users | grep -v '^_' | wc -l",
                "expected_result": "User accounts are properly managed",
                "remediation": "Review and manage user accounts according to organizational policy"
            },
            {
                "check_id": "AC-7",
                "title": "Unsuccessful Logon Attempts",
                "description": "Verify account lockout policy is configured",
                "category": "Access Control",
                "severity": "medium",
                "command": "pwpolicy -getaccountpolicies 2>/dev/null || echo 'No policy configured'",
                "expected_result": "Account lockout policy is configured",
                "remediation": "Configure account lockout policy using pwpolicy"
            },
            {
                "check_id": "AU-2",
                "title": "Audit Events",
                "description": "Verify audit logging is enabled",
                "category": "Audit and Accountability",
                "severity": "high",
                "command": "sudo launchctl list | grep -i audit",
                "expected_result": "Audit daemon is running",
                "remediation": "Enable audit logging using auditd"
            },
            {
                "check_id": "CM-6",
                "title": "Configuration Settings",
                "description": "Verify security configuration settings",
                "category": "Configuration Management",
                "severity": "medium",
                "command": "csrutil status",
                "expected_result": "System Integrity Protection status: enabled",
                "remediation": "Enable System Integrity Protection"
            },
            {
                "check_id": "IA-5",
                "title": "Authenticator Management",
                "description": "Verify password policy is configured",
                "category": "Identification and Authentication",
                "severity": "high",
                "command": "pwpolicy -getglobalpolicy 2>/dev/null || echo 'No global policy'",
                "expected_result": "Password policy is configured",
                "remediation": "Configure password policy using pwpolicy"
            },
            {
                "check_id": "SC-7",
                "title": "Boundary Protection",
                "description": "Verify firewall is enabled",
                "category": "System and Communications Protection",
                "severity": "high",
                "command": "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate",
                "expected_result": "Firewall is enabled",
                "remediation": "Enable application firewall"
            },
            {
                "check_id": "SC-13",
                "title": "Cryptographic Protection",
                "description": "Verify disk encryption is enabled",
                "category": "System and Communications Protection",
                "severity": "critical",
                "command": "fdesetup status",
                "expected_result": "FileVault is On",
                "remediation": "Enable FileVault disk encryption"
            }
        ]
    
    def _get_cis_macos_checks(self) -> List[Dict[str, Any]]:
        """Get CIS macOS benchmark checks"""
        return [
            {
                "check_id": "1.1",
                "title": "Verify all Apple provided software is current",
                "description": "Ensure software updates are current",
                "category": "Software Updates",
                "severity": "high",
                "command": "softwareupdate -l 2>&1 | grep -i 'no new software available' || echo 'Updates available'",
                "expected_result": "No new software available",
                "remediation": "Install available software updates"
            },
            {
                "check_id": "1.2",
                "title": "Enable Auto Update",
                "description": "Verify automatic updates are enabled",
                "category": "Software Updates",
                "severity": "medium",
                "command": "defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled",
                "expected_result": "1",
                "remediation": "Enable automatic software updates"
            },
            {
                "check_id": "2.1.1",
                "title": "Turn off Bluetooth, if no paired devices exist",
                "description": "Disable Bluetooth when not needed",
                "category": "Bluetooth",
                "severity": "low",
                "command": "defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState 2>/dev/null || echo '0'",
                "expected_result": "0",
                "remediation": "Disable Bluetooth if not needed"
            },
            {
                "check_id": "2.4.1",
                "title": "Enable FileVault",
                "description": "Verify disk encryption is enabled",
                "category": "FileVault",
                "severity": "critical",
                "command": "fdesetup status",
                "expected_result": "FileVault is On",
                "remediation": "Enable FileVault disk encryption"
            },
            {
                "check_id": "2.5.1",
                "title": "Enable Gatekeeper",
                "description": "Verify Gatekeeper is enabled",
                "category": "Gatekeeper",
                "severity": "high",
                "command": "spctl --status",
                "expected_result": "assessments enabled",
                "remediation": "Enable Gatekeeper"
            },
            {
                "check_id": "2.6.1",
                "title": "Enable Firewall",
                "description": "Verify application firewall is enabled",
                "category": "Firewall",
                "severity": "high",
                "command": "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate",
                "expected_result": "Firewall is enabled",
                "remediation": "Enable application firewall"
            },
            {
                "check_id": "2.6.2",
                "title": "Enable Firewall Stealth Mode",
                "description": "Verify firewall stealth mode is enabled",
                "category": "Firewall",
                "severity": "medium",
                "command": "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode",
                "expected_result": "Stealth mode enabled",
                "remediation": "Enable firewall stealth mode"
            },
            {
                "check_id": "3.1",
                "title": "Enable security auditing",
                "description": "Verify audit logging is enabled",
                "category": "Logging and Auditing",
                "severity": "high",
                "command": "sudo launchctl list | grep -i audit",
                "expected_result": "Audit daemon is running",
                "remediation": "Enable audit logging"
            }
        ]
    
    def _get_iso27001_checks(self) -> List[Dict[str, Any]]:
        """Get ISO 27001 compliance checks"""
        return [
            {
                "check_id": "A.9.1.1",
                "title": "Access control policy",
                "description": "Verify access control mechanisms are in place",
                "category": "Access Control",
                "severity": "high",
                "command": "dscl . -list /Users | grep -v '^_' | wc -l",
                "expected_result": "User accounts are properly managed",
                "remediation": "Implement access control policy"
            },
            {
                "check_id": "A.10.1.1",
                "title": "Cryptographic controls",
                "description": "Verify cryptographic controls are implemented",
                "category": "Cryptography",
                "severity": "critical",
                "command": "fdesetup status",
                "expected_result": "FileVault is On",
                "remediation": "Implement disk encryption"
            },
            {
                "check_id": "A.12.4.1",
                "title": "Event logging",
                "description": "Verify event logging is enabled",
                "category": "Operations Security",
                "severity": "high",
                "command": "sudo launchctl list | grep -i audit",
                "expected_result": "Audit daemon is running",
                "remediation": "Enable comprehensive event logging"
            },
            {
                "check_id": "A.13.1.1",
                "title": "Network controls",
                "description": "Verify network security controls",
                "category": "Communications Security",
                "severity": "high",
                "command": "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate",
                "expected_result": "Firewall is enabled",
                "remediation": "Enable network security controls"
            }
        ]
    
    def _get_custom_checks(self) -> List[Dict[str, Any]]:
        """Get custom organization-specific checks"""
        return [
            {
                "check_id": "CUSTOM-001",
                "title": "System Integrity Protection",
                "description": "Verify SIP is enabled",
                "category": "System Protection",
                "severity": "critical",
                "command": "csrutil status",
                "expected_result": "System Integrity Protection status: enabled",
                "remediation": "Enable System Integrity Protection"
            },
            {
                "check_id": "CUSTOM-002",
                "title": "Automatic Login Disabled",
                "description": "Verify automatic login is disabled",
                "category": "Authentication",
                "severity": "high",
                "command": "defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null || echo 'Not set'",
                "expected_result": "Not set",
                "remediation": "Disable automatic login"
            },
            {
                "check_id": "CUSTOM-003",
                "title": "Screen Saver Password Required",
                "description": "Verify screen saver requires password",
                "category": "Physical Security",
                "severity": "medium",
                "command": "defaults read com.apple.screensaver askForPassword 2>/dev/null || echo '0'",
                "expected_result": "1",
                "remediation": "Require password for screen saver"
            }
        ]
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Get system information for the report"""
        try:
            system_info = {
                "hostname": subprocess.check_output(["hostname"], text=True).strip(),
                "macos_version": subprocess.check_output(["sw_vers", "-productVersion"], text=True).strip(),
                "macos_build": subprocess.check_output(["sw_vers", "-buildVersion"], text=True).strip(),
                "hardware_model": subprocess.check_output(["sysctl", "-n", "hw.model"], text=True).strip(),
                "serial_number": subprocess.check_output(["system_profiler", "SPHardwareDataType"], text=True),
                "scan_date": datetime.now().isoformat(),
                "albator_version": "3.0.0"  # Update this as needed
            }
            
            # Extract serial number from system profiler output
            for line in system_info["serial_number"].split('\n'):
                if "Serial Number" in line:
                    system_info["serial_number"] = line.split(':')[-1].strip()
                    break
            else:
                system_info["serial_number"] = "Unknown"
            
            return system_info
            
        except Exception as e:
            self.logger.error(f"Error getting system info: {e}")
            return {
                "hostname": "Unknown",
                "macos_version": "Unknown",
                "macos_build": "Unknown",
                "hardware_model": "Unknown",
                "serial_number": "Unknown",
                "scan_date": datetime.now().isoformat(),
                "albator_version": "3.0.0",
                "error": str(e)
            }
    
    def _execute_check(self, check_data: Dict[str, Any]) -> ComplianceCheck:
        """Execute a single compliance check"""
        check = ComplianceCheck(
            check_id=check_data["check_id"],
            title=check_data["title"],
            description=check_data["description"],
            category=check_data["category"],
            severity=check_data["severity"],
            framework="",  # Will be set by caller
            command=check_data["command"],
            expected_result=check_data["expected_result"],
            remediation=check_data["remediation"],
            timestamp=datetime.now().isoformat()
        )
        
        try:
            # Execute the command
            result = subprocess.run(
                check.command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            check.actual_result = result.stdout.strip()
            
            # Determine pass/fail based on expected result
            if check.expected_result.lower() in check.actual_result.lower():
                check.status = "pass"
            else:
                check.status = "fail"
                
            if result.stderr:
                check.error_message = result.stderr.strip()
                
        except subprocess.TimeoutExpired:
            check.status = "error"
            check.error_message = "Command timed out"
        except Exception as e:
            check.status = "error"
            check.error_message = str(e)
        
        return check
    
    def generate_compliance_report(self, framework: str, profile: str = "basic") -> ComplianceReport:
        """Generate a compliance report for the specified framework"""
        log_operation_start(f"generate_compliance_report: {framework}")
        
        if framework not in self.frameworks:
            raise ValueError(f"Unknown framework: {framework}")
        
        framework_info = self.frameworks[framework]
        
        # Get system information
        system_info = self._get_system_info()
        
        # Execute all checks
        checks = []
        for check_data in framework_info["checks"]:
            check = self._execute_check(check_data)
            check.framework = framework
            checks.append(check)
            self.logger.info(f"Executed check {check.check_id}: {check.status}")
        
        # Generate summary
        summary = self._generate_summary(checks)
        
        # Create report
        report = ComplianceReport(
            report_id=f"{framework}_{int(datetime.now().timestamp())}",
            framework=framework,
            system_info=system_info,
            checks=checks,
            summary=summary,
            generated_at=datetime.now().isoformat(),
            profile=profile
        )
        
        log_operation_success(f"generate_compliance_report: {framework}", {
            "total_checks": len(checks),
            "passed": summary["passed"],
            "failed": summary["failed"],
            "compliance_score": summary["compliance_score"]
        })
        
        return report
    
    def _generate_summary(self, checks: List[ComplianceCheck]) -> Dict[str, Any]:
        """Generate summary statistics for the compliance report"""
        total = len(checks)
        passed = sum(1 for check in checks if check.status == "pass")
        failed = sum(1 for check in checks if check.status == "fail")
        errors = sum(1 for check in checks if check.status == "error")
        
        # Calculate compliance score
        compliance_score = (passed / total * 100) if total > 0 else 0
        
        # Categorize by severity
        severity_summary = {}
        for check in checks:
            severity = check.severity
            if severity not in severity_summary:
                severity_summary[severity] = {"total": 0, "passed": 0, "failed": 0, "errors": 0}
            
            severity_summary[severity]["total"] += 1
            if check.status == "pass":
                severity_summary[severity]["passed"] += 1
            elif check.status == "fail":
                severity_summary[severity]["failed"] += 1
            elif check.status == "error":
                severity_summary[severity]["errors"] += 1
        
        # Categorize by category
        category_summary = {}
        for check in checks:
            category = check.category
            if category not in category_summary:
                category_summary[category] = {"total": 0, "passed": 0, "failed": 0, "errors": 0}
            
            category_summary[category]["total"] += 1
            if check.status == "pass":
                category_summary[category]["passed"] += 1
            elif check.status == "fail":
                category_summary[category]["failed"] += 1
            elif check.status == "error":
                category_summary[category]["errors"] += 1
        
        return {
            "total_checks": total,
            "passed": passed,
            "failed": failed,
            "errors": errors,
            "compliance_score": round(compliance_score, 2),
            "severity_summary": severity_summary,
            "category_summary": category_summary
        }
    
    def export_report(self, report: ComplianceReport, output_path: str, format: str = "json") -> bool:
        """Export compliance report to file"""
        log_operation_start(f"export_report: {report.report_id}")
        
        try:
            report_data = asdict(report)
            
            if format.lower() == "json":
                with open(output_path, 'w') as f:
                    json.dump(report_data, f, indent=2)
            elif format.lower() == "yaml":
                with open(output_path, 'w') as f:
                    yaml.dump(report_data, f, indent=2)
            elif format.lower() == "html":
                self._export_html_report(report, output_path)
            else:
                raise ValueError(f"Unsupported format: {format}")
            
            log_operation_success(f"export_report: {report.report_id}", {"output_path": output_path})
            return True
            
        except Exception as e:
            log_operation_failure(f"export_report: {report.report_id}", str(e))
            return False
    
    def _export_html_report(self, report: ComplianceReport, output_path: str):
        """Export compliance report as HTML"""
        html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Albator Compliance Report - {framework}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .summary {{ background: #ecf0f1; padding: 15px; margin: 20px 0; border-radius: 5px; }}
        .check {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
        .pass {{ border-left: 5px solid #27ae60; }}
        .fail {{ border-left: 5px solid #e74c3c; }}
        .error {{ border-left: 5px solid #f39c12; }}
        .severity-critical {{ background: #fdf2f2; }}
        .severity-high {{ background: #fef9e7; }}
        .severity-medium {{ background: #f0f9ff; }}
        .severity-low {{ background: #f9f9f9; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background: #f2f2f2; }}
        .score {{ font-size: 2em; font-weight: bold; }}
        .pass-score {{ color: #27ae60; }}
        .fail-score {{ color: #e74c3c; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Albator Compliance Report</h1>
        <h2>{framework_name}</h2>
        <p>Generated: {generated_at}</p>
        <p>System: {hostname} ({macos_version})</p>
    </div>
    
    <div class="summary">
        <h3>Compliance Summary</h3>
        <div class="score {score_class}">{compliance_score}% Compliant</div>
        <p><strong>Total Checks:</strong> {total_checks}</p>
        <p><strong>Passed:</strong> {passed} | <strong>Failed:</strong> {failed} | <strong>Errors:</strong> {errors}</p>
    </div>
    
    <h3>System Information</h3>
    <table>
        <tr><th>Hostname</th><td>{hostname}</td></tr>
        <tr><th>macOS Version</th><td>{macos_version}</td></tr>
        <tr><th>Build</th><td>{macos_build}</td></tr>
        <tr><th>Hardware Model</th><td>{hardware_model}</td></tr>
        <tr><th>Serial Number</th><td>{serial_number}</td></tr>
        <tr><th>Scan Date</th><td>{scan_date}</td></tr>
    </table>
    
    <h3>Compliance Checks</h3>
    {checks_html}
    
    <h3>Summary by Category</h3>
    <table>
        <tr><th>Category</th><th>Total</th><th>Passed</th><th>Failed</th><th>Errors</th></tr>
        {category_rows}
    </table>
    
    <h3>Summary by Severity</h3>
    <table>
        <tr><th>Severity</th><th>Total</th><th>Passed</th><th>Failed</th><th>Errors</th></tr>
        {severity_rows}
    </table>
</body>
</html>"""
        
        # Generate checks HTML
        checks_html = ""
        for check in report.checks:
            status_class = check.status
            severity_class = f"severity-{check.severity}"
            
            checks_html += f"""
            <div class="check {status_class} {severity_class}">
                <h4>{check.check_id}: {check.title}</h4>
                <p><strong>Description:</strong> {check.description}</p>
                <p><strong>Category:</strong> {check.category} | <strong>Severity:</strong> {check.severity}</p>
                <p><strong>Status:</strong> {check.status.upper()}</p>
                <p><strong>Expected:</strong> {check.expected_result}</p>
                <p><strong>Actual:</strong> {check.actual_result}</p>
                {f'<p><strong>Error:</strong> {check.error_message}</p>' if check.error_message else ''}
                <p><strong>Remediation:</strong> {check.remediation}</p>
            </div>
            """
        
        # Generate category summary rows
        category_rows = ""
        for category, stats in report.summary["category_summary"].items():
            category_rows += f"""
            <tr>
                <td>{category}</td>
                <td>{stats['total']}</td>
                <td>{stats['passed']}</td>
                <td>{stats['failed']}</td>
                <td>{stats['errors']}</td>
            </tr>
            """
        
        # Generate severity summary rows
        severity_rows = ""
        for severity, stats in report.summary["severity_summary"].items():
            severity_rows += f"""
            <tr>
                <td>{severity.title()}</td>
                <td>{stats['total']}</td>
                <td>{stats['passed']}</td>
                <td>{stats['failed']}</td>
                <td>{stats['errors']}</td>
            </tr>
            """
        
        # Determine score class
        score_class = "pass-score" if report.summary["compliance_score"] >= 80 else "fail-score"
        
        # Format the HTML
        html_content = html_template.format(
            framework=report.framework,
            framework_name=self.frameworks[report.framework]["name"],
            generated_at=report.generated_at,
            hostname=report.system_info["hostname"],
            macos_version=report.system_info["macos_version"],
            macos_build=report.system_info["macos_build"],
            hardware_model=report.system_info["hardware_model"],
            serial_number=report.system_info["serial_number"],
            scan_date=report.system_info["scan_date"],
            compliance_score=report.summary["compliance_score"],
            score_class=score_class,
            total_checks=report.summary["total_checks"],
            passed=report.summary["passed"],
            failed=report.summary["failed"],
            errors=report.summary["errors"],
            checks_html=checks_html,
            category_rows=category_rows,
            severity_rows=severity_rows
        )
        
        with open(output_path, 'w') as f:
            f.write(html_content)
    
    def get_available_frameworks(self) -> List[str]:
        """Get list of available compliance frameworks"""
        return list(self.frameworks.keys())
    
    def get_framework_info(self, framework: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific framework"""
        return self.frameworks.get(framework)

def main():
    """Main function for compliance reporting"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Albator Compliance Reporter")
    parser.add_argument("--config", default="config/albator.yaml", help="Configuration file path")
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # List frameworks
    subparsers.add_parser("list", help="List available frameworks")
    
    # Generate report
    generate_parser = subparsers.add_parser("generate", help="Generate compliance report")
    generate_parser.add_argument("framework", choices=["nist_800_53", "cis_macos", "iso27001", "custom"])
    generate_parser.add_argument("--profile", default="basic", help="Security profile")
    generate_parser.add_argument("--output", help="Output file path")
    generate_parser.add_argument("--format", choices=["json", "yaml", "html"], default="json", help="Output format")
    
    # Framework info
    info_parser = subparsers.add_parser("info", help="Show framework information")
    info_parser.add_argument("framework", choices=["nist_800_53", "cis_macos", "iso27001", "custom"])
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize compliance reporter
    reporter = ComplianceReporter(args.config)
    
    if args.command == "list":
        frameworks = reporter.get_available_frameworks()
        print("Available Compliance Frameworks:")
        print("-" * 40)
        for framework in frameworks:
            info = reporter.get_framework_info(framework)
            print(f"{framework:15} - {info['name']} ({info['version']})")
    
    elif args.command == "generate":
        print(f"Generating {args.framework} compliance report...")
        
        try:
            report = reporter.generate_compliance_report(args.framework, args.profile)
            
            # Determine output path
            if args.output:
                output_path = args.output
            else:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                extension = args.format
                output_path = f"compliance_report_{args.framework}_{timestamp}.{extension}"
            
            # Export report
            success = reporter.export_report(report, output_path, args.format)
            
            if success:
                print(f"Report generated successfully: {output_path}")
                print(f"Compliance Score: {report.summary['compliance_score']}%")
                print(f"Checks: {report.summary['passed']}/{report.summary['total_checks']} passed")
            else:
                print("Failed to generate report")
                
        except Exception as e:
            print(f"Error generating report: {e}")
    
    elif args.command == "info":
        info = reporter.get_framework_info(args.framework)
        if info:
            print(f"Framework: {info['name']}")
]}
            print(f"Description: {info[\"description\"]}")
            print(f"Version: {info[\"version\"]}")
            print(f"Total Checks: {len(info[\"checks\"])}")
        else:
            print(f"Framework {args.framework} not found")

if __name__ == "__main__":
    main()
