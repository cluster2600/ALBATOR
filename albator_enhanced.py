#!/usr/bin/env python3
"""
Albator Enhanced CLI - Unified interface for all Albator features
Integrates legacy Python tools with new Bash scripts and enterprise features
"""

import os
import sys
import json
import argparse
import subprocess
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path

# Add lib directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'lib'))


def _fallback_logger(name: str):
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger


def _noop(*args, **kwargs):
    return None

try:
    from logger import get_logger, log_operation_start, log_operation_success, log_operation_failure
    from config_manager import ConfigurationManager
    from compliance_reporter import ComplianceReporter
    from analytics_dashboard import AnalyticsDashboard
    from fleet_manager import FleetManager
    from rollback import RollbackManager
    from cli_enhancements import AlbatorCompleter, CommandHistory, BatchProcessor, PluginManager
except ImportError as e:
    get_logger = _fallback_logger
    log_operation_start = _noop
    log_operation_success = _noop
    log_operation_failure = _noop
    ConfigurationManager = None
    ComplianceReporter = None
    AnalyticsDashboard = None
    FleetManager = None
    RollbackManager = None
    AlbatorCompleter = None
    CommandHistory = None
    BatchProcessor = None
    PluginManager = None
    print(f"Warning: Optional enhanced modules unavailable: {e}")
    print("Only core script orchestration features will be available.")

class AlbatorEnhanced:
    """Enhanced Albator CLI with integrated features"""
    
    def __init__(self, config_path: str = "config/albator.yaml"):
        """Initialize the enhanced Albator CLI"""
        self.config_path = config_path
        self.logger = get_logger("albator_enhanced")
        
        # Initialize managers
        try:
            self.config_manager = ConfigurationManager(config_path) if ConfigurationManager else None
            self.compliance_reporter = ComplianceReporter(config_path) if ComplianceReporter else None
            self.analytics_dashboard = AnalyticsDashboard() if AnalyticsDashboard else None
            self.fleet_manager = FleetManager(config_path) if FleetManager else None
            self.rollback_manager = RollbackManager() if RollbackManager else None
            
            # Initialize CLI enhancement components
            self.command_history = CommandHistory() if CommandHistory else None
            self.batch_processor = BatchProcessor() if BatchProcessor else None
            self.plugin_manager = PluginManager() if PluginManager else None
        except Exception as e:
            print(f"Warning: Could not initialize all managers: {e}")
            self.config_manager = None
            self.compliance_reporter = None
            self.analytics_dashboard = None
            self.fleet_manager = None
            self.rollback_manager = None
            self.command_history = None
            self.batch_processor = None
            self.plugin_manager = None
    
    def run_hardening_script(self, script_name: str, profile: str = "basic", 
                           dry_run: bool = False, test: bool = False) -> bool:
        """Run a hardening script with enhanced options"""
        if self.logger:
            log_operation_start(f"run_hardening_script: {script_name}")
        
        script_path = f"./{script_name}.sh"
        if not os.path.exists(script_path):
            print(f"Error: Script {script_path} not found")
            return False
        
        # Build command
        cmd = [script_path]
        
        if dry_run:
            cmd.append("--dry-run")
        
        if test:
            cmd.append("--test")
        
        # Set environment variables for profile
        env = os.environ.copy()
        env["ALBATOR_PROFILE"] = profile
        
        try:
            print(f"Running {script_name} hardening (profile: {profile})...")
            result = subprocess.run(cmd, env=env, capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"✅ {script_name} hardening completed successfully")
                if self.logger:
                    log_operation_success(f"run_hardening_script: {script_name}")
                return True
            else:
                print(f"❌ {script_name} hardening failed:")
                print(result.stderr)
                if self.logger:
                    log_operation_failure(f"run_hardening_script: {script_name}", result.stderr)
                return False
                
        except Exception as e:
            print(f"Error running {script_name}: {e}")
            if self.logger:
                log_operation_failure(f"run_hardening_script: {script_name}", str(e))
            return False
    
    def run_comprehensive_hardening(self, profile: str = "basic", 
                                  dry_run: bool = False, 
                                  generate_report: bool = True) -> bool:
        """Run comprehensive hardening across all areas"""
        print(f"🚀 Starting comprehensive hardening (profile: {profile})")
        print("=" * 60)
        
        # Define hardening scripts in order
        scripts = [
            "privacy",
            "firewall", 
            "encryption",
            "app_security"
        ]
        
        success_count = 0
        total_scripts = len(scripts)
        
        # Create rollback point before starting
        if self.rollback_manager and not dry_run:
            rollback_id = self.rollback_manager.create_rollback_point(
                "comprehensive_hardening",
                f"Before comprehensive hardening with {profile} profile"
            )
            print(f"📝 Created rollback point: {rollback_id}")
        
        # Run each script
        for script in scripts:
            print(f"\n🔧 Running {script} hardening...")
            if self.run_hardening_script(script, profile, dry_run):
                success_count += 1
            else:
                print(f"⚠️  {script} hardening had issues")
        
        # Summary
        print(f"\n📊 Hardening Summary:")
        print(f"   Successful: {success_count}/{total_scripts}")
        print(f"   Profile: {profile}")
        print(f"   Dry Run: {dry_run}")
        
        # Generate compliance report if requested
        if generate_report and not dry_run and self.compliance_reporter:
            print(f"\n📋 Generating compliance report...")
            try:
                report = self.compliance_reporter.generate_compliance_report("custom", profile)
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                report_path = f"compliance_report_{timestamp}.html"
                
                if self.compliance_reporter.export_report(report, report_path, "html"):
                    print(f"✅ Compliance report generated: {report_path}")
                    
                    # Record in analytics if available
                    if self.analytics_dashboard:
                        self.analytics_dashboard.record_compliance_report(report)
                        print("📈 Report recorded in analytics database")
                
            except Exception as e:
                print(f"⚠️  Could not generate compliance report: {e}")
        
        return success_count == total_scripts
    
    def generate_security_dashboard(self, output_path: str = None, days: int = 30) -> bool:
        """Generate comprehensive security dashboard"""
        if not self.analytics_dashboard:
            print("❌ Analytics dashboard not available")
            return False
        
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"security_dashboard_{timestamp}.html"
        
        print(f"📊 Generating security dashboard...")
        
        try:
            success = self.analytics_dashboard.generate_security_dashboard(output_path, days=days)
            
            if success:
                print(f"✅ Security dashboard generated: {output_path}")
                return True
            else:
                print("❌ Failed to generate security dashboard")
                return False
                
        except Exception as e:
            print(f"❌ Error generating dashboard: {e}")
            return False
    
    def manage_profiles(self, action: str, profile_name: str = None, **kwargs) -> bool:
        """Manage security profiles"""
        if not self.config_manager:
            print("❌ Configuration manager not available")
            return False
        
        try:
            if action == "list":
                profiles = self.config_manager.list_profiles()
                print("📋 Available Security Profiles:")
                print("-" * 40)
                for profile in profiles:
                    info = self.config_manager.get_profile_info(profile)
                    print(f"  {profile:15} - {info.get('description', 'No description')}")
                    print(f"                  Security Level: {info.get('security_level', 'Unknown')}%")
                return True
                
            elif action == "create" and profile_name:
                success = self.config_manager.create_profile(profile_name, kwargs)
                if success:
                    print(f"✅ Profile '{profile_name}' created successfully")
                else:
                    print(f"❌ Failed to create profile '{profile_name}'")
                return success
                
            elif action == "delete" and profile_name:
                success = self.config_manager.delete_profile(profile_name)
                if success:
                    print(f"✅ Profile '{profile_name}' deleted successfully")
                else:
                    print(f"❌ Failed to delete profile '{profile_name}'")
                return success
                
            elif action == "info" and profile_name:
                info = self.config_manager.get_profile_info(profile_name)
                if info:
                    print(f"📋 Profile Information: {profile_name}")
                    print("-" * 40)
                    for key, value in info.items():
                        print(f"  {key:20}: {value}")
                else:
                    print(f"❌ Profile '{profile_name}' not found")
                return info is not None
                
            else:
                print(f"❌ Invalid action or missing profile name")
                return False
                
        except Exception as e:
            print(f"❌ Error managing profiles: {e}")
            return False
    
    def manage_fleet(self, action: str, **kwargs) -> bool:
        """Manage fleet operations"""
        if not self.fleet_manager:
            print("❌ Fleet manager not available")
            return False
        
        try:
            if action == "list":
                hosts = self.fleet_manager.list_hosts()
                print("🖥️  Fleet Systems:")
                print("-" * 50)
                for host_id, host_info in hosts.items():
                    status = "🟢 Online" if host_info.get('status') == 'online' else "🔴 Offline"
                    print(f"  {host_id:20} {status}")
                    print(f"                       {host_info.get('hostname', 'Unknown')}")
                return True
                
            elif action == "add":
                host_id = kwargs.get('host_id')
                hostname = kwargs.get('hostname')
                if host_id and hostname:
                    success = self.fleet_manager.add_host(host_id, hostname, kwargs)
                    if success:
                        print(f"✅ Host '{host_id}' added to fleet")
                    else:
                        print(f"❌ Failed to add host '{host_id}'")
                    return success
                else:
                    print("❌ Host ID and hostname required")
                    return False
                    
            elif action == "remove":
                host_id = kwargs.get('host_id')
                if host_id:
                    success = self.fleet_manager.remove_host(host_id)
                    if success:
                        print(f"✅ Host '{host_id}' removed from fleet")
                    else:
                        print(f"❌ Failed to remove host '{host_id}'")
                    return success
                else:
                    print("❌ Host ID required")
                    return False
                    
            elif action == "deploy":
                profile = kwargs.get('profile', 'basic')
                print(f"🚀 Deploying Albator to fleet (profile: {profile})...")
                results = self.fleet_manager.deploy_to_fleet(profile)
                
                success_count = sum(1 for result in results.values() if result.get('success'))
                total_count = len(results)
                
                print(f"📊 Deployment Results: {success_count}/{total_count} successful")
                
                for host_id, result in results.items():
                    status = "✅" if result.get('success') else "❌"
                    print(f"  {status} {host_id}: {result.get('message', 'No message')}")
                
                return success_count == total_count
                
            else:
                print(f"❌ Invalid fleet action: {action}")
                return False
                
        except Exception as e:
            print(f"❌ Error managing fleet: {e}")
            return False
    
    def manage_rollbacks(self, action: str, rollback_id: str = None, **kwargs) -> bool:
        """Manage rollback operations"""
        if not self.rollback_manager:
            print("❌ Rollback manager not available")
            return False
        
        try:
            if action == "list":
                rollbacks = self.rollback_manager.list_rollback_points()
                print("🔄 Available Rollback Points:")
                print("-" * 60)
                for rollback in rollbacks:
                    print(f"  {rollback['id']:20} {rollback['timestamp']}")
                    print(f"                       {rollback['description']}")
                return True
                
            elif action == "create":
                description = kwargs.get('description', 'Manual rollback point')
                rollback_id = self.rollback_manager.create_rollback_point("manual", description)
                if rollback_id:
                    print(f"✅ Rollback point created: {rollback_id}")
                else:
                    print("❌ Failed to create rollback point")
                return rollback_id is not None
                
            elif action == "restore" and rollback_id:
                dry_run = kwargs.get('dry_run', False)
                success = self.rollback_manager.rollback_to_point(rollback_id, dry_run)
                if success:
                    action_text = "Would restore" if dry_run else "Restored"
                    print(f"✅ {action_text} to rollback point: {rollback_id}")
                else:
                    print(f"❌ Failed to restore rollback point: {rollback_id}")
                return success
                
            elif action == "cleanup":
                keep_count = kwargs.get('keep', 5)
                cleaned = self.rollback_manager.cleanup_old_rollbacks(keep_count)
                print(f"✅ Cleaned up {cleaned} old rollback points (kept {keep_count})")
                return True
                
            else:
                print(f"❌ Invalid rollback action or missing rollback ID")
                return False
                
        except Exception as e:
            print(f"❌ Error managing rollbacks: {e}")
            return False
    
    def run_compliance_scan(self, framework: str = "custom", profile: str = "basic", 
                          output_format: str = "html") -> bool:
        """Run compliance scan and generate report"""
        if not self.compliance_reporter:
            print("❌ Compliance reporter not available")
            return False
        
        print(f"🔍 Running {framework} compliance scan...")
        
        try:
            report = self.compliance_reporter.generate_compliance_report(framework, profile)
            
            # Generate output filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"compliance_report_{framework}_{timestamp}.{output_format}"
            
            # Export report
            success = self.compliance_reporter.export_report(report, output_path, output_format)
            
            if success:
                print(f"✅ Compliance report generated: {output_path}")
                print(f"📊 Compliance Score: {report.summary['compliance_score']:.1f}%")
                print(f"📋 Checks: {report.summary['passed']}/{report.summary['total_checks']} passed")
                
                # Record in analytics
                if self.analytics_dashboard:
                    self.analytics_dashboard.record_compliance_report(report)
                    print("📈 Report recorded in analytics database")
                
                return True
            else:
                print("❌ Failed to export compliance report")
                return False
                
        except Exception as e:
            print(f"❌ Error running compliance scan: {e}")
            return False

def create_parser():
    """Create the argument parser"""
    parser = argparse.ArgumentParser(
        description="Albator Enhanced - Unified macOS Security Hardening Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run comprehensive hardening
  python3 albator_enhanced.py harden --profile advanced --report

  # Generate security dashboard
  python3 albator_enhanced.py dashboard --days 30

  # Manage security profiles
  python3 albator_enhanced.py profile list
  python3 albator_enhanced.py profile create custom_profile

  # Fleet management
  python3 albator_enhanced.py fleet list
  python3 albator_enhanced.py fleet deploy --profile enterprise

  # Compliance scanning
  python3 albator_enhanced.py compliance --framework nist_800_53 --format html

  # Rollback management
  python3 albator_enhanced.py rollback list
  python3 albator_enhanced.py rollback restore <rollback_id>
        """
    )
    
    parser.add_argument("--config", default="config/albator.yaml", 
                       help="Configuration file path")
    parser.add_argument("--verbose", "-v", action="store_true", 
                       help="Enable verbose output")
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Hardening command
    harden_parser = subparsers.add_parser("harden", help="Run security hardening")
    harden_parser.add_argument("--profile", default="basic", 
                              choices=["basic", "advanced", "enterprise"],
                              help="Security profile to use")
    harden_parser.add_argument("--script", help="Run specific script only")
    harden_parser.add_argument("--dry-run", action="store_true", 
                              help="Show what would be done without making changes")
    harden_parser.add_argument("--no-report", action="store_true", 
                              help="Skip compliance report generation")
    
    # Dashboard command
    dashboard_parser = subparsers.add_parser("dashboard", help="Generate security dashboard")
    dashboard_parser.add_argument("--output", help="Output file path")
    dashboard_parser.add_argument("--days", type=int, default=30, 
                                 help="Days of data to include")
    
    # Profile management
    profile_parser = subparsers.add_parser("profile", help="Manage security profiles")
    profile_subparsers = profile_parser.add_subparsers(dest="profile_action")
    
    profile_subparsers.add_parser("list", help="List available profiles")
    
    profile_create = profile_subparsers.add_parser("create", help="Create new profile")
    profile_create.add_argument("name", help="Profile name")
    profile_create.add_argument("--description", help="Profile description")
    profile_create.add_argument("--security-level", type=int, help="Security level (0-100)")
    
    profile_delete = profile_subparsers.add_parser("delete", help="Delete profile")
    profile_delete.add_argument("name", help="Profile name")
    
    profile_info = profile_subparsers.add_parser("info", help="Show profile information")
    profile_info.add_argument("name", help="Profile name")
    
    # Fleet management
    fleet_parser = subparsers.add_parser("fleet", help="Manage fleet operations")
    fleet_subparsers = fleet_parser.add_subparsers(dest="fleet_action")
    
    fleet_subparsers.add_parser("list", help="List fleet systems")
    
    fleet_add = fleet_subparsers.add_parser("add", help="Add system to fleet")
    fleet_add.add_argument("host_id", help="Host identifier")
    fleet_add.add_argument("hostname", help="Hostname or IP address")
    fleet_add.add_argument("--username", help="SSH username")
    fleet_add.add_argument("--key-path", help="SSH key path")
    
    fleet_remove = fleet_subparsers.add_parser("remove", help="Remove system from fleet")
    fleet_remove.add_argument("host_id", help="Host identifier")
    
    fleet_deploy = fleet_subparsers.add_parser("deploy", help="Deploy to fleet")
    fleet_deploy.add_argument("--profile", default="basic", help="Security profile")
    
    # Compliance scanning
    compliance_parser = subparsers.add_parser("compliance", help="Run compliance scan")
    compliance_parser.add_argument("--framework", default="custom",
                                  choices=["nist_800_53", "cis_macos", "iso27001", "custom"],
                                  help="Compliance framework")
    compliance_parser.add_argument("--profile", default="basic", help="Security profile")
    compliance_parser.add_argument("--format", default="html", 
                                  choices=["html", "json", "yaml"],
                                  help="Output format")
    
    # Rollback management
    rollback_parser = subparsers.add_parser("rollback", help="Manage rollbacks")
    rollback_subparsers = rollback_parser.add_subparsers(dest="rollback_action")
    
    rollback_subparsers.add_parser("list", help="List rollback points")
    
    rollback_create = rollback_subparsers.add_parser("create", help="Create rollback point")
    rollback_create.add_argument("--description", help="Rollback description")
    
    rollback_restore = rollback_subparsers.add_parser("restore", help="Restore rollback point")
    rollback_restore.add_argument("rollback_id", help="Rollback point ID")
    rollback_restore.add_argument("--dry-run", action="store_true", help="Dry run mode")
    
    rollback_cleanup = rollback_subparsers.add_parser("cleanup", help="Cleanup old rollbacks")
    rollback_cleanup.add_argument("--keep", type=int, default=5, help="Number to keep")
    
    # Interactive shell command
    shell_parser = subparsers.add_parser("shell", help="Launch interactive shell")
    
    # Batch processing command
    batch_parser = subparsers.add_parser("batch", help="Execute batch operations")
    batch_parser.add_argument("file", help="Batch file containing commands")
    batch_parser.add_argument("--validate", action="store_true", help="Validate batch file only")
    batch_parser.add_argument("--continue-on-error", action="store_true", 
                             help="Continue execution even if a command fails")
    
    # Plugin management
    plugin_parser = subparsers.add_parser("plugin", help="Manage plugins")
    plugin_subparsers = plugin_parser.add_subparsers(dest="plugin_action")
    
    plugin_subparsers.add_parser("list", help="List installed plugins")
    
    plugin_install = plugin_subparsers.add_parser("install", help="Install a plugin")
    plugin_install.add_argument("name", help="Plugin name")
    plugin_install.add_argument("source", help="Plugin source URL or path")
    plugin_install.add_argument("--version", default="latest", help="Plugin version")
    
    plugin_enable = plugin_subparsers.add_parser("enable", help="Enable a plugin")
    plugin_enable.add_argument("name", help="Plugin name")
    
    plugin_disable = plugin_subparsers.add_parser("disable", help="Disable a plugin")
    plugin_disable.add_argument("name", help="Plugin name")
    
    # Setup auto-completion command
    subparsers.add_parser("setup-completion", help="Setup bash auto-completion")
    
    return parser

def main():
    """Main function"""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize Albator Enhanced
    albator = AlbatorEnhanced(args.config)
    
    # Handle commands
    success = False
    
    if args.command == "harden":
        if args.script:
            success = albator.run_hardening_script(
                args.script, 
                args.profile, 
                args.dry_run
            )
        else:
            success = albator.run_comprehensive_hardening(
                args.profile,
                args.dry_run,
                not args.no_report
            )
    
    elif args.command == "dashboard":
        success = albator.generate_security_dashboard(args.output, args.days)
    
    elif args.command == "profile":
        if args.profile_action == "list":
            success = albator.manage_profiles("list")
        elif args.profile_action == "create":
            kwargs = {}
            if args.description:
                kwargs['description'] = args.description
            if args.security_level:
                kwargs['security_level'] = args.security_level
            success = albator.manage_profiles("create", args.name, **kwargs)
        elif args.profile_action == "delete":
            success = albator.manage_profiles("delete", args.name)
        elif args.profile_action == "info":
            success = albator.manage_profiles("info", args.name)
    
    elif args.command == "fleet":
        if args.fleet_action == "list":
            success = albator.manage_fleet("list")
        elif args.fleet_action == "add":
            kwargs = {
                'host_id': args.host_id,
                'hostname': args.hostname
            }
            if args.username:
                kwargs['username'] = args.username
            if args.key_path:
                kwargs['key_path'] = args.key_path
            success = albator.manage_fleet("add", **kwargs)
        elif args.fleet_action == "remove":
            success = albator.manage_fleet("remove", host_id=args.host_id)
        elif args.fleet_action == "deploy":
            success = albator.manage_fleet("deploy", profile=args.profile)
    
    elif args.command == "compliance":
        success = albator.run_compliance_scan(
            args.framework,
            args.profile,
            args.format
        )
    
    elif args.command == "rollback":
        if args.rollback_action == "list":
            success = albator.manage_rollbacks("list")
        elif args.rollback_action == "create":
            kwargs = {}
            if args.description:
                kwargs['description'] = args.description
            success = albator.manage_rollbacks("create", **kwargs)
        elif args.rollback_action == "restore":
            success = albator.manage_rollbacks(
                "restore", 
                args.rollback_id,
                dry_run=args.dry_run
            )
        elif args.rollback_action == "cleanup":
            success = albator.manage_rollbacks("cleanup", keep=args.keep)
    
    elif args.command == "shell":
        # Launch interactive shell
        try:
            from cli_enhancements import InteractiveShell
            shell = InteractiveShell()
            shell.cmdloop()
            success = True
        except ImportError:
            print("❌ Interactive shell not available. Please ensure cli_enhancements module is installed.")
            success = False
        except KeyboardInterrupt:
            print("\n✅ Exiting interactive shell.")
            success = True
    
    elif args.command == "batch":
        # Execute batch operations
        if not albator.batch_processor:
            print("❌ Batch processor not available")
            success = False
        else:
            if args.validate:
                success = albator.batch_processor.validate_batch_file(args.file)
                if success:
                    print("✅ Batch file is valid")
                else:
                    print("❌ Batch file validation failed")
            else:
                results = albator.batch_processor.execute_batch(
                    args.file,
                    continue_on_error=args.continue_on_error
                )
                successful = sum(1 for r in results if r['success'])
                total = len(results)
                print(f"\n📊 Batch Execution Summary: {successful}/{total} commands successful")
                success = successful == total
    
    elif args.command == "plugin":
        # Manage plugins
        if not albator.plugin_manager:
            print("❌ Plugin manager not available")
            success = False
        else:
            if args.plugin_action == "list":
                plugins = albator.plugin_manager.list_plugins()
                if plugins:
                    print("🔌 Installed Plugins:")
                    for plugin in plugins:
                        status = "✅ Enabled" if plugin['enabled'] else "❌ Disabled"
                        print(f"  {plugin['name']} v{plugin['version']} - {status}")
                else:
                    print("No plugins installed")
                success = True
            elif args.plugin_action == "install":
                success = albator.plugin_manager.install_plugin(
                    args.name,
                    args.source,
                    args.version
                )
                if success:
                    print(f"✅ Plugin '{args.name}' installed successfully")
                else:
                    print(f"❌ Failed to install plugin '{args.name}'")
            elif args.plugin_action == "enable":
                success = albator.plugin_manager.enable_plugin(args.name)
                if success:
                    print(f"✅ Plugin '{args.name}' enabled")
                else:
                    print(f"❌ Plugin '{args.name}' not found")
            elif args.plugin_action == "disable":
                success = albator.plugin_manager.disable_plugin(args.name)
                if success:
                    print(f"✅ Plugin '{args.name}' disabled")
                else:
                    print(f"❌ Plugin '{args.name}' not found")
    
    elif args.command == "setup-completion":
        # Setup bash auto-completion
        try:
            from cli_enhancements import setup_cli_completion
            setup_cli_completion()
            success = True
        except ImportError:
            print("❌ CLI enhancements module not available")
            success = False
        except Exception as e:
            print(f"❌ Failed to setup completion: {e}")
            success = False
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
