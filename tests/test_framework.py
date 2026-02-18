#!/usr/bin/env python3
"""
Albator Testing Framework
Comprehensive testing system for validating security hardening operations
"""

import os
import sys
import subprocess
import yaml
import json
import time
import logging
from typing import Dict, List, Any, Tuple, Optional
from pathlib import Path

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from preflight import run_preflight

try:
    # Add lib directory to path for imports when available in legacy layouts.
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lib'))
    from logger import get_logger, log_operation_start, log_operation_success, log_operation_failure
except Exception:
    def get_logger(name: str):
        logger = logging.getLogger(name)
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        return logger

    def log_operation_start(name: str):
        logging.getLogger("test_framework").info("START: %s", name)

    def log_operation_success(name: str, details: Any = None):
        logging.getLogger("test_framework").info("SUCCESS: %s %s", name, details or "")

    def log_operation_failure(name: str, message: str, details: Any = None):
        logging.getLogger("test_framework").error("FAIL: %s %s %s", name, message, details or "")

class TestResult:
    """Represents the result of a test"""
    
    def __init__(self, test_name: str, passed: bool, message: str = "", details: Dict = None):
        self.test_name = test_name
        self.passed = passed
        self.message = message
        self.details = details or {}
        self.timestamp = time.time()

class AlbatorTestFramework:
    """Main testing framework for Albator"""
    
    def __init__(self, config_path: str = "config/albator.yaml"):
        """Initialize the test framework"""
        self.logger = get_logger("test_framework")
        self.config = self._load_config(config_path)
        self.results: List[TestResult] = []
        self.backup_location = "/tmp/albator_test_backup"
        
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            self.logger.warning(f"Config file {config_path} not found, using defaults")
            return {}
        except Exception as e:
            self.logger.error(f"Error loading config: {e}")
            return {}
    
    def run_command(self, command: str, timeout: int = 30) -> Tuple[bool, str, str]:
        """Run a shell command and return success, stdout, stderr"""
        try:
            result = subprocess.run(
                command, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=timeout
            )
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", f"Command timed out after {timeout} seconds"
        except Exception as e:
            return False, "", str(e)
    
    def verify_setting(self, check_command: str, expected_output: str, test_name: str) -> TestResult:
        """Verify a system setting matches expected output"""
        log_operation_start(f"verify_setting: {test_name}")
        
        success, stdout, stderr = self.run_command(check_command)
        
        if not success:
            result = TestResult(test_name, False, f"Command failed: {stderr}")
            log_operation_failure(f"verify_setting: {test_name}", stderr)
            return result
        
        # Check if expected output is in stdout
        if expected_output.lower() in stdout.lower():
            result = TestResult(test_name, True, "Setting verified successfully")
            log_operation_success(f"verify_setting: {test_name}")
        else:
            result = TestResult(
                test_name, 
                False, 
                f"Expected '{expected_output}' not found in output: {stdout}"
            )
            log_operation_failure(f"verify_setting: {test_name}", f"Expected '{expected_output}', got '{stdout}'")
        
        return result
    
    def test_firewall_configuration(self) -> List[TestResult]:
        """Test firewall configuration"""
        tests = []
        
        # Test firewall is enabled
        tests.append(self.verify_setting(
            "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate",
            "enabled",
            "firewall_enabled"
        ))
        
        # Test stealth mode is enabled
        tests.append(self.verify_setting(
            "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode",
            "enabled",
            "firewall_stealth_mode"
        ))
        
        # Test block all incoming is enabled
        tests.append(self.verify_setting(
            "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getblockall",
            "enabled",
            "firewall_block_all"
        ))
        
        # Test logging is enabled
        tests.append(self.verify_setting(
            "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getloggingmode",
            "enabled",
            "firewall_logging"
        ))
        
        return tests
    
    def test_privacy_settings(self) -> List[TestResult]:
        """Test privacy configuration"""
        tests = []
        
        # Test diagnostic reports disabled
        tests.append(self.verify_setting(
            "sudo defaults read /Library/Preferences/com.apple.SubmitDiagInfo AutoSubmit",
            "0",
            "privacy_diagnostic_reports"
        ))
        
        # Test Siri analytics disabled
        tests.append(self.verify_setting(
            "defaults read com.apple.assistant.analytics AnalyticsEnabled",
            "0",
            "privacy_siri_analytics"
        ))
        
        # Test Safari search suggestions disabled
        tests.append(self.verify_setting(
            "defaults read com.apple.Safari SuppressSearchSuggestions",
            "1",
            "privacy_safari_suggestions"
        ))
        
        # Test remote login disabled
        tests.append(self.verify_setting(
            "sudo systemsetup -getremotelogin",
            "off",
            "privacy_remote_login"
        ))
        
        return tests
    
    def test_encryption_settings(self) -> List[TestResult]:
        """Test encryption configuration"""
        tests = []
        
        # Test FileVault status
        tests.append(self.verify_setting(
            "diskutil apfs list",
            "FileVault: Yes",
            "encryption_filevault"
        ))
        
        return tests
    
    def test_app_security_settings(self) -> List[TestResult]:
        """Test application security configuration"""
        tests = []
        
        # Test Gatekeeper is enabled
        tests.append(self.verify_setting(
            "spctl --status",
            "assessments enabled",
            "app_security_gatekeeper"
        ))
        
        # Test Safari hardened runtime
        tests.append(self.verify_setting(
            "codesign -dv --verbose /Applications/Safari.app 2>&1",
            "hardened",
            "app_security_safari_hardened"
        ))
        
        return tests
    
    def test_system_integrity(self) -> List[TestResult]:
        """Test system integrity and dependencies"""
        tests = []
        
        # Test required dependencies
        required_deps = self.config.get('dependencies', {}).get('required', ['curl', 'jq'])
        for dep in required_deps:
            tests.append(self.verify_setting(
                f"which {dep}",
                f"/{dep}",  # Should contain the path to the binary
                f"dependency_{dep}"
            ))
        
        # Test macOS version against configured minimum policy.
        min_version = str(self.config.get('preflight', {}).get('min_macos_version', '26.3'))
        expected_major = min_version.split('.')[0]
        tests.append(self.verify_setting(
            "sw_vers -productVersion",
            expected_major,
            "macos_version"
        ))
        
        return tests
    
    def run_script_test(self, script_path: str, script_name: str) -> TestResult:
        """Run a hardening script and verify it completes successfully"""
        log_operation_start(f"script_test: {script_name}")
        
        if not os.path.exists(script_path):
            result = TestResult(script_name, False, f"Script not found: {script_path}")
            log_operation_failure(f"script_test: {script_name}", f"Script not found: {script_path}")
            return result
        
        # Run the script
        success, stdout, stderr = self.run_command(f"bash {script_path}", timeout=60)
        
        if success:
            result = TestResult(script_name, True, "Script executed successfully", {"stdout": stdout})
            log_operation_success(f"script_test: {script_name}")
        else:
            result = TestResult(script_name, False, f"Script failed: {stderr}", {"stdout": stdout, "stderr": stderr})
            log_operation_failure(f"script_test: {script_name}", stderr)
        
        return result
    
    def run_all_tests(self, include_scripts: bool = False) -> Dict[str, Any]:
        """Run all tests and return comprehensive results"""
        log_operation_start("run_all_tests")
        
        self.results.clear()
        preflight_summary = run_preflight(require_sudo=False, require_rules=False)
        
        # System integrity tests
        self.logger.info("Running system integrity tests...")
        self.results.extend(self.test_system_integrity())
        
        # Firewall tests
        self.logger.info("Running firewall tests...")
        self.results.extend(self.test_firewall_configuration())
        
        # Privacy tests
        self.logger.info("Running privacy tests...")
        self.results.extend(self.test_privacy_settings())
        
        # Encryption tests
        self.logger.info("Running encryption tests...")
        self.results.extend(self.test_encryption_settings())
        
        # App security tests
        self.logger.info("Running app security tests...")
        self.results.extend(self.test_app_security_settings())
        
        # Script execution tests (optional)
        if include_scripts:
            self.logger.info("Running script execution tests...")
            scripts = [
                ("privacy.sh", "privacy_script"),
                ("firewall.sh", "firewall_script"),
                ("app_security.sh", "app_security_script"),
                ("cve_fetch.sh", "cve_fetch_script"),
                ("apple_updates.sh", "apple_updates_script")
            ]
            
            for script_file, script_name in scripts:
                self.results.append(self.run_script_test(script_file, script_name))
        
        # Generate summary
        total_tests = len(self.results)
        passed_tests = sum(1 for r in self.results if r.passed)
        failed_tests = total_tests - passed_tests
        
        summary = {
            "total_tests": total_tests,
            "passed": passed_tests,
            "failed": failed_tests,
            "success_rate": (passed_tests / total_tests * 100) if total_tests > 0 else 0,
            "preflight": preflight_summary,
            "results": [
                {
                    "test_name": r.test_name,
                    "passed": r.passed,
                    "message": r.message,
                    "details": r.details,
                    "timestamp": r.timestamp
                }
                for r in self.results
            ]
        }
        
        if failed_tests == 0:
            log_operation_success("run_all_tests", {"total": total_tests, "passed": passed_tests})
        else:
            log_operation_failure("run_all_tests", f"{failed_tests} tests failed", {"total": total_tests, "failed": failed_tests})
        
        return summary
    
    def generate_report(self, output_file: str = "test_report.json"):
        """Generate a detailed test report"""
        summary = self.run_all_tests()
        
        # Write JSON report
        with open(output_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        # Print summary to console
        print(f"\n{'='*60}")
        print("ALBATOR TEST REPORT")
        print(f"{'='*60}")
        print(f"Total Tests: {summary['total_tests']}")
        print(f"Passed: {summary['passed']}")
        print(f"Failed: {summary['failed']}")
        print(f"Success Rate: {summary['success_rate']:.1f}%")
        print(
            "Preflight: "
            f"{'PASS' if summary['preflight']['passed'] else 'FAIL'} "
            f"(required failures: {summary['preflight']['failed_required_count']}, "
            f"warnings: {summary['preflight']['warning_count']})"
        )
        print(f"{'='*60}")
        
        # Print failed tests
        failed_results = [r for r in self.results if not r.passed]
        if failed_results:
            print("\nFAILED TESTS:")
            print("-" * 40)
            for result in failed_results:
                print(f"❌ {result.test_name}: {result.message}")
        
        # Print passed tests
        passed_results = [r for r in self.results if r.passed]
        if passed_results:
            print(f"\nPASSED TESTS ({len(passed_results)}):")
            print("-" * 40)
            for result in passed_results:
                print(f"✅ {result.test_name}")
        
        print(f"\nDetailed report saved to: {output_file}")
        return summary

def main():
    """Main function for running tests"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Albator Test Framework")
    parser.add_argument("--config", default="config/albator.yaml", help="Configuration file path")
    parser.add_argument("--output", default="test_report.json", help="Output report file")
    parser.add_argument("--include-scripts", action="store_true", help="Include script execution tests")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Initialize test framework
    framework = AlbatorTestFramework(args.config)
    
    if args.verbose:
        framework.logger.setLevel("DEBUG")
    
    # Run tests and generate report
    try:
        summary = framework.generate_report(args.output)
        
        # Exit with appropriate code
        if summary['failed'] > 0:
            sys.exit(1)
        else:
            sys.exit(0)
            
    except Exception as e:
        framework.logger.error(f"Test framework error: {e}")
        sys.exit(2)

if __name__ == "__main__":
    main()
