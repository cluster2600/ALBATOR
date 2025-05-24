#!/usr/bin/env python3
"""
Albator Configuration Manager
Handles profile-based configuration and settings management
"""

import os
import sys
import yaml
import json
from typing import Dict, List, Any, Optional, Union
from pathlib import Path

# Add lib directory to path for imports
sys.path.insert(0, os.path.dirname(__file__))
from logger import get_logger, log_operation_start, log_operation_success, log_operation_failure

class ConfigurationManager:
    """Manages Albator configuration profiles and settings"""
    
    def __init__(self, config_path: str = "config/albator.yaml"):
        """Initialize the configuration manager"""
        self.logger = get_logger("config_manager")
        self.config_path = config_path
        self.config = self._load_config()
        self.current_profile = "basic"  # Default profile
        
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            if not os.path.exists(self.config_path):
                self.logger.warning(f"Config file {self.config_path} not found, creating default")
                return self._create_default_config()
            
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
                self.logger.info(f"Configuration loaded from {self.config_path}")
                return config
                
        except Exception as e:
            self.logger.error(f"Error loading config: {e}")
            return self._create_default_config()
    
    def _create_default_config(self) -> Dict[str, Any]:
        """Create default configuration"""
        default_config = {
            "global": {
                "log_level": "INFO",
                "log_file": "/var/log/albator.log",
                "backup_settings": True,
                "dry_run": False,
                "progress_indicators": True
            },
            "profiles": {
                "basic": {
                    "description": "Basic security hardening for general users",
                    "firewall": {"enabled": True, "stealth_mode": True, "logging": True},
                    "privacy": {"disable_telemetry": True, "disable_siri_analytics": True},
                    "encryption": {"filevault": False},
                    "app_security": {"gatekeeper": True, "verify_hardened_runtime": True}
                },
                "advanced": {
                    "description": "Advanced security hardening for power users",
                    "firewall": {"enabled": True, "stealth_mode": True, "logging": True},
                    "privacy": {"disable_telemetry": True, "disable_siri_analytics": True, "disable_smb": True},
                    "encryption": {"filevault": True},
                    "app_security": {"gatekeeper": True, "verify_hardened_runtime": True}
                },
                "enterprise": {
                    "description": "Enterprise-grade security hardening",
                    "firewall": {"enabled": True, "stealth_mode": True, "logging": True, "advanced_logging": True},
                    "privacy": {"disable_telemetry": True, "disable_siri_analytics": True, "disable_smb": True, "disable_bluetooth": True},
                    "encryption": {"filevault": True, "secure_recovery_key": True},
                    "app_security": {"gatekeeper": True, "verify_hardened_runtime": True, "additional_checks": True}
                }
            }
        }
        
        # Save default config
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            with open(self.config_path, 'w') as f:
                yaml.dump(default_config, f, indent=2)
            self.logger.info(f"Default configuration created at {self.config_path}")
        except Exception as e:
            self.logger.error(f"Failed to create default config: {e}")
        
        return default_config
    
    def get_profiles(self) -> List[str]:
        """Get list of available profiles"""
        return list(self.config.get('profiles', {}).keys())
    
    def get_profile(self, profile_name: str) -> Optional[Dict[str, Any]]:
        """Get configuration for a specific profile"""
        profiles = self.config.get('profiles', {})
        if profile_name not in profiles:
            self.logger.error(f"Profile '{profile_name}' not found")
            return None
        return profiles[profile_name]
    
    def set_current_profile(self, profile_name: str) -> bool:
        """Set the current active profile"""
        if profile_name not in self.get_profiles():
            self.logger.error(f"Profile '{profile_name}' does not exist")
            return False
        
        self.current_profile = profile_name
        self.logger.info(f"Current profile set to '{profile_name}'")
        return True
    
    def get_current_profile(self) -> str:
        """Get the current active profile name"""
        return self.current_profile
    
    def get_current_profile_config(self) -> Dict[str, Any]:
        """Get configuration for the current profile"""
        return self.get_profile(self.current_profile) or {}
    
    def get_setting(self, component: str, setting: str, default: Any = None) -> Any:
        """Get a specific setting from the current profile"""
        profile_config = self.get_current_profile_config()
        component_config = profile_config.get(component, {})
        return component_config.get(setting, default)
    
    def get_global_setting(self, setting: str, default: Any = None) -> Any:
        """Get a global setting"""
        global_config = self.config.get('global', {})
        return global_config.get(setting, default)
    
    def validate_profile(self, profile_name: str) -> List[str]:
        """Validate a profile configuration and return list of issues"""
        issues = []
        profile = self.get_profile(profile_name)
        
        if not profile:
            issues.append(f"Profile '{profile_name}' not found")
            return issues
        
        # Required components
        required_components = ['firewall', 'privacy', 'encryption', 'app_security']
        for component in required_components:
            if component not in profile:
                issues.append(f"Missing component '{component}' in profile '{profile_name}'")
        
        # Validate firewall settings
        firewall = profile.get('firewall', {})
        if not isinstance(firewall.get('enabled'), bool):
            issues.append(f"Invalid firewall.enabled setting in profile '{profile_name}'")
        
        # Validate privacy settings
        privacy = profile.get('privacy', {})
        if not isinstance(privacy.get('disable_telemetry'), bool):
            issues.append(f"Invalid privacy.disable_telemetry setting in profile '{profile_name}'")
        
        # Validate encryption settings
        encryption = profile.get('encryption', {})
        if not isinstance(encryption.get('filevault'), bool):
            issues.append(f"Invalid encryption.filevault setting in profile '{profile_name}'")
        
        # Validate app_security settings
        app_security = profile.get('app_security', {})
        if not isinstance(app_security.get('gatekeeper'), bool):
            issues.append(f"Invalid app_security.gatekeeper setting in profile '{profile_name}'")
        
        return issues
    
    def create_profile(self, profile_name: str, base_profile: str = "basic", description: str = "") -> bool:
        """Create a new profile based on an existing one"""
        log_operation_start(f"create_profile: {profile_name}")
        
        if profile_name in self.get_profiles():
            self.logger.error(f"Profile '{profile_name}' already exists")
            log_operation_failure(f"create_profile: {profile_name}", "Profile already exists")
            return False
        
        base_config = self.get_profile(base_profile)
        if not base_config:
            self.logger.error(f"Base profile '{base_profile}' not found")
            log_operation_failure(f"create_profile: {profile_name}", f"Base profile '{base_profile}' not found")
            return False
        
        # Create new profile
        new_profile = base_config.copy()
        if description:
            new_profile['description'] = description
        else:
            new_profile['description'] = f"Custom profile based on {base_profile}"
        
        # Add to configuration
        if 'profiles' not in self.config:
            self.config['profiles'] = {}
        
        self.config['profiles'][profile_name] = new_profile
        
        # Save configuration
        if self._save_config():
            log_operation_success(f"create_profile: {profile_name}")
            return True
        else:
            log_operation_failure(f"create_profile: {profile_name}", "Failed to save configuration")
            return False
    
    def delete_profile(self, profile_name: str) -> bool:
        """Delete a profile"""
        log_operation_start(f"delete_profile: {profile_name}")
        
        # Prevent deletion of built-in profiles
        builtin_profiles = ['basic', 'advanced', 'enterprise']
        if profile_name in builtin_profiles:
            self.logger.error(f"Cannot delete built-in profile '{profile_name}'")
            log_operation_failure(f"delete_profile: {profile_name}", "Cannot delete built-in profile")
            return False
        
        if profile_name not in self.get_profiles():
            self.logger.error(f"Profile '{profile_name}' not found")
            log_operation_failure(f"delete_profile: {profile_name}", "Profile not found")
            return False
        
        # Remove profile
        del self.config['profiles'][profile_name]
        
        # If this was the current profile, switch to basic
        if self.current_profile == profile_name:
            self.current_profile = 'basic'
            self.logger.info("Switched to 'basic' profile after deletion")
        
        # Save configuration
        if self._save_config():
            log_operation_success(f"delete_profile: {profile_name}")
            return True
        else:
            log_operation_failure(f"delete_profile: {profile_name}", "Failed to save configuration")
            return False
    
    def update_profile_setting(self, profile_name: str, component: str, setting: str, value: Any) -> bool:
        """Update a specific setting in a profile"""
        log_operation_start(f"update_profile_setting: {profile_name}.{component}.{setting}")
        
        profile = self.get_profile(profile_name)
        if not profile:
            log_operation_failure(f"update_profile_setting: {profile_name}.{component}.{setting}", "Profile not found")
            return False
        
        # Update the setting
        if component not in profile:
            profile[component] = {}
        
        profile[component][setting] = value
        
        # Save configuration
        if self._save_config():
            log_operation_success(f"update_profile_setting: {profile_name}.{component}.{setting}")
            return True
        else:
            log_operation_failure(f"update_profile_setting: {profile_name}.{component}.{setting}", "Failed to save configuration")
            return False
    
    def export_profile(self, profile_name: str, output_path: str) -> bool:
        """Export a profile to a file"""
        log_operation_start(f"export_profile: {profile_name}")
        
        profile = self.get_profile(profile_name)
        if not profile:
            log_operation_failure(f"export_profile: {profile_name}", "Profile not found")
            return False
        
        try:
            export_data = {
                'profile_name': profile_name,
                'exported_at': str(Path().cwd()),
                'config': profile
            }
            
            with open(output_path, 'w') as f:
                if output_path.endswith('.json'):
                    json.dump(export_data, f, indent=2)
                else:
                    yaml.dump(export_data, f, indent=2)
            
            log_operation_success(f"export_profile: {profile_name}", {"output_path": output_path})
            return True
            
        except Exception as e:
            log_operation_failure(f"export_profile: {profile_name}", str(e))
            return False
    
    def import_profile(self, input_path: str, profile_name: str = None) -> bool:
        """Import a profile from a file"""
        log_operation_start(f"import_profile: {input_path}")
        
        try:
            with open(input_path, 'r') as f:
                if input_path.endswith('.json'):
                    import_data = json.load(f)
                else:
                    import_data = yaml.safe_load(f)
            
            # Extract profile name and config
            imported_profile_name = profile_name or import_data.get('profile_name', 'imported_profile')
            profile_config = import_data.get('config', import_data)
            
            # Validate the imported profile
            temp_config = {'profiles': {imported_profile_name: profile_config}}
            temp_manager = ConfigurationManager.__new__(ConfigurationManager)
            temp_manager.config = temp_config
            temp_manager.logger = self.logger
            
            issues = temp_manager.validate_profile(imported_profile_name)
            if issues:
                self.logger.error(f"Imported profile validation failed: {issues}")
                log_operation_failure(f"import_profile: {input_path}", f"Validation failed: {issues}")
                return False
            
            # Add to current configuration
            if 'profiles' not in self.config:
                self.config['profiles'] = {}
            
            self.config['profiles'][imported_profile_name] = profile_config
            
            # Save configuration
            if self._save_config():
                log_operation_success(f"import_profile: {input_path}", {"profile_name": imported_profile_name})
                return True
            else:
                log_operation_failure(f"import_profile: {input_path}", "Failed to save configuration")
                return False
                
        except Exception as e:
            log_operation_failure(f"import_profile: {input_path}", str(e))
            return False
    
    def compare_profiles(self, profile1: str, profile2: str) -> Dict[str, Any]:
        """Compare two profiles and return differences"""
        config1 = self.get_profile(profile1)
        config2 = self.get_profile(profile2)
        
        if not config1 or not config2:
            return {"error": "One or both profiles not found"}
        
        differences = {}
        all_components = set(config1.keys()) | set(config2.keys())
        
        for component in all_components:
            comp1 = config1.get(component, {})
            comp2 = config2.get(component, {})
            
            if comp1 != comp2:
                differences[component] = {
                    profile1: comp1,
                    profile2: comp2
                }
        
        return differences
    
    def get_profile_summary(self, profile_name: str) -> Dict[str, Any]:
        """Get a summary of a profile's settings"""
        profile = self.get_profile(profile_name)
        if not profile:
            return {"error": "Profile not found"}
        
        summary = {
            "name": profile_name,
            "description": profile.get('description', 'No description'),
            "components": {},
            "security_level": self._calculate_security_level(profile)
        }
        
        # Summarize each component
        for component, settings in profile.items():
            if component == 'description':
                continue
            
            if isinstance(settings, dict):
                enabled_count = sum(1 for v in settings.values() if v is True)
                total_count = len(settings)
                summary["components"][component] = {
                    "enabled_settings": enabled_count,
                    "total_settings": total_count,
                    "coverage": f"{enabled_count}/{total_count}"
                }
        
        return summary
    
    def _calculate_security_level(self, profile: Dict[str, Any]) -> str:
        """Calculate security level based on enabled settings"""
        total_security_settings = 0
        enabled_security_settings = 0
        
        security_weights = {
            'firewall': {'enabled': 2, 'stealth_mode': 1, 'logging': 1},
            'privacy': {'disable_telemetry': 1, 'disable_siri_analytics': 1, 'disable_smb': 1},
            'encryption': {'filevault': 3, 'secure_recovery_key': 1},
            'app_security': {'gatekeeper': 2, 'verify_hardened_runtime': 1, 'additional_checks': 1}
        }
        
        for component, weights in security_weights.items():
            component_config = profile.get(component, {})
            for setting, weight in weights.items():
                total_security_settings += weight
                if component_config.get(setting, False):
                    enabled_security_settings += weight
        
        if total_security_settings == 0:
            return "Unknown"
        
        percentage = (enabled_security_settings / total_security_settings) * 100
        
        if percentage >= 90:
            return "High"
        elif percentage >= 70:
            return "Medium"
        elif percentage >= 50:
            return "Basic"
        else:
            return "Low"
    
    def _save_config(self) -> bool:
        """Save configuration to file"""
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            with open(self.config_path, 'w') as f:
                yaml.dump(self.config, f, indent=2)
            self.logger.info(f"Configuration saved to {self.config_path}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to save configuration: {e}")
            return False

def main():
    """Main function for configuration management"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Albator Configuration Manager")
    parser.add_argument("--config", default="config/albator.yaml", help="Configuration file path")
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # List profiles
    subparsers.add_parser("list", help="List available profiles")
    
    # Show profile
    show_parser = subparsers.add_parser("show", help="Show profile details")
    show_parser.add_argument("profile", help="Profile name")
    
    # Create profile
    create_parser = subparsers.add_parser("create", help="Create new profile")
    create_parser.add_argument("name", help="New profile name")
    create_parser.add_argument("--base", default="basic", help="Base profile to copy from")
    create_parser.add_argument("--description", help="Profile description")
    
    # Delete profile
    delete_parser = subparsers.add_parser("delete", help="Delete profile")
    delete_parser.add_argument("profile", help="Profile name to delete")
    
    # Compare profiles
    compare_parser = subparsers.add_parser("compare", help="Compare two profiles")
    compare_parser.add_argument("profile1", help="First profile")
    compare_parser.add_argument("profile2", help="Second profile")
    
    # Export profile
    export_parser = subparsers.add_parser("export", help="Export profile")
    export_parser.add_argument("profile", help="Profile name")
    export_parser.add_argument("output", help="Output file path")
    
    # Import profile
    import_parser = subparsers.add_parser("import", help="Import profile")
    import_parser.add_argument("input", help="Input file path")
    import_parser.add_argument("--name", help="Profile name (if different from file)")
    
    # Validate profile
    validate_parser = subparsers.add_parser("validate", help="Validate profile")
    validate_parser.add_argument("profile", help="Profile name")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize configuration manager
    config_manager = ConfigurationManager(args.config)
    
    if args.command == "list":
        profiles = config_manager.get_profiles()
        print("Available profiles:")
        for profile in profiles:
            summary = config_manager.get_profile_summary(profile)
            print(f"  {profile}: {summary['description']} (Security: {summary['security_level']})")
    
    elif args.command == "show":
        profile = config_manager.get_profile(args.profile)
        if profile:
            summary = config_manager.get_profile_summary(args.profile)
            print(f"Profile: {args.profile}")
            print(f"Description: {summary['description']}")
            print(f"Security Level: {summary['security_level']}")
            print("\nComponents:")
            for component, info in summary['components'].items():
                print(f"  {component}: {info['coverage']} settings enabled")
            print(f"\nFull configuration:")
            print(yaml.dump(profile, indent=2))
        else:
            print(f"Profile '{args.profile}' not found")
    
    elif args.command == "create":
        if config_manager.create_profile(args.name, args.base, args.description or ""):
            print(f"Profile '{args.name}' created successfully")
        else:
            print(f"Failed to create profile '{args.name}'")
    
    elif args.command == "delete":
        if config_manager.delete_profile(args.profile):
            print(f"Profile '{args.profile}' deleted successfully")
        else:
            print(f"Failed to delete profile '{args.profile}'")
    
    elif args.command == "compare":
        differences = config_manager.compare_profiles(args.profile1, args.profile2)
        if "error" in differences:
            print(f"Error: {differences['error']}")
        elif not differences:
            print(f"Profiles '{args.profile1}' and '{args.profile2}' are identical")
        else:
            print(f"Differences between '{args.profile1}' and '{args.profile2}':")
            print(yaml.dump(differences, indent=2))
    
    elif args.command == "export":
        if config_manager.export_profile(args.profile, args.output):
            print(f"Profile '{args.profile}' exported to '{args.output}'")
        else:
            print(f"Failed to export profile '{args.profile}'")
    
    elif args.command == "import":
        if config_manager.import_profile(args.input, args.name):
            print(f"Profile imported successfully from '{args.input}'")
        else:
            print(f"Failed to import profile from '{args.input}'")
    
    elif args.command == "validate":
        issues = config_manager.validate_profile(args.profile)
        if not issues:
            print(f"Profile '{args.profile}' is valid")
        else:
            print(f"Profile '{args.profile}' has issues:")
            for issue in issues:
                print(f"  - {issue}")

if __name__ == "__main__":
    main()
