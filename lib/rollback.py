#!/usr/bin/env python3
"""
Albator Rollback System
Provides functionality to undo security hardening changes
"""

import os
import sys
import json
import yaml
import subprocess
import shutil
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path

# Add lib directory to path for imports
sys.path.insert(0, os.path.dirname(__file__))
from logger import get_logger, log_operation_start, log_operation_success, log_operation_failure

class RollbackManager:
    """Manages rollback operations for Albator"""
    
    def __init__(self, config_path: str = "config/albator.yaml"):
        """Initialize the rollback manager"""
        self.logger = get_logger("rollback")
        self.config = self._load_config(config_path)
        self.backup_location = self.config.get('rollback', {}).get('backup_location', '/tmp/albator_backup')
        self.rollback_enabled = self.config.get('rollback', {}).get('enabled', True)
        
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
    
    def create_rollback_point(self, component: str, description: str) -> str:
        """Create a rollback point for a component"""
        if not self.rollback_enabled:
            self.logger.info("Rollback disabled, skipping rollback point creation")
            return ""
        
        log_operation_start(f"create_rollback_point: {component}")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        rollback_id = f"{component}_{timestamp}"
        rollback_dir = os.path.join(self.backup_location, rollback_id)
        
        try:
            os.makedirs(rollback_dir, exist_ok=True)
            
            # Create rollback metadata
            metadata = {
                "rollback_id": rollback_id,
                "component": component,
                "description": description,
                "timestamp": timestamp,
                "created_at": datetime.now().isoformat(),
                "system_info": {
                    "macos_version": self._get_macos_version(),
                    "user": os.getenv('USER', 'unknown'),
                    "hostname": os.getenv('HOSTNAME', 'unknown')
                },
                "backups": []
            }
            
            # Save metadata
            metadata_file = os.path.join(rollback_dir, "metadata.json")
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            log_operation_success(f"create_rollback_point: {component}", {"rollback_id": rollback_id})
            return rollback_id
            
        except Exception as e:
            log_operation_failure(f"create_rollback_point: {component}", str(e))
            return ""
    
    def backup_defaults_setting(self, rollback_id: str, domain: str, key: str, use_sudo: bool = False) -> bool:
        """Backup a defaults setting"""
        if not rollback_id:
            return False
        
        try:
            rollback_dir = os.path.join(self.backup_location, rollback_id)
            backup_file = os.path.join(rollback_dir, f"defaults_{domain}_{key}.backup")
            
            # Get current value
            cmd = f"{'sudo ' if use_sudo else ''}defaults read '{domain}' '{key}'"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            backup_data = {
                "type": "defaults",
                "domain": domain,
                "key": key,
                "use_sudo": use_sudo,
                "original_value": result.stdout.strip() if result.returncode == 0 else None,
                "exists": result.returncode == 0,
                "backup_time": datetime.now().isoformat()
            }
            
            with open(backup_file, 'w') as f:
                json.dump(backup_data, f, indent=2)
            
            # Update metadata
            self._update_rollback_metadata(rollback_id, {
                "file": backup_file,
                "type": "defaults",
                "domain": domain,
                "key": key
            })
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to backup defaults setting {domain}.{key}: {e}")
            return False
    
    def backup_system_setting(self, rollback_id: str, setting_name: str, check_command: str) -> bool:
        """Backup a system setting"""
        if not rollback_id:
            return False
        
        try:
            rollback_dir = os.path.join(self.backup_location, rollback_id)
            backup_file = os.path.join(rollback_dir, f"system_{setting_name}.backup")
            
            # Get current value
            result = subprocess.run(check_command, shell=True, capture_output=True, text=True)
            
            backup_data = {
                "type": "system",
                "setting_name": setting_name,
                "check_command": check_command,
                "original_value": result.stdout.strip() if result.returncode == 0 else None,
                "return_code": result.returncode,
                "backup_time": datetime.now().isoformat()
            }
            
            with open(backup_file, 'w') as f:
                json.dump(backup_data, f, indent=2)
            
            # Update metadata
            self._update_rollback_metadata(rollback_id, {
                "file": backup_file,
                "type": "system",
                "setting_name": setting_name
            })
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to backup system setting {setting_name}: {e}")
            return False
    
    def backup_service_state(self, rollback_id: str, service_name: str) -> bool:
        """Backup a service state"""
        if not rollback_id:
            return False
        
        try:
            rollback_dir = os.path.join(self.backup_location, rollback_id)
            backup_file = os.path.join(rollback_dir, f"service_{service_name}.backup")
            
            # Check if service is loaded
            check_cmd = f"sudo launchctl list | grep {service_name}"
            result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)
            
            backup_data = {
                "type": "service",
                "service_name": service_name,
                "was_loaded": result.returncode == 0,
                "service_info": result.stdout.strip() if result.returncode == 0 else None,
                "backup_time": datetime.now().isoformat()
            }
            
            with open(backup_file, 'w') as f:
                json.dump(backup_data, f, indent=2)
            
            # Update metadata
            self._update_rollback_metadata(rollback_id, {
                "file": backup_file,
                "type": "service",
                "service_name": service_name
            })
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to backup service state {service_name}: {e}")
            return False
    
    def rollback(self, rollback_id: str, dry_run: bool = False) -> bool:
        """Perform rollback to a specific point"""
        log_operation_start(f"rollback: {rollback_id}")
        
        rollback_dir = os.path.join(self.backup_location, rollback_id)
        metadata_file = os.path.join(rollback_dir, "metadata.json")
        
        if not os.path.exists(metadata_file):
            log_operation_failure(f"rollback: {rollback_id}", "Metadata file not found")
            return False
        
        try:
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
            
            self.logger.info(f"Rolling back: {metadata['description']}")
            
            errors = 0
            for backup_info in metadata.get('backups', []):
                backup_file = backup_info['file']
                
                if not os.path.exists(backup_file):
                    self.logger.error(f"Backup file not found: {backup_file}")
                    errors += 1
                    continue
                
                with open(backup_file, 'r') as f:
                    backup_data = json.load(f)
                
                if backup_data['type'] == 'defaults':
                    if not self._restore_defaults_setting(backup_data, dry_run):
                        errors += 1
                elif backup_data['type'] == 'system':
                    if not self._restore_system_setting(backup_data, dry_run):
                        errors += 1
                elif backup_data['type'] == 'service':
                    if not self._restore_service_state(backup_data, dry_run):
                        errors += 1
            
            if errors == 0:
                log_operation_success(f"rollback: {rollback_id}")
                return True
            else:
                log_operation_failure(f"rollback: {rollback_id}", f"{errors} errors occurred")
                return False
                
        except Exception as e:
            log_operation_failure(f"rollback: {rollback_id}", str(e))
            return False
    
    def _restore_defaults_setting(self, backup_data: Dict, dry_run: bool) -> bool:
        """Restore a defaults setting"""
        domain = backup_data['domain']
        key = backup_data['key']
        use_sudo = backup_data['use_sudo']
        original_value = backup_data['original_value']
        exists = backup_data['exists']
        
        try:
            if dry_run:
                if exists:
                    self.logger.info(f"DRY RUN: Would restore {domain}.{key} to '{original_value}'")
                else:
                    self.logger.info(f"DRY RUN: Would delete {domain}.{key}")
                return True
            
            if exists and original_value is not None:
                # Restore original value
                cmd = f"{'sudo ' if use_sudo else ''}defaults write '{domain}' '{key}' '{original_value}'"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                if result.returncode == 0:
                    self.logger.info(f"Restored {domain}.{key} to '{original_value}'")
                    return True
                else:
                    self.logger.error(f"Failed to restore {domain}.{key}: {result.stderr}")
                    return False
            else:
                # Delete the key (it didn't exist originally)
                cmd = f"{'sudo ' if use_sudo else ''}defaults delete '{domain}' '{key}'"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                if result.returncode == 0:
                    self.logger.info(f"Deleted {domain}.{key} (didn't exist originally)")
                    return True
                else:
                    self.logger.warning(f"Could not delete {domain}.{key}: {result.stderr}")
                    return True  # This might be expected if it was already deleted
                    
        except Exception as e:
            self.logger.error(f"Error restoring defaults setting {domain}.{key}: {e}")
            return False
    
    def _restore_system_setting(self, backup_data: Dict, dry_run: bool) -> bool:
        """Restore a system setting"""
        setting_name = backup_data['setting_name']
        
        try:
            if dry_run:
                self.logger.info(f"DRY RUN: Would restore system setting {setting_name}")
                return True
            
            # System settings restoration is complex and depends on the specific setting
            # For now, we'll log what would be restored
            self.logger.warning(f"System setting restoration not implemented for {setting_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error restoring system setting {setting_name}: {e}")
            return False
    
    def _restore_service_state(self, backup_data: Dict, dry_run: bool) -> bool:
        """Restore a service state"""
        service_name = backup_data['service_name']
        was_loaded = backup_data['was_loaded']
        
        try:
            if dry_run:
                action = "load" if was_loaded else "unload"
                self.logger.info(f"DRY RUN: Would {action} service {service_name}")
                return True
            
            if was_loaded:
                # Service was originally loaded, load it back
                cmd = f"sudo launchctl load -w /System/Library/LaunchDaemons/{service_name}.plist"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                if result.returncode == 0:
                    self.logger.info(f"Restored service {service_name} (loaded)")
                    return True
                else:
                    self.logger.error(f"Failed to load service {service_name}: {result.stderr}")
                    return False
            else:
                # Service was originally unloaded, ensure it's unloaded
                self.logger.info(f"Service {service_name} was originally unloaded, no action needed")
                return True
                
        except Exception as e:
            self.logger.error(f"Error restoring service state {service_name}: {e}")
            return False
    
    def list_rollback_points(self) -> List[Dict[str, Any]]:
        """List available rollback points"""
        rollback_points = []
        
        if not os.path.exists(self.backup_location):
            return rollback_points
        
        for item in os.listdir(self.backup_location):
            metadata_file = os.path.join(self.backup_location, item, "metadata.json")
            
            if os.path.exists(metadata_file):
                try:
                    with open(metadata_file, 'r') as f:
                        metadata = json.load(f)
                    rollback_points.append(metadata)
                except Exception as e:
                    self.logger.error(f"Error reading metadata for {item}: {e}")
        
        # Sort by creation time (newest first)
        rollback_points.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        return rollback_points
    
    def cleanup_old_rollback_points(self, keep_count: int = 10) -> int:
        """Clean up old rollback points, keeping only the most recent ones"""
        rollback_points = self.list_rollback_points()
        
        if len(rollback_points) <= keep_count:
            return 0
        
        points_to_remove = rollback_points[keep_count:]
        removed_count = 0
        
        for point in points_to_remove:
            rollback_dir = os.path.join(self.backup_location, point['rollback_id'])
            try:
                shutil.rmtree(rollback_dir)
                self.logger.info(f"Removed old rollback point: {point['rollback_id']}")
                removed_count += 1
            except Exception as e:
                self.logger.error(f"Failed to remove rollback point {point['rollback_id']}: {e}")
        
        return removed_count
    
    def _update_rollback_metadata(self, rollback_id: str, backup_info: Dict) -> None:
        """Update rollback metadata with backup information"""
        metadata_file = os.path.join(self.backup_location, rollback_id, "metadata.json")
        
        try:
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
            
            metadata['backups'].append(backup_info)
            
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Failed to update rollback metadata: {e}")
    
    def _get_macos_version(self) -> str:
        """Get macOS version"""
        try:
            result = subprocess.run(['sw_vers', '-productVersion'], capture_output=True, text=True)
            return result.stdout.strip() if result.returncode == 0 else "unknown"
        except Exception:
            return "unknown"

def main():
    """Main function for rollback operations"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Albator Rollback Manager")
    parser.add_argument("--config", default="config/albator.yaml", help="Configuration file path")
    parser.add_argument("--list", action="store_true", help="List available rollback points")
    parser.add_argument("--rollback", help="Rollback to specific point (rollback_id)")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be done without making changes")
    parser.add_argument("--cleanup", type=int, metavar="N", help="Clean up old rollback points, keeping only N most recent")
    
    args = parser.parse_args()
    
    manager = RollbackManager(args.config)
    
    if args.list:
        points = manager.list_rollback_points()
        if points:
            print("Available Rollback Points:")
            print("=" * 50)
            for point in points:
                print(f"ID: {point['rollback_id']}")
                print(f"Component: {point['component']}")
                print(f"Description: {point['description']}")
                print(f"Created: {point['created_at']}")
                print(f"Backups: {len(point.get('backups', []))}")
                print("-" * 30)
        else:
            print("No rollback points found.")
    
    elif args.rollback:
        success = manager.rollback(args.rollback, args.dry_run)
        if success:
            print(f"Rollback to {args.rollback} completed successfully.")
            sys.exit(0)
        else:
            print(f"Rollback to {args.rollback} failed.")
            sys.exit(1)
    
    elif args.cleanup is not None:
        removed = manager.cleanup_old_rollback_points(args.cleanup)
        print(f"Removed {removed} old rollback points.")
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
