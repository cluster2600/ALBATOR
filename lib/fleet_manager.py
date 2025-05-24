#!/usr/bin/env python3
"""
Albator Fleet Manager
Manages security hardening across multiple macOS systems
"""

import os
import sys
import json
import yaml
import asyncio
import aiohttp
import paramiko
import threading
import time
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict

# Add lib directory to path for imports
sys.path.insert(0, os.path.dirname(__file__))
from logger import get_logger, log_operation_start, log_operation_success, log_operation_failure
from config_manager import ConfigurationManager

@dataclass
class MacHost:
    """Represents a Mac host in the fleet"""
    hostname: str
    ip_address: str
    username: str
    ssh_key_path: Optional[str] = None
    password: Optional[str] = None
    port: int = 22
    tags: List[str] = None
    profile: str = "basic"
    last_contact: Optional[str] = None
    status: str = "unknown"  # unknown, online, offline, error
    macos_version: Optional[str] = None
    albator_version: Optional[str] = None
    security_status: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []
        if self.security_status is None:
            self.security_status = {}

@dataclass
class FleetOperation:
    """Represents a fleet-wide operation"""
    operation_id: str
    operation_type: str
    profile: str
    target_hosts: List[str]
    dry_run: bool
    created_at: str
    status: str = "pending"  # pending, running, completed, failed, partial
    results: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.results is None:
            self.results = {}

class FleetManager:
    """Manages a fleet of Mac systems for security hardening"""
    
    def __init__(self, config_path: str = "config/albator.yaml", fleet_config_path: str = "config/fleet.yaml"):
        """Initialize the fleet manager"""
        self.logger = get_logger("fleet_manager")
        self.config_manager = ConfigurationManager(config_path)
        self.fleet_config_path = fleet_config_path
        self.hosts: Dict[str, MacHost] = {}
        self.operations: Dict[str, FleetOperation] = {}
        self.executor = ThreadPoolExecutor(max_workers=10)
        self._load_fleet_config()
    
    def _load_fleet_config(self):
        """Load fleet configuration from file"""
        try:
            if os.path.exists(self.fleet_config_path):
                with open(self.fleet_config_path, 'r') as f:
                    config = yaml.safe_load(f)
                    
                # Load hosts
                for host_data in config.get('hosts', []):
                    host = MacHost(**host_data)
                    self.hosts[host.hostname] = host
                    
                self.logger.info(f"Loaded {len(self.hosts)} hosts from fleet configuration")
            else:
                self.logger.warning(f"Fleet config file {self.fleet_config_path} not found")
                self._create_default_fleet_config()
                
        except Exception as e:
            self.logger.error(f"Error loading fleet config: {e}")
            self._create_default_fleet_config()
    
    def _create_default_fleet_config(self):
        """Create default fleet configuration"""
        default_config = {
            'fleet_name': 'Albator Fleet',
            'created_at': datetime.now().isoformat(),
            'settings': {
                'ssh_timeout': 30,
                'operation_timeout': 300,
                'max_concurrent_operations': 5,
                'retry_attempts': 3,
                'health_check_interval': 300
            },
            'hosts': [
                {
                    'hostname': 'example-mac-1',
                    'ip_address': '192.168.1.100',
                    'username': 'admin',
                    'ssh_key_path': '~/.ssh/id_rsa',
                    'tags': ['development', 'test'],
                    'profile': 'basic'
                }
            ]
        }
        
        try:
            os.makedirs(os.path.dirname(self.fleet_config_path), exist_ok=True)
            with open(self.fleet_config_path, 'w') as f:
                yaml.dump(default_config, f, indent=2)
            self.logger.info(f"Created default fleet config at {self.fleet_config_path}")
        except Exception as e:
            self.logger.error(f"Failed to create default fleet config: {e}")
    
    def _save_fleet_config(self):
        """Save fleet configuration to file"""
        try:
            config = {
                'fleet_name': 'Albator Fleet',
                'updated_at': datetime.now().isoformat(),
                'settings': {
                    'ssh_timeout': 30,
                    'operation_timeout': 300,
                    'max_concurrent_operations': 5,
                    'retry_attempts': 3,
                    'health_check_interval': 300
                },
                'hosts': [asdict(host) for host in self.hosts.values()]
            }
            
            with open(self.fleet_config_path, 'w') as f:
                yaml.dump(config, f, indent=2)
            self.logger.info("Fleet configuration saved")
            
        except Exception as e:
            self.logger.error(f"Failed to save fleet config: {e}")
    
    def add_host(self, hostname: str, ip_address: str, username: str, 
                 ssh_key_path: str = None, password: str = None, 
                 tags: List[str] = None, profile: str = "basic") -> bool:
        """Add a host to the fleet"""
        log_operation_start(f"add_host: {hostname}")
        
        try:
            if hostname in self.hosts:
                self.logger.warning(f"Host {hostname} already exists in fleet")
                return False
            
            host = MacHost(
                hostname=hostname,
                ip_address=ip_address,
                username=username,
                ssh_key_path=ssh_key_path,
                password=password,
                tags=tags or [],
                profile=profile
            )
            
            self.hosts[hostname] = host
            self._save_fleet_config()
            
            log_operation_success(f"add_host: {hostname}")
            return True
            
        except Exception as e:
            log_operation_failure(f"add_host: {hostname}", str(e))
            return False
    
    def remove_host(self, hostname: str) -> bool:
        """Remove a host from the fleet"""
        log_operation_start(f"remove_host: {hostname}")
        
        try:
            if hostname not in self.hosts:
                self.logger.warning(f"Host {hostname} not found in fleet")
                return False
            
            del self.hosts[hostname]
            self._save_fleet_config()
            
            log_operation_success(f"remove_host: {hostname}")
            return True
            
        except Exception as e:
            log_operation_failure(f"remove_host: {hostname}", str(e))
            return False
    
    def get_hosts_by_tag(self, tag: str) -> List[MacHost]:
        """Get hosts filtered by tag"""
        return [host for host in self.hosts.values() if tag in host.tags]
    
    def get_hosts_by_profile(self, profile: str) -> List[MacHost]:
        """Get hosts filtered by profile"""
        return [host for host in self.hosts.values() if host.profile == profile]
    
    def test_host_connection(self, hostname: str) -> Tuple[bool, str]:
        """Test SSH connection to a host"""
        if hostname not in self.hosts:
            return False, "Host not found in fleet"
        
        host = self.hosts[hostname]
        
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect using SSH key or password
            if host.ssh_key_path:
                key_path = os.path.expanduser(host.ssh_key_path)
                ssh.connect(
                    hostname=host.ip_address,
                    port=host.port,
                    username=host.username,
                    key_filename=key_path,
                    timeout=30
                )
            elif host.password:
                ssh.connect(
                    hostname=host.ip_address,
                    port=host.port,
                    username=host.username,
                    password=host.password,
                    timeout=30
                )
            else:
                return False, "No authentication method configured"
            
            # Test basic command
            stdin, stdout, stderr = ssh.exec_command('echo "connection_test"')
            result = stdout.read().decode().strip()
            
            ssh.close()
            
            if result == "connection_test":
                host.status = "online"
                host.last_contact = datetime.now().isoformat()
                return True, "Connection successful"
            else:
                host.status = "error"
                return False, "Command execution failed"
                
        except Exception as e:
            host.status = "offline"
            return False, str(e)
    
    def get_host_info(self, hostname: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a host"""
        if hostname not in self.hosts:
            return None
        
        host = self.hosts[hostname]
        
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect
            if host.ssh_key_path:
                key_path = os.path.expanduser(host.ssh_key_path)
                ssh.connect(
                    hostname=host.ip_address,
                    port=host.port,
                    username=host.username,
                    key_filename=key_path,
                    timeout=30
                )
            elif host.password:
                ssh.connect(
                    hostname=host.ip_address,
                    port=host.port,
                    username=host.username,
                    password=host.password,
                    timeout=30
                )
            else:
                return None
            
            # Get system information
            commands = {
                'macos_version': 'sw_vers -productVersion',
                'hostname': 'hostname',
                'uptime': 'uptime',
                'disk_usage': 'df -h /',
                'memory_usage': 'vm_stat | head -10',
                'firewall_status': 'sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate',
                'filevault_status': 'fdesetup status',
                'gatekeeper_status': 'spctl --status',
                'sip_status': 'csrutil status'
            }
            
            info = {}
            for key, command in commands.items():
                try:
                    stdin, stdout, stderr = ssh.exec_command(command)
                    result = stdout.read().decode().strip()
                    error = stderr.read().decode().strip()
                    
                    if result:
                        info[key] = result
                    elif error:
                        info[key] = f"Error: {error}"
                    else:
                        info[key] = "No output"
                        
                except Exception as e:
                    info[key] = f"Command failed: {str(e)}"
            
            ssh.close()
            
            # Update host information
            host.macos_version = info.get('macos_version', 'Unknown')
            host.last_contact = datetime.now().isoformat()
            host.status = "online"
            host.security_status = {
                'firewall': 'enabled' in info.get('firewall_status', '').lower(),
                'filevault': 'FileVault is On' in info.get('filevault_status', ''),
                'gatekeeper': 'assessments enabled' in info.get('gatekeeper_status', '').lower(),
                'sip': 'enabled' in info.get('sip_status', '').lower()
            }
            
            return info
            
        except Exception as e:
            host.status = "error"
            self.logger.error(f"Failed to get info for {hostname}: {e}")
            return None
    
    def execute_command_on_host(self, hostname: str, command: str, timeout: int = 60) -> Tuple[bool, str, str]:
        """Execute a command on a specific host"""
        if hostname not in self.hosts:
            return False, "", "Host not found in fleet"
        
        host = self.hosts[hostname]
        
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect
            if host.ssh_key_path:
                key_path = os.path.expanduser(host.ssh_key_path)
                ssh.connect(
                    hostname=host.ip_address,
                    port=host.port,
                    username=host.username,
                    key_filename=key_path,
                    timeout=30
                )
            elif host.password:
                ssh.connect(
                    hostname=host.ip_address,
                    port=host.port,
                    username=host.username,
                    password=host.password,
                    timeout=30
                )
            else:
                return False, "", "No authentication method configured"
            
            # Execute command
            stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)
            
            stdout_data = stdout.read().decode()
            stderr_data = stderr.read().decode()
            exit_code = stdout.channel.recv_exit_status()
            
            ssh.close()
            
            success = exit_code == 0
            return success, stdout_data, stderr_data
            
        except Exception as e:
            return False, "", str(e)
    
    def deploy_albator_to_host(self, hostname: str) -> bool:
        """Deploy Albator to a specific host"""
        log_operation_start(f"deploy_albator: {hostname}")
        
        try:
            if hostname not in self.hosts:
                log_operation_failure(f"deploy_albator: {hostname}", "Host not found")
                return False
            
            host = self.hosts[hostname]
            
            # Create SSH connection
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            if host.ssh_key_path:
                key_path = os.path.expanduser(host.ssh_key_path)
                ssh.connect(
                    hostname=host.ip_address,
                    port=host.port,
                    username=host.username,
                    key_filename=key_path,
                    timeout=30
                )
            elif host.password:
                ssh.connect(
                    hostname=host.ip_address,
                    port=host.port,
                    username=host.username,
                    password=host.password,
                    timeout=30
                )
            else:
                log_operation_failure(f"deploy_albator: {hostname}", "No authentication method")
                return False
            
            # Create SFTP connection for file transfer
            sftp = ssh.open_sftp()
            
            # Create remote directory
            remote_dir = "/tmp/albator_deployment"
            ssh.exec_command(f"mkdir -p {remote_dir}")
            
            # Files to deploy
            files_to_deploy = [
                'privacy.sh',
                'firewall.sh',
                'encryption.sh',
                'app_security.sh',
                'cve_fetch.sh',
                'apple_updates.sh',
                'lib/logger.py',
                'lib/config_manager.py',
                'lib/rollback.py',
                'config/albator.yaml'
            ]
            
            # Transfer files
            for file_path in files_to_deploy:
                if os.path.exists(file_path):
                    remote_path = f"{remote_dir}/{os.path.basename(file_path)}"
                    sftp.put(file_path, remote_path)
                    self.logger.info(f"Deployed {file_path} to {hostname}")
            
            # Make scripts executable
            ssh.exec_command(f"chmod +x {remote_dir}/*.sh")
            
            # Create lib directory and copy Python files
            ssh.exec_command(f"mkdir -p {remote_dir}/lib")
            ssh.exec_command(f"mkdir -p {remote_dir}/config")
            
            sftp.close()
            ssh.close()
            
            log_operation_success(f"deploy_albator: {hostname}")
            return True
            
        except Exception as e:
            log_operation_failure(f"deploy_albator: {hostname}", str(e))
            return False
    
    def run_fleet_operation(self, operation_type: str, target_hosts: List[str] = None, 
                           profile: str = "basic", dry_run: bool = False) -> str:
        """Run an operation across multiple hosts"""
        operation_id = f"{operation_type}_{int(time.time())}"
        
        # Determine target hosts
        if target_hosts is None:
            target_hosts = list(self.hosts.keys())
        
        # Validate hosts
        valid_hosts = [h for h in target_hosts if h in self.hosts]
        if not valid_hosts:
            self.logger.error("No valid hosts specified for operation")
            return ""
        
        # Create operation
        operation = FleetOperation(
            operation_id=operation_id,
            operation_type=operation_type,
            profile=profile,
            target_hosts=valid_hosts,
            dry_run=dry_run,
            created_at=datetime.now().isoformat()
        )
        
        self.operations[operation_id] = operation
        
        log_operation_start(f"fleet_operation: {operation_id}")
        
        # Run operation in background thread
        thread = threading.Thread(
            target=self._execute_fleet_operation,
            args=(operation,)
        )
        thread.daemon = True
        thread.start()
        
        return operation_id
    
    def _execute_fleet_operation(self, operation: FleetOperation):
        """Execute a fleet operation"""
        operation.status = "running"
        
        # Map operation types to scripts
        script_mapping = {
            'privacy': 'privacy.sh',
            'firewall': 'firewall.sh',
            'encryption': 'encryption.sh',
            'app_security': 'app_security.sh',
            'cve_fetch': 'cve_fetch.sh',
            'apple_updates': 'apple_updates.sh'
        }
        
        script_name = script_mapping.get(operation.operation_type)
        if not script_name:
            operation.status = "failed"
            operation.results['error'] = f"Unknown operation type: {operation.operation_type}"
            return
        
        # Build command
        command = f"/tmp/albator_deployment/{script_name}"
        if operation.dry_run:
            command += " --dry-run"
        
        # Execute on all hosts concurrently
        futures = {}
        with ThreadPoolExecutor(max_workers=5) as executor:
            for hostname in operation.target_hosts:
                future = executor.submit(self.execute_command_on_host, hostname, command, 300)
                futures[future] = hostname
            
            # Collect results
            for future in as_completed(futures):
                hostname = futures[future]
                try:
                    success, stdout, stderr = future.result()
                    operation.results[hostname] = {
                        'success': success,
                        'stdout': stdout,
                        'stderr': stderr,
                        'timestamp': datetime.now().isoformat()
                    }
                except Exception as e:
                    operation.results[hostname] = {
                        'success': False,
                        'stdout': '',
                        'stderr': str(e),
                        'timestamp': datetime.now().isoformat()
                    }
        
        # Determine overall status
        successful_hosts = sum(1 for result in operation.results.values() if result.get('success', False))
        total_hosts = len(operation.target_hosts)
        
        if successful_hosts == total_hosts:
            operation.status = "completed"
        elif successful_hosts > 0:
            operation.status = "partial"
        else:
            operation.status = "failed"
        
        log_operation_success(f"fleet_operation: {operation.operation_id}", {
            'successful_hosts': successful_hosts,
            'total_hosts': total_hosts,
            'status': operation.status
        })
    
    def get_operation_status(self, operation_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a fleet operation"""
        if operation_id not in self.operations:
            return None
        
        operation = self.operations[operation_id]
        return asdict(operation)
    
    def get_fleet_summary(self) -> Dict[str, Any]:
        """Get summary of fleet status"""
        total_hosts = len(self.hosts)
        online_hosts = sum(1 for host in self.hosts.values() if host.status == "online")
        offline_hosts = sum(1 for host in self.hosts.values() if host.status == "offline")
        
        # Security status summary
        security_summary = {
            'firewall_enabled': 0,
            'filevault_enabled': 0,
            'gatekeeper_enabled': 0,
            'sip_enabled': 0
        }
        
        for host in self.hosts.values():
            if host.security_status:
                if host.security_status.get('firewall'):
                    security_summary['firewall_enabled'] += 1
                if host.security_status.get('filevault'):
                    security_summary['filevault_enabled'] += 1
                if host.security_status.get('gatekeeper'):
                    security_summary['gatekeeper_enabled'] += 1
                if host.security_status.get('sip'):
                    security_summary['sip_enabled'] += 1
        
        return {
            'total_hosts': total_hosts,
            'online_hosts': online_hosts,
            'offline_hosts': offline_hosts,
            'error_hosts': total_hosts - online_hosts - offline_hosts,
            'security_summary': security_summary,
            'profiles_in_use': list(set(host.profile for host in self.hosts.values())),
            'tags_in_use': list(set(tag for host in self.hosts.values() for tag in host.tags)),
            'last_updated': datetime.now().isoformat()
        }

def main():
    """Main function for fleet management"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Albator Fleet Manager")
    parser.add_argument("--config", default="config/albator.yaml", help="Configuration file path")
    parser.add_argument("--fleet-config", default="config/fleet.yaml", help="Fleet configuration file path")
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Add host
    add_parser = subparsers.add_parser("add", help="Add host to fleet")
    add_parser.add_argument("hostname", help="Hostname")
    add_parser.add_argument("ip", help="IP address")
    add_parser.add_argument("username", help="SSH username")
    add_parser.add_argument("--ssh-key", help="SSH key path")
    add_parser.add_argument("--password", help="SSH password")
    add_parser.add_argument("--tags", nargs="*", help="Host tags")
    add_parser.add_argument("--profile", default="basic", help="Security profile")
    
    # Remove host
    remove_parser = subparsers.add_parser("remove", help="Remove host from fleet")
    remove_parser.add_argument("hostname", help="Hostname to remove")
    
    # List hosts
    list_parser = subparsers.add_parser("list", help="List fleet hosts")
    list_parser.add_argument("--tag", help="Filter by tag")
    list_parser.add_argument("--profile", help="Filter by profile")
    
    # Test connection
    test_parser = subparsers.add_parser("test", help="Test host connection")
    test_parser.add_argument("hostname", help="Hostname to test")
    
    # Get host info
    info_parser = subparsers.add_parser("info", help="Get host information")
    info_parser.add_parser("hostname", help="Hostname")
    
    # Deploy Albator
    deploy_parser = subparsers.add_parser("deploy", help="Deploy Albator to hosts")
    deploy_parser.add_argument("hostnames", nargs="*", help="Hostnames (empty for all)")
    
    # Run operation
    run_parser = subparsers.add_parser("run", help="Run fleet operation")
    run_parser.add_argument("operation", choices=["privacy", "firewall", "encryption", "app_security", "cve_fetch", "apple_updates"])
    run_parser.add_argument("--hosts", nargs="*", help="Target hostnames (empty for all)")
    run_parser.add_argument("--profile", default="basic", help="Security profile")
    run_parser.add_argument("--dry-run", action="store_true", help="Dry run mode")
    
    # Fleet summary
    subparsers.add_parser("summary", help="Show fleet summary")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize fleet manager
    fleet_manager = FleetManager(args.config, args.fleet_config)
    
    if args.command == "add":
        success = fleet_manager.add_host(
            args.hostname, args.ip, args.username,
            args.ssh_key, args.password, args.tags, args.profile
        )
        if success:
            print(f"Host {args.hostname} added to fleet")
        else:
            print(f"Failed to add host {args.hostname}")
    
    elif args.command == "remove":
        success = fleet_manager.remove_host(args.hostname)
        if success:
            print(f"Host {args.hostname} removed from fleet")
        else:
            print(f"Failed to remove host {args.hostname}")
    
    elif args.command == "list":
        hosts = list(fleet_manager.hosts.values())
        
        if args.tag:
            hosts = [h for h in hosts if args.tag in h.tags]
        if args.profile:
            hosts = [h for h in hosts if h.profile == args.profile]
        
        print(f"Fleet Hosts ({len(hosts)}):")
        print("-" * 60)
        for host in hosts:
            print(f"{host.hostname:20} {host.ip_address:15} {host.status:10} {host.profile}")
    
    elif args.command == "test":
        success, message = fleet_manager.test_host_connection(args.hostname)
        print(f"Connection test for {args.hostname}: {'SUCCESS' if success else 'FAILED'}")
        print(f"Message: {message}")
    
    elif args.command == "info":
        info = fleet_manager.get_host_info(args.hostname)
        if info:
            print(f"Host Information for {args.hostname}:")
            print("-" * 40)
            for key, value in info.items():
                print(f"{key:20}: {value}")
        else:
            print(f"Failed to get information for {args.hostname}")
    
    elif args.command == "deploy":
        hostnames = args.hostnames if args.hostnames else list(fleet_manager.hosts.keys())
        
        for hostname in hostnames:
            print(f"Deploying to {hostname}...")
            success = fleet_manager.deploy_albator_to_host(hostname)
            print(f"  {'SUCCESS' if success else 'FAILED'}")
    
    elif args.command == "run":
        operation_id = fleet_manager.run_fleet_operation(
            args.operation, args.hosts, args.profile, args.dry_run
        )
        if operation_id:
            print(f"Fleet operation started: {operation_id}")
            print("Use 'status' command to check progress")
        else:
            print("Failed to start fleet operation")
    
    elif args.command == "summary":
        summary = fleet_manager.get_fleet_summary()
        print("Fleet Summary:")
        print("=" * 40)
        print(f"Total Hosts: {summary['total_hosts']}")
        print(f"Online: {summary['online_hosts']}")
        print(f"Offline: {summary['offline_hosts']}")
        print(f"Error: {summary['error_hosts']}")
        print("\nSecurity Status:")
        for key, value in summary['security_summary'].items():
            print(f"  {key}: {value}/{summary['total_hosts']}")
        print(f"\nProfiles: {', '.join(summary['profiles_in_use'])}")
        print(f"Tags: {', '.join(summary['tags_in_use'])}")

if __name__ == "__main__":
    main()
