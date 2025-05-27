#!/usr/bin/env python3
"""
Albator Threat Detection System
Provides anomaly detection, threat intelligence integration, and automated incident response
"""

import os
import sys
import json
import subprocess
import requests
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import re
import sqlite3
import threading
import time

# Add lib directory to path for imports
sys.path.insert(0, os.path.dirname(__file__))
from logger import get_logger, log_operation_start, log_operation_success, log_operation_failure
from ml_security_engine import MLSecurityEngine
from zero_trust_security import ZeroTrustSecurity

@dataclass
class ThreatIndicator:
    """Represents a threat indicator"""
    indicator_id: str
    type: str  # ip, domain, file_hash, behavior
    value: str
    severity: str  # low, medium, high, critical
    source: str
    description: str
    created_at: str
    metadata: Dict[str, Any]

@dataclass
class SecurityIncident:
    """Represents a security incident"""
    incident_id: str
    detected_at: str
    type: str  # config_change, malware, intrusion, anomaly
    severity: str
    description: str
    affected_resources: List[str]
    indicators: List[ThreatIndicator]
    status: str  # detected, investigating, contained, resolved
    response_actions: List[Dict[str, Any]]

@dataclass
class ConfigurationChange:
    """Represents a system configuration change"""
    change_id: str
    timestamp: str
    file_path: str
    change_type: str  # created, modified, deleted
    old_value: Optional[str]
    new_value: Optional[str]
    risk_score: float
    authorized: bool

@dataclass
class ForensicArtifact:
    """Represents forensic data collected"""
    artifact_id: str
    collected_at: str
    type: str  # process, network, file, log
    data: Dict[str, Any]
    incident_id: Optional[str]
    hash_value: str

class ThreatDetectionSystem:
    """Threat Detection System for Albator"""
    
    def __init__(self):
        """Initialize Threat Detection System"""
        self.logger = get_logger("threat_detection")
        self.ml_engine = MLSecurityEngine()
        self.zero_trust = ZeroTrustSecurity()
        
        # Storage paths
        self.threat_store = Path.home() / ".albator" / "threat_detection"
        self.threat_store.mkdir(parents=True, exist_ok=True)
        
        # Initialize database
        self.db_path = self.threat_store / "threats.db"
        self._init_database()
        
        # Threat intelligence feeds
        self.threat_feeds = {
            "abuse_ch": "https://urlhaus.abuse.ch/downloads/json_recent/",
            "alienvault": "https://otx.alienvault.com/api/v1/pulses/subscribed",
            "threatfox": "https://threatfox-api.abuse.ch/api/v1/"
        }
        
        # Configuration baselines
        self.config_baselines = {}
        self._load_config_baselines()
        
        # Monitoring threads
        self.monitoring_active = False
        self.monitor_thread = None
    
    def _init_database(self):
        """Initialize SQLite database for threat data"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_indicators (
                indicator_id TEXT PRIMARY KEY,
                type TEXT,
                value TEXT,
                severity TEXT,
                source TEXT,
                description TEXT,
                created_at TEXT,
                metadata TEXT
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_incidents (
                incident_id TEXT PRIMARY KEY,
                detected_at TEXT,
                type TEXT,
                severity TEXT,
                description TEXT,
                affected_resources TEXT,
                indicators TEXT,
                status TEXT,
                response_actions TEXT
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS configuration_changes (
                change_id TEXT PRIMARY KEY,
                timestamp TEXT,
                file_path TEXT,
                change_type TEXT,
                old_value TEXT,
                new_value TEXT,
                risk_score REAL,
                authorized INTEGER
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS forensic_artifacts (
                artifact_id TEXT PRIMARY KEY,
                collected_at TEXT,
                type TEXT,
                data TEXT,
                incident_id TEXT,
                hash_value TEXT
            )
        """)
        
        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_indicators_type ON threat_indicators(type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON security_incidents(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_changes_timestamp ON configuration_changes(timestamp)")
        
        conn.commit()
        conn.close()
    
    def start_monitoring(self):
        """Start continuous threat monitoring"""
        log_operation_start("start_monitoring")
        
        try:
            if self.monitoring_active:
                self.logger.warning("Monitoring already active")
                return
            
            self.monitoring_active = True
            self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
            self.monitor_thread.start()
            
            log_operation_success("start_monitoring")
            self.logger.info("Threat monitoring started")
            
        except Exception as e:
            log_operation_failure("start_monitoring", str(e))
            raise
    
    def stop_monitoring(self):
        """Stop threat monitoring"""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        self.logger.info("Threat monitoring stopped")
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                # Check for configuration changes
                self.detect_config_anomalies()
                
                # Check for suspicious processes
                self._check_suspicious_processes()
                
                # Check network connections
                self._check_network_threats()
                
                # Update threat intelligence
                self.update_threat_intelligence()
                
                # Sleep for monitoring interval
                time.sleep(60)  # Check every minute
                
            except Exception as e:
                self.logger.error(f"Monitoring error: {e}")
    
    def detect_config_anomalies(self) -> List[ConfigurationChange]:
        """Detect anomalous configuration changes"""
        log_operation_start("detect_config_anomalies")
        
        try:
            changes = []
            
            # Monitor critical system files
            critical_files = [
                "/etc/hosts",
                "/etc/sudoers",
                "/etc/ssh/sshd_config",
                "/Library/LaunchDaemons",
                "/Library/LaunchAgents",
                "~/Library/LaunchAgents"
            ]
            
            for file_path in critical_files:
                expanded_path = os.path.expanduser(file_path)
                
                if os.path.exists(expanded_path):
                    # Calculate file hash
                    current_hash = self._calculate_file_hash(expanded_path)
                    
                    # Compare with baseline
                    baseline_hash = self.config_baselines.get(expanded_path)
                    
                    if baseline_hash and current_hash != baseline_hash:
                        # Configuration changed
                        change = self._analyze_config_change(expanded_path, baseline_hash, current_hash)
                        changes.append(change)
                        
                        # Check if change is authorized
                        if not change.authorized:
                            # Create security incident
                            self._create_config_change_incident(change)
                    
                    # Update baseline
                    self.config_baselines[expanded_path] = current_hash
            
            log_operation_success("detect_config_anomalies", {"changes_detected": len(changes)})
            return changes
            
        except Exception as e:
            log_operation_failure("detect_config_anomalies", str(e))
            return []
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of a file"""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            self.logger.error(f"Failed to hash file {file_path}: {e}")
            return ""
    
    def _analyze_config_change(self, file_path: str, old_hash: str, new_hash: str) -> ConfigurationChange:
        """Analyze a configuration change"""
        # Calculate risk score based on file criticality
        risk_scores = {
            "/etc/sudoers": 0.9,
            "/etc/hosts": 0.7,
            "/etc/ssh/sshd_config": 0.8,
            "/Library/LaunchDaemons": 0.8,
            "/Library/LaunchAgents": 0.7,
            "~/Library/LaunchAgents": 0.6
        }
        
        risk_score = risk_scores.get(file_path, 0.5)
        
        # Check if change is during maintenance window
        current_hour = datetime.now().hour
        authorized = 2 <= current_hour <= 4  # Maintenance window 2-4 AM
        
        change = ConfigurationChange(
            change_id=hashlib.sha256(f"{file_path}{new_hash}".encode()).hexdigest()[:16],
            timestamp=datetime.now().isoformat(),
            file_path=file_path,
            change_type="modified",
            old_value=old_hash,
            new_value=new_hash,
            risk_score=risk_score,
            authorized=authorized
        )
        
        # Store in database
        self._store_config_change(change)
        
        return change
    
    def _create_config_change_incident(self, change: ConfigurationChange):
        """Create security incident for unauthorized config change"""
        indicator = ThreatIndicator(
            indicator_id=hashlib.sha256(f"config_{change.change_id}".encode()).hexdigest()[:16],
            type="behavior",
            value=f"Unauthorized modification of {change.file_path}",
            severity="high" if change.risk_score > 0.7 else "medium",
            source="config_monitor",
            description=f"Critical system file modified outside maintenance window",
            created_at=datetime.now().isoformat(),
            metadata={"file_path": change.file_path, "risk_score": change.risk_score}
        )
        
        incident = SecurityIncident(
            incident_id=hashlib.sha256(f"incident_{change.change_id}".encode()).hexdigest()[:16],
            detected_at=datetime.now().isoformat(),
            type="config_change",
            severity=indicator.severity,
            description=f"Unauthorized configuration change detected: {change.file_path}",
            affected_resources=[change.file_path],
            indicators=[indicator],
            status="detected",
            response_actions=[]
        )
        
        # Store incident
        self._store_incident(incident)
        
        # Trigger automated response
        self.automated_incident_response(incident)
    
    def update_threat_intelligence(self):
        """Update threat intelligence from feeds"""
        log_operation_start("update_threat_intelligence")
        
        try:
            indicators_added = 0
            
            # Fetch from URLhaus (abuse.ch)
            try:
                response = requests.get(self.threat_feeds["abuse_ch"], timeout=30)
                if response.status_code == 200:
                    data = response.json()
                    for entry in data[:100]:  # Process latest 100
                        indicator = ThreatIndicator(
                            indicator_id=hashlib.sha256(entry['url'].encode()).hexdigest()[:16],
                            type="domain",
                            value=entry['url'],
                            severity="high",
                            source="abuse.ch",
                            description=entry.get('threat', 'Malicious URL'),
                            created_at=datetime.now().isoformat(),
                            metadata=entry
                        )
                        self._store_threat_indicator(indicator)
                        indicators_added += 1
            except Exception as e:
                self.logger.error(f"Failed to fetch URLhaus feed: {e}")
            
            log_operation_success("update_threat_intelligence", {"indicators_added": indicators_added})
            
        except Exception as e:
            log_operation_failure("update_threat_intelligence", str(e))
    
    def _check_suspicious_processes(self):
        """Check for suspicious processes"""
        try:
            # Get running processes
            result = subprocess.run(
                ["ps", "aux"],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                suspicious_patterns = [
                    r'nc\s+-l',  # Netcat listener
                    r'python.*SimpleHTTPServer',  # Python HTTP server
                    r'ruby.*-run\s+-e\s+httpd',  # Ruby HTTP server
                    r'/tmp/.*\.sh',  # Scripts from temp
                    r'curl.*\|.*sh',  # Curl pipe to shell
                    r'wget.*\|.*sh',  # Wget pipe to shell
                ]
                
                for line in result.stdout.split('\n'):
                    for pattern in suspicious_patterns:
                        if re.search(pattern, line):
                            # Suspicious process found
                            self._create_process_incident(line, pattern)
                            
        except Exception as e:
            self.logger.error(f"Failed to check processes: {e}")
    
    def _check_network_threats(self):
        """Check network connections for threats"""
        try:
            # Get network connections
            result = subprocess.run(
                ["netstat", "-an"],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                # Check against threat indicators
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute("SELECT value FROM threat_indicators WHERE type = 'ip'")
                threat_ips = set(row[0] for row in cursor.fetchall())
                
                for line in result.stdout.split('\n'):
                    if 'ESTABLISHED' in line:
                        # Extract IP addresses
                        parts = line.split()
                        if len(parts) >= 5:
                            foreign_addr = parts[4]
                            ip = foreign_addr.split(':')[0]
                            
                            if ip in threat_ips:
                                # Connection to known threat
                                self._create_network_incident(ip, line)
                
                conn.close()
                
        except Exception as e:
            self.logger.error(f"Failed to check network threats: {e}")
    
    def _create_process_incident(self, process_line: str, pattern: str):
        """Create incident for suspicious process"""
        indicator = ThreatIndicator(
            indicator_id=hashlib.sha256(process_line.encode()).hexdigest()[:16],
            type="behavior",
            value=f"Suspicious process matching: {pattern}",
            severity="high",
            source="process_monitor",
            description="Potentially malicious process detected",
            created_at=datetime.now().isoformat(),
            metadata={"process_line": process_line, "pattern": pattern}
        )
        
        incident = SecurityIncident(
            incident_id=hashlib.sha256(f"proc_{datetime.now().isoformat()}".encode()).hexdigest()[:16],
            detected_at=datetime.now().isoformat(),
            type="malware",
            severity="high",
            description="Suspicious process activity detected",
            affected_resources=["system_processes"],
            indicators=[indicator],
            status="detected",
            response_actions=[]
        )
        
        self._store_incident(incident)
        self.automated_incident_response(incident)
    
    def _create_network_incident(self, threat_ip: str, connection_info: str):
        """Create incident for network threat"""
        indicator = ThreatIndicator(
            indicator_id=hashlib.sha256(threat_ip.encode()).hexdigest()[:16],
            type="ip",
            value=threat_ip,
            severity="critical",
            source="network_monitor",
            description="Connection to known malicious IP",
            created_at=datetime.now().isoformat(),
            metadata={"connection": connection_info}
        )
        
        incident = SecurityIncident(
            incident_id=hashlib.sha256(f"net_{datetime.now().isoformat()}".encode()).hexdigest()[:16],
            detected_at=datetime.now().isoformat(),
            type="intrusion",
            severity="critical",
            description=f"Connection to known threat IP: {threat_ip}",
            affected_resources=["network"],
            indicators=[indicator],
            status="detected",
            response_actions=[]
        )
        
        self._store_incident(incident)
        self.automated_incident_response(incident)
    
    def automated_incident_response(self, incident: SecurityIncident):
        """Execute automated incident response"""
        log_operation_start("automated_incident_response", {"incident_id": incident.incident_id})
        
        try:
            response_actions = []
            
            if incident.severity in ["critical", "high"]:
                # Critical/High severity response
                
                # 1. Isolate system if network threat
                if incident.type == "intrusion":
                    action = self._isolate_network()
                    response_actions.append(action)
                
                # 2. Kill suspicious processes
                if incident.type == "malware":
                    action = self._kill_suspicious_processes(incident)
                    response_actions.append(action)
                
                # 3. Collect forensic data
                artifacts = self.collect_forensic_data(incident.incident_id)
                response_actions.append({
                    "action": "collect_forensics",
                    "status": "completed",
                    "artifacts": len(artifacts)
                })
                
                # 4. Notify security team
                self._send_security_alert(incident)
                response_actions.append({
                    "action": "notify_security",
                    "status": "completed"
                })
            
            # Update incident status
            incident.response_actions = response_actions
            incident.status = "investigating"
            self._update_incident(incident)
            
            log_operation_success("automated_incident_response", {
                "incident_id": incident.incident_id,
                "actions_taken": len(response_actions)
            })
            
        except Exception as e:
            log_operation_failure("automated_incident_response", str(e))
    
    def _isolate_network(self) -> Dict[str, Any]:
        """Isolate system from network"""
        try:
            # Enable firewall in restrictive mode
            subprocess.run(
                ["sudo", "/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", "on"],
                capture_output=True
            )
            
            # Block all incoming connections
            subprocess.run(
                ["sudo", "/usr/libexec/ApplicationFirewall/socketfilterfw", "--setblockall", "on"],
                capture_output=True
            )
            
            return {
                "action": "network_isolation",
                "status": "success",
                "details": "Firewall enabled with all incoming connections blocked"
            }
            
        except Exception as e:
            self.logger.error(f"Failed to isolate network: {e}")
            return {
                "action": "network_isolation",
                "status": "failed",
                "error": str(e)
            }
    
    def _kill_suspicious_processes(self, incident: SecurityIncident) -> Dict[str, Any]:
        """Kill suspicious processes identified in incident"""
        killed_processes = []
        
        try:
            for indicator in incident.indicators:
                if indicator.type == "behavior" and "process_line" in indicator.metadata:
                    process_line = indicator.metadata["process_line"]
                    # Extract PID
                    parts = process_line.split()
                    if len(parts) > 1:
                        pid = parts[1]
                        try:
                            subprocess.run(["kill", "-9", pid], capture_output=True)
                            killed_processes.append(pid)
                        except:
                            pass
            
            return {
                "action": "kill_processes",
                "status": "success",
                "killed_pids": killed_processes
            }
            
        except Exception as e:
            return {
                "action": "kill_processes",
                "status": "failed",
                "error": str(e)
            }
    
    def collect_forensic_data(self, incident_id: str) -> List[ForensicArtifact]:
        """Collect forensic data for incident"""
        log_operation_start("collect_forensic_data", {"incident_id": incident_id})
        
        artifacts = []
        
        try:
            # 1. Collect process information
            process_artifact = self._collect_process_info()
            process_artifact.incident_id = incident_id
            artifacts.append(process_artifact)
            
            # 2. Collect network connections
            network_artifact = self._collect_network_info()
            network_artifact.incident_id = incident_id
            artifacts.append(network_artifact)
            
            # 3. Collect system logs
            log_artifact = self._collect_system_logs()
            log_artifact.incident_id = incident_id
            artifacts.append(log_artifact)
            
            # 4. Collect file system changes
            fs_artifact = self._collect_filesystem_changes()
            fs_artifact.incident_id = incident_id
            artifacts.append(fs_artifact)
            
            # Store artifacts
            for artifact in artifacts:
                self._store_forensic_artifact(artifact)
            
            log_operation_success("collect_forensic_data", {"artifacts_collected": len(artifacts)})
            return artifacts
            
        except Exception as e:
            log_operation_failure("collect_forensic_data", str(e))
            return artifacts
    
    def _collect_process_info(self) -> ForensicArtifact:
        """Collect process information"""
        data = {}
        
        try:
            # Get process list
            result = subprocess.run(["ps", "aux"], capture_output=True, text=True)
            data["process_list"] = result.stdout
            
            # Get open files
            result = subprocess.run(["lsof"], capture_output=True, text=True)
            data["open_files"] = result.stdout[:10000]  # Limit size
            
        except Exception as e:
            data["error"] = str(e)
        
        artifact_data = json.dumps(data)
        return ForensicArtifact(
            artifact_id=hashlib.sha256(f"proc_{datetime.now().isoformat()}".encode()).hexdigest()[:16],
            collected_at=datetime.now().isoformat(),
            type="process",
            data=data,
            incident_id=None,
            hash_value=hashlib.sha256(artifact_data.encode()).hexdigest()
        )
    
    def _collect_network_info(self) -> ForensicArtifact:
        """Collect network information"""
        data = {}
        
        try:
            # Get network connections
            result = subprocess.run(["netstat", "-an"], capture_output=True, text=True)
            data["connections"] = result.stdout
            
            # Get routing table
            result = subprocess.run(["netstat", "-rn"], capture_output=True, text=True)
            data["routes"] = result.stdout
            
            # Get ARP cache
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
            data["arp_cache"] = result.stdout
            
        except Exception as e:
            data["error"] = str(e)
        
        artifact_data = json.dumps(data)
        return ForensicArtifact(
            artifact_id=hashlib.sha256(f"net_{datetime.now().isoformat()}".encode()).hexdigest()[:16],
            collected_at=datetime.now().isoformat(),
            type="network",
            data=data,
            incident_id=None,
            hash_value=hashlib.sha256(artifact_data.encode()).hexdigest()
        )
    
    def _collect_system_logs(self) -> ForensicArtifact:
        """Collect system logs"""
        data = {}
        
        try:
            # Get recent system log entries
            result = subprocess.run(
                ["log", "show", "--predicate", "eventMessage contains 'error' or eventMessage contains 'fail'", 
                 "--last", "1h"],
                capture_output=True,
                text=True
            )
            data["system_logs"] = result.stdout[:50000]  # Limit size
            
        except Exception as e:
            data["error"] = str(e)
        
        artifact_data = json.dumps(data)
        return ForensicArtifact(
            artifact_id=hashlib.sha256(f"log_{datetime.now().isoformat()}".encode()).hexdigest()[:16],
            collected_at=datetime.now().isoformat(),
            type="log",
            data=data,
            incident_id=None,
            hash_value=hashlib.sha256(artifact_data.encode()).hexdigest()
        )
    
    def _collect_filesystem_changes(self) -> ForensicArtifact:
        """Collect recent filesystem changes"""
        data = {}
        
        try:
            # Find recently modified files
            result = subprocess.run(
                ["find", "/tmp", "/var/tmp", "-type", "f", "-mtime", "-1"],
                capture_output=True,
                text=True
            )
            data["recent_tmp_files"] = result.stdout
            
            # Check for new LaunchAgents
            paths = ["/Library/LaunchAgents", "/Library/LaunchDaemons", 
                    os.path.expanduser("~/Library/LaunchAgents")]
            
            new_agents = []
            for path in paths:
                if os.path.exists(path):
                    result = subprocess.run(
                        ["find", path, "-type", "f", "-mtime", "-7"],
                        capture_output=True,
                        text=True
                    )
                    if result.stdout:
                        new_agents.append({"path": path, "files": result.stdout})
            
            data["new_launch_agents"] = new_agents
            
        except Exception as e:
            data["error"] = str(e)
        
        artifact_data = json.dumps(data)
        return ForensicArtifact(
            artifact_id=hashlib.sha256(f"fs_{datetime.now().isoformat()}".encode()).hexdigest()[:16],
            collected_at=datetime.now().isoformat(),
            type="file",
            data=data,
            incident_id=None,
            hash_value=hashlib.sha256(artifact_data.encode()).hexdigest()
        )
    
    def perform_threat_hunt(self, ioc_list: List[str]) -> List[ThreatIndicator]:
        """Perform threat hunting with given indicators of compromise"""
        log_operation_start("perform_threat_hunt", {"ioc_count": len(ioc_list)})
        
        found_threats = []
        
        try:
            for ioc in ioc_list:
                # Determine IOC type
                ioc_type = self._determine_ioc_type(ioc)
                
                if ioc_type == "ip":
                    threats = self._hunt_ip_ioc(ioc)
                elif ioc_type == "domain":
                    threats = self._hunt_domain_ioc(ioc)
                elif ioc_type == "file_hash":
                    threats = self._hunt_filehash_ioc(ioc)
                else:
                    threats = self._hunt_generic_ioc(ioc)
                
                found_threats.extend(threats)
            
            log_operation_success("perform_threat_hunt", {"threats_found": len(found_threats)})
            return found_threats
            
        except Exception as e:
            log_operation_failure("perform_threat_hunt", str(e))
            return found_threats
    
    def _determine_ioc_type(self, ioc: str) -> str:
        """Determine the type of an IOC"""
        # IP address pattern
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc):
            return "ip"
        # Domain pattern
        elif re.match(r'^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9])*$', ioc):
            return "domain"
        # SHA256 hash pattern
        elif re.match(r'^[a-fA-F0-9]{64}$', ioc):
            return "file_hash"
        else:
            return "generic"
    
    def _hunt_ip_ioc(self, ip: str) -> List[ThreatIndicator]:
        """Hunt for IP-based IOC"""
        threats = []
        
        try:
            # Check current connections
            result = subprocess.run(["netstat", "-an"], capture_output=True, text=True)
            if ip in result.stdout:
                threat = ThreatIndicator(
                    indicator_id=hashlib.sha256(f"hunt_ip_{ip}_{datetime.now()}".encode()).hexdigest()[:16],
                    type="ip",
                    value=ip,
                    severity="high",
                    source="threat_hunt",
                    description=f"Active connection to IOC IP: {ip}",
                    created_at=datetime.now().isoformat(),
                    metadata={"connection_found": True}
                )
                threats.append(threat)
                self._store_threat_indicator(threat)
                
        except Exception as e:
            self.logger.error(f"Error hunting IP IOC: {e}")
        
        return threats
    
    def _hunt_domain_ioc(self, domain: str) -> List[ThreatIndicator]:
        """Hunt for domain-based IOC"""
        threats = []
        
        try:
            # Check DNS cache
            result = subprocess.run(["dscacheutil", "-cachedump"], capture_output=True, text=True)
            if domain in result.stdout:
                threat = ThreatIndicator(
                    indicator_id=hashlib.sha256(f"hunt_domain_{domain}_{datetime.now()}".encode()).hexdigest()[:16],
                    type="domain",
                    value=domain,
                    severity="medium",
                    source="threat_hunt",
                    description=f"IOC domain found in DNS cache: {domain}",
                    created_at=datetime.now().isoformat(),
                    metadata={"dns_cache": True}
                )
                threats.append(threat)
                self._store_threat_indicator(threat)
                
        except Exception as e:
            self.logger.error(f"Error hunting domain IOC: {e}")
        
        return threats
    
    def _hunt_filehash_ioc(self, file_hash: str) -> List[ThreatIndicator]:
        """Hunt for file hash IOC"""
        threats = []
        
        try:
            # Search for files with matching hash
            search_paths = ["/Applications", "/tmp", "/var/tmp", 
                          os.path.expanduser("~/Downloads"), 
                          os.path.expanduser("~/Desktop")]
            
            for search_path in search_paths:
                if os.path.exists(search_path):
                    for root, dirs, files in os.walk(search_path):
                        for file in files:
                            file_path = os.path.join(root, file)
                            try:
                                if self._calculate_file_hash(file_path) == file_hash:
                                    threat = ThreatIndicator(
                                        indicator_id=hashlib.sha256(f"hunt_hash_{file_hash}_{file_path}".encode()).hexdigest()[:16],
                                        type="file_hash",
                                        value=file_hash,
                                        severity="critical",
                                        source="threat_hunt",
                                        description=f"Malicious file found: {file_path}",
                                        created_at=datetime.now().isoformat(),
                                        metadata={"file_path": file_path}
                                    )
                                    threats.append(threat)
                                    self._store_threat_indicator(threat)
                            except:
                                continue
                                
        except Exception as e:
            self.logger.error(f"Error hunting file hash IOC: {e}")
        
        return threats
    
    def _hunt_generic_ioc(self, ioc: str) -> List[ThreatIndicator]:
        """Hunt for generic IOC"""
        threats = []
        
        try:
            # Search in running processes
            result = subprocess.run(["ps", "aux"], capture_output=True, text=True)
            if ioc in result.stdout:
                threats.append(ThreatIndicator(
                    indicator_id=hashlib.sha256(f"hunt_generic_proc_{ioc}".encode()).hexdigest()[:16],
                    type="generic",
                    value=ioc,
                    severity="medium",
                    source="threat_hunt",
                    description=f"IOC found in process list: {ioc}",
                    created_at=datetime.now().isoformat(),
                    metadata={"found_in": "processes"}
                ))
            
            # Search in system logs
            result = subprocess.run(
                ["log", "show", "--last", "1h"],
                capture_output=True,
                text=True
            )
            if ioc in result.stdout:
                threats.append(ThreatIndicator(
                    indicator_id=hashlib.sha256(f"hunt_generic_log_{ioc}".encode()).hexdigest()[:16],
                    type="generic",
                    value=ioc,
                    severity="medium",
                    source="threat_hunt",
                    description=f"IOC found in system logs: {ioc}",
                    created_at=datetime.now().isoformat(),
                    metadata={"found_in": "logs"}
                ))
                
        except Exception as e:
            self.logger.error(f"Error hunting generic IOC: {e}")
        
        return threats
    
    def _load_config_baselines(self):
        """Load configuration baselines from storage"""
        baseline_file = self.threat_store / "config_baselines.json"
        try:
            if baseline_file.exists():
                with open(baseline_file, 'r') as f:
                    self.config_baselines = json.load(f)
            else:
                # Initialize baselines for critical files
                self._create_initial_baselines()
        except Exception as e:
            self.logger.error(f"Failed to load config baselines: {e}")
    
    def _create_initial_baselines(self):
        """Create initial configuration baselines"""
        critical_files = [
            "/etc/hosts",
            "/etc/sudoers",
            "/etc/ssh/sshd_config",
            "/Library/LaunchDaemons",
            "/Library/LaunchAgents",
            "~/Library/LaunchAgents"
        ]
        
        for file_path in critical_files:
            expanded_path = os.path.expanduser(file_path)
            if os.path.exists(expanded_path):
                hash_value = self._calculate_file_hash(expanded_path)
                if hash_value:
                    self.config_baselines[expanded_path] = hash_value
        
        # Save baselines
        self._save_config_baselines()
    
    def _save_config_baselines(self):
        """Save configuration baselines"""
        baseline_file = self.threat_store / "config_baselines.json"
        try:
            with open(baseline_file, 'w') as f:
                json.dump(self.config_baselines, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save config baselines: {e}")
    
    def _send_security_alert(self, incident: SecurityIncident):
        """Send security alert (placeholder for notification system)"""
        self.logger.critical(f"SECURITY ALERT: {incident.severity.upper()} - {incident.description}")
        # In production, this would send email/SMS/Slack notifications
    
    def _store_threat_indicator(self, indicator: ThreatIndicator):
        """Store threat indicator in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT OR REPLACE INTO threat_indicators 
                (indicator_id, type, value, severity, source, description, created_at, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                indicator.indicator_id,
                indicator.type,
                indicator.value,
                indicator.severity,
                indicator.source,
                indicator.description,
                indicator.created_at,
                json.dumps(indicator.metadata)
            ))
            conn.commit()
        except Exception as e:
            self.logger.error(f"Failed to store threat indicator: {e}")
        finally:
            conn.close()
    
    def _store_incident(self, incident: SecurityIncident):
        """Store security incident in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT OR REPLACE INTO security_incidents 
                (incident_id, detected_at, type, severity, description, 
                 affected_resources, indicators, status, response_actions)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                incident.incident_id,
                incident.detected_at,
                incident.type,
                incident.severity,
                incident.description,
                json.dumps(incident.affected_resources),
                json.dumps([asdict(i) for i in incident.indicators]),
                incident.status,
                json.dumps(incident.response_actions)
            ))
            conn.commit()
        except Exception as e:
            self.logger.error(f"Failed to store incident: {e}")
        finally:
            conn.close()
    
    def _update_incident(self, incident: SecurityIncident):
        """Update existing incident"""
        self._store_incident(incident)  # Same as store with INSERT OR REPLACE
    
    def _store_config_change(self, change: ConfigurationChange):
        """Store configuration change in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT OR REPLACE INTO configuration_changes 
                (change_id, timestamp, file_path, change_type, old_value, 
                 new_value, risk_score, authorized)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                change.change_id,
                change.timestamp,
                change.file_path,
                change.change_type,
                change.old_value,
                change.new_value,
                change.risk_score,
                1 if change.authorized else 0
            ))
            conn.commit()
        except Exception as e:
            self.logger.error(f"Failed to store config change: {e}")
        finally:
            conn.close()
    
    def _store_forensic_artifact(self, artifact: ForensicArtifact):
        """Store forensic artifact in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT OR REPLACE INTO forensic_artifacts 
                (artifact_id, collected_at, type, data, incident_id, hash_value)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                artifact.artifact_id,
                artifact.collected_at,
                artifact.type,
                json.dumps(artifact.data),
                artifact.incident_id,
                artifact.hash_value
            ))
            conn.commit()
        except Exception as e:
            self.logger.error(f"Failed to store forensic artifact: {e}")
        finally:
            conn.close()
    
    def get_threat_summary(self) -> Dict[str, Any]:
        """Get summary of threats and incidents"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        summary = {}
        
        try:
            # Count indicators by type
            cursor.execute("SELECT type, COUNT(*) FROM threat_indicators GROUP BY type")
            summary['indicators_by_type'] = dict(cursor.fetchall())
            
            # Count incidents by status
            cursor.execute("SELECT status, COUNT(*) FROM security_incidents GROUP BY status")
            summary['incidents_by_status'] = dict(cursor.fetchall())
            
            # Recent incidents
            cursor.execute("""
                SELECT incident_id, detected_at, type, severity, description 
                FROM security_incidents 
                ORDER BY detected_at DESC 
                LIMIT 10
            """)
            summary['recent_incidents'] = [
                {
                    'incident_id': row[0],
                    'detected_at': row[1],
                    'type': row[2],
                    'severity': row[3],
                    'description': row[4]
                }
                for row in cursor.fetchall()
            ]
            
        except Exception as e:
            self.logger.error(f"Failed to get threat summary: {e}")
        finally:
            conn.close()
        
        return summary

def main():
    """Main function for Threat Detection System"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Albator Threat Detection System")
    parser.add_argument("command", choices=["monitor", "hunt", "incidents", "forensics", "demo"])
    parser.add_argument("--start", action="store_true", help="Start monitoring")
    parser.add_argument("--stop", action="store_true", help="Stop monitoring")
    parser.add_argument("--iocs", nargs='+', help="IOCs for threat hunting")
    parser.add_argument("--incident", help="Incident ID for forensics")
    
    args = parser.parse_args()
    
    # Initialize Threat Detection System
    tds = ThreatDetectionSystem()
    
    if args.command == "monitor":
        if args.start:
            print("🛡️  Starting Threat Monitoring...")
            tds.start_monitoring()
            print("✅ Monitoring active. Press Ctrl+C to stop.")
            
            try:
                # Keep running until interrupted
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n⏹️  Stopping monitoring...")
                tds.stop_monitoring()
                
        elif args.stop:
            tds.stop_monitoring()
            print("✅ Monitoring stopped.")
        else:
            print("Use --start or --stop flag")
    
    elif args.command == "hunt":
        if not args.iocs:
            print("❌ Please provide IOCs with --iocs flag")
            return
        
        print(f"🔍 Hunting for {len(args.iocs)} IOCs...")
        threats = tds.perform_threat_hunt(args.iocs)
        
        if threats:
            print(f"\n⚠️  Found {len(threats)} threats:")
            for threat in threats:
                print(f"  - {threat.type}: {threat.value}")
                print(f"    {threat.description}")
        else:
            print("✅ No threats found.")
    
    elif args.command == "incidents":
        print("📊 Threat Summary")
        print("=" * 50)
        
        summary = tds.get_threat_summary()
        
        print("\nIndicators by Type:")
        for ioc_type, count in summary.get('indicators_by_type', {}).items():
            print(f"  {ioc_type}: {count}")
        
        print("\nIncidents by Status:")
        for status, count in summary.get('incidents_by_status', {}).items():
            print(f"  {status}: {count}")
        
        print("\nRecent Incidents:")
        for incident in summary.get('recent_incidents', []):
            print(f"  [{incident['severity'].upper()}] {incident['type']} - {incident['description']}")
            print(f"    ID: {incident['incident_id']} | Time: {incident['detected_at']}")
    
    elif args.command == "forensics":
        if not args.incident:
            print("❌ Please provide incident ID with --incident flag")
            return
        
        print(f"🔬 Collecting Forensic Data for Incident: {args.incident}")
        artifacts = tds.collect_forensic_data(args.incident)
        
        print(f"\n✅ Collected {len(artifacts)} forensic artifacts:")
        for artifact in artifacts:
            print(f"  - {artifact.type}: {artifact.artifact_id}")
            print(f"    Hash: {artifact.hash_value[:16]}...")
    
    elif args.command == "demo":
        print("🚀 Albator Threat Detection Demo")
        print("=" * 50)
        
        # 1. Configuration Monitoring
        print("\n1. Checking for Configuration Anomalies...")
        changes = tds.detect_config_anomalies()
        print(f"   Found {len(changes)} configuration changes")
        
        # 2. Threat Intelligence Update
        print("\n2. Updating Threat Intelligence...")
        tds.update_threat_intelligence()
        
        # 3. Threat Hunting
        print("\n3. Performing Threat Hunt...")
        demo_iocs = ["192.168.1.100", "malicious.com", "a" * 64]
        threats = tds.perform_threat_hunt(demo_iocs)
        print(f"   Checked {len(demo_iocs)} IOCs, found {len(threats)} threats")
        
        # 4. Summary
        print("\n4. Threat Summary:")
        summary = tds.get_threat_summary()
        total_indicators = sum(summary.get('indicators_by_type', {}).values())
        total_incidents = sum(summary.get('incidents_by_status', {}).values())
        print(f"   Total Indicators: {total_indicators}")
        print(f"   Total Incidents: {total_incidents}")
        
        print("\n✅ Threat Detection Demo Complete!")

if __name__ == "__main__":
    main()
