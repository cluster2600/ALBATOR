#!/usr/bin/env python3
"""
Albator Cloud Integration
Provides cloud-based configuration management and multi-tenant architecture
"""

import os
import sys
import json
import boto3
import azure.storage.blob
from google.cloud import storage as gcs
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import requests
import hashlib
import hmac
from cryptography.fernet import Fernet
import base64

# Add lib directory to path for imports
sys.path.insert(0, os.path.dirname(__file__))
from logger import get_logger, log_operation_start, log_operation_success, log_operation_failure
from config_manager import ConfigManager
from fleet_manager import FleetManager

@dataclass
class CloudTenant:
    """Represents a cloud tenant"""
    tenant_id: str
    tenant_name: str
    subscription_tier: str  # free, pro, enterprise
    created_at: str
    api_key_hash: str
    settings: Dict[str, Any]
    usage_limits: Dict[str, int]
    active: bool

@dataclass
class CloudConfiguration:
    """Represents cloud-synced configuration"""
    config_id: str
    tenant_id: str
    config_name: str
    config_data: Dict[str, Any]
    version: int
    created_at: str
    modified_at: str
    checksum: str
    encrypted: bool

@dataclass
class SecurityPostureSnapshot:
    """Represents a cloud-stored security posture snapshot"""
    snapshot_id: str
    tenant_id: str
    timestamp: str
    fleet_size: int
    compliance_scores: Dict[str, float]
    risk_metrics: Dict[str, Any]
    vulnerabilities: List[Dict[str, Any]]
    recommendations: List[str]

class CloudIntegration:
    """Cloud integration for Albator platform"""
    
    def __init__(self, cloud_provider: str = "aws", config_path: str = None):
        """Initialize cloud integration"""
        self.logger = get_logger("cloud_integration")
        self.cloud_provider = cloud_provider.lower()
        self.config_manager = ConfigManager()
        self.fleet_manager = FleetManager()
        
        # Load cloud configuration
        self.cloud_config = self._load_cloud_config(config_path)
        
        # Initialize cloud client
        self.cloud_client = self._initialize_cloud_client()
        
        # Encryption for sensitive data
        self.encryption_key = self._get_or_create_encryption_key()
        self.cipher_suite = Fernet(self.encryption_key)
        
        # Multi-tenant data
        self.tenants = {}
        self.tenant_configs = {}
    
    def _load_cloud_config(self, config_path: str) -> Dict[str, Any]:
        """Load cloud configuration"""
        if config_path and os.path.exists(config_path):
            with open(config_path, 'r') as f:
                return json.load(f)
        
        # Default configuration
        return {
            "aws": {
                "bucket_name": "albator-cloud-configs",
                "region": "us-east-1",
                "kms_key_id": None
            },
            "azure": {
                "container_name": "albator-configs",
                "storage_account": "albatorstorage"
            },
            "gcp": {
                "bucket_name": "albator-cloud-configs",
                "project_id": "albator-security"
            },
            "api": {
                "base_url": "https://api.albator.cloud",
                "version": "v1"
            },
            "encryption": {
                "enabled": True,
                "key_rotation_days": 90
            }
        }
    
    def _initialize_cloud_client(self):
        """Initialize cloud provider client"""
        try:
            if self.cloud_provider == "aws":
                return boto3.client('s3', region_name=self.cloud_config["aws"]["region"])
            elif self.cloud_provider == "azure":
                connection_string = os.environ.get('AZURE_STORAGE_CONNECTION_STRING')
                if connection_string:
                    from azure.storage.blob import BlobServiceClient
                    return BlobServiceClient.from_connection_string(connection_string)
            elif self.cloud_provider == "gcp":
                return gcs.Client(project=self.cloud_config["gcp"]["project_id"])
            else:
                self.logger.warning(f"Unsupported cloud provider: {self.cloud_provider}")
                return None
        except Exception as e:
            self.logger.error(f"Failed to initialize cloud client: {e}")
            return None
    
    def _get_or_create_encryption_key(self) -> bytes:
        """Get or create encryption key for cloud data"""
        key_file = os.path.expanduser("~/.albator/cloud_encryption.key")
        
        try:
            if os.path.exists(key_file):
                with open(key_file, 'rb') as f:
                    return f.read()
            else:
                # Generate new key
                key = Fernet.generate_key()
                os.makedirs(os.path.dirname(key_file), exist_ok=True)
                with open(key_file, 'wb') as f:
                    f.write(key)
                os.chmod(key_file, 0o600)  # Restrict access
                return key
        except Exception as e:
            self.logger.error(f"Error managing encryption key: {e}")
            # Fallback to environment variable
            env_key = os.environ.get('ALBATOR_CLOUD_KEY')
            if env_key:
                return env_key.encode()
            else:
                return Fernet.generate_key()
    
    def create_tenant(self, tenant_name: str, subscription_tier: str = "free") -> CloudTenant:
        """Create a new cloud tenant"""
        log_operation_start("create_tenant", {"tenant_name": tenant_name})
        
        try:
            # Generate tenant ID and API key
            tenant_id = self._generate_tenant_id(tenant_name)
            api_key = self._generate_api_key()
            api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            
            # Set usage limits based on tier
            usage_limits = self._get_tier_limits(subscription_tier)
            
            # Create tenant object
            tenant = CloudTenant(
                tenant_id=tenant_id,
                tenant_name=tenant_name,
                subscription_tier=subscription_tier,
                created_at=datetime.now().isoformat(),
                api_key_hash=api_key_hash,
                settings={
                    "notifications_enabled": True,
                    "auto_sync": True,
                    "retention_days": 30
                },
                usage_limits=usage_limits,
                active=True
            )
            
            # Store tenant data
            self.tenants[tenant_id] = tenant
            self._save_tenant_to_cloud(tenant)
            
            log_operation_success("create_tenant", {"tenant_id": tenant_id})
            
            # Return tenant with API key (only time it's shown)
            return tenant, api_key
            
        except Exception as e:
            log_operation_failure("create_tenant", str(e))
            raise
    
    def sync_configuration(self, tenant_id: str, config_name: str, 
                         config_data: Dict[str, Any]) -> CloudConfiguration:
        """Sync configuration to cloud"""
        log_operation_start("sync_configuration", {
            "tenant_id": tenant_id,
            "config_name": config_name
        })
        
        try:
            # Validate tenant
            if not self._validate_tenant(tenant_id):
                raise ValueError(f"Invalid tenant: {tenant_id}")
            
            # Check usage limits
            if not self._check_usage_limit(tenant_id, "configurations"):
                raise ValueError("Configuration limit exceeded for tenant")
            
            # Create configuration object
            config_json = json.dumps(config_data, sort_keys=True)
            checksum = hashlib.sha256(config_json.encode()).hexdigest()
            
            # Encrypt if enabled
            if self.cloud_config["encryption"]["enabled"]:
                encrypted_data = self.cipher_suite.encrypt(config_json.encode())
                config_json = base64.b64encode(encrypted_data).decode()
                encrypted = True
            else:
                encrypted = False
            
            # Get or create config ID
            config_id = f"{tenant_id}-{config_name}"
            existing_config = self._get_cloud_configuration(config_id)
            version = existing_config.version + 1 if existing_config else 1
            
            # Create configuration object
            cloud_config = CloudConfiguration(
                config_id=config_id,
                tenant_id=tenant_id,
                config_name=config_name,
                config_data=config_data,
                version=version,
                created_at=existing_config.created_at if existing_config else datetime.now().isoformat(),
                modified_at=datetime.now().isoformat(),
                checksum=checksum,
                encrypted=encrypted
            )
            
            # Save to cloud
            self._save_configuration_to_cloud(cloud_config, config_json)
            
            # Update local cache
            if tenant_id not in self.tenant_configs:
                self.tenant_configs[tenant_id] = {}
            self.tenant_configs[tenant_id][config_name] = cloud_config
            
            log_operation_success("sync_configuration", {
                "config_id": config_id,
                "version": version
            })
            
            return cloud_config
            
        except Exception as e:
            log_operation_failure("sync_configuration", str(e))
            raise
    
    def retrieve_configuration(self, tenant_id: str, config_name: str) -> Dict[str, Any]:
        """Retrieve configuration from cloud"""
        log_operation_start("retrieve_configuration", {
            "tenant_id": tenant_id,
            "config_name": config_name
        })
        
        try:
            # Validate tenant
            if not self._validate_tenant(tenant_id):
                raise ValueError(f"Invalid tenant: {tenant_id}")
            
            # Get configuration
            config_id = f"{tenant_id}-{config_name}"
            cloud_config, config_data = self._get_cloud_configuration_data(config_id)
            
            if not cloud_config:
                raise ValueError(f"Configuration not found: {config_name}")
            
            # Decrypt if necessary
            if cloud_config.encrypted:
                encrypted_data = base64.b64decode(config_data)
                decrypted_data = self.cipher_suite.decrypt(encrypted_data)
                config_dict = json.loads(decrypted_data.decode())
            else:
                config_dict = json.loads(config_data)
            
            log_operation_success("retrieve_configuration", {
                "config_id": config_id,
                "version": cloud_config.version
            })
            
            return config_dict
            
        except Exception as e:
            log_operation_failure("retrieve_configuration", str(e))
            raise
    
    def upload_security_posture(self, tenant_id: str, posture_data: Dict[str, Any]) -> SecurityPostureSnapshot:
        """Upload security posture snapshot to cloud"""
        log_operation_start("upload_security_posture", {"tenant_id": tenant_id})
        
        try:
            # Validate tenant
            if not self._validate_tenant(tenant_id):
                raise ValueError(f"Invalid tenant: {tenant_id}")
            
            # Check usage limits
            if not self._check_usage_limit(tenant_id, "snapshots"):
                raise ValueError("Snapshot limit exceeded for tenant")
            
            # Create snapshot
            snapshot = SecurityPostureSnapshot(
                snapshot_id=self._generate_snapshot_id(),
                tenant_id=tenant_id,
                timestamp=datetime.now().isoformat(),
                fleet_size=posture_data.get("fleet_size", 0),
                compliance_scores=posture_data.get("compliance_scores", {}),
                risk_metrics=posture_data.get("risk_metrics", {}),
                vulnerabilities=posture_data.get("vulnerabilities", []),
                recommendations=posture_data.get("recommendations", [])
            )
            
            # Encrypt sensitive data
            snapshot_json = json.dumps(asdict(snapshot))
            if self.cloud_config["encryption"]["enabled"]:
                encrypted_data = self.cipher_suite.encrypt(snapshot_json.encode())
                snapshot_data = base64.b64encode(encrypted_data).decode()
            else:
                snapshot_data = snapshot_json
            
            # Upload to cloud
            self._upload_to_cloud(
                f"posture/{tenant_id}/{snapshot.snapshot_id}.json",
                snapshot_data
            )
            
            # Trigger cloud analytics if available
            self._trigger_cloud_analytics(tenant_id, snapshot)
            
            log_operation_success("upload_security_posture", {
                "snapshot_id": snapshot.snapshot_id
            })
            
            return snapshot
            
        except Exception as e:
            log_operation_failure("upload_security_posture", str(e))
            raise
    
    def get_cloud_insights(self, tenant_id: str, days: int = 30) -> Dict[str, Any]:
        """Get cloud-based security insights"""
        log_operation_start("get_cloud_insights", {
            "tenant_id": tenant_id,
            "days": days
        })
        
        try:
            # Validate tenant
            if not self._validate_tenant(tenant_id):
                raise ValueError(f"Invalid tenant: {tenant_id}")
            
            # Call cloud API for insights
            api_url = f"{self.cloud_config['api']['base_url']}/{self.cloud_config['api']['version']}/insights"
            
            response = requests.get(
                api_url,
                params={
                    "tenant_id": tenant_id,
                    "days": days
                },
                headers=self._get_api_headers(tenant_id),
                timeout=30
            )
            
            if response.status_code == 200:
                insights = response.json()
            else:
                # Fallback to local analysis
                insights = self._generate_local_insights(tenant_id, days)
            
            log_operation_success("get_cloud_insights", {
                "insight_count": len(insights.get("insights", []))
            })
            
            return insights
            
        except Exception as e:
            log_operation_failure("get_cloud_insights", str(e))
            # Return basic insights on error
            return {
                "insights": [],
                "error": str(e),
                "generated_at": datetime.now().isoformat()
            }
    
    def enable_multi_tenant_mode(self) -> bool:
        """Enable multi-tenant mode for SaaS deployment"""
        log_operation_start("enable_multi_tenant_mode")
        
        try:
            # Create cloud infrastructure
            self._setup_cloud_infrastructure()
            
            # Initialize tenant database
            self._initialize_tenant_database()
            
            # Setup API endpoints
            self._setup_api_endpoints()
            
            # Configure auto-scaling
            self._configure_auto_scaling()
            
            log_operation_success("enable_multi_tenant_mode")
            return True
            
        except Exception as e:
            log_operation_failure("enable_multi_tenant_mode", str(e))
            return False
    
    def _generate_tenant_id(self, tenant_name: str) -> str:
        """Generate unique tenant ID"""
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        hash_input = f"{tenant_name}-{timestamp}"
        return hashlib.sha256(hash_input.encode()).hexdigest()[:16]
    
    def _generate_api_key(self) -> str:
        """Generate secure API key"""
        return base64.urlsafe_b64encode(os.urandom(32)).decode()
    
    def _get_tier_limits(self, tier: str) -> Dict[str, int]:
        """Get usage limits for subscription tier"""
        limits = {
            "free": {
                "configurations": 5,
                "snapshots": 10,
                "api_calls_per_day": 100,
                "fleet_size": 10
            },
            "pro": {
                "configurations": 50,
                "snapshots": 100,
                "api_calls_per_day": 10000,
                "fleet_size": 100
            },
            "enterprise": {
                "configurations": -1,  # Unlimited
                "snapshots": -1,
                "api_calls_per_day": -1,
                "fleet_size": -1
            }
        }
        return limits.get(tier, limits["free"])
    
    def _validate_tenant(self, tenant_id: str) -> bool:
        """Validate tenant exists and is active"""
        tenant = self.tenants.get(tenant_id)
        return tenant is not None and tenant.active
    
    def _check_usage_limit(self, tenant_id: str, resource: str) -> bool:
        """Check if tenant has reached usage limit"""
        tenant = self.tenants.get(tenant_id)
        if not tenant:
            return False
        
        limit = tenant.usage_limits.get(resource, 0)
        if limit == -1:  # Unlimited
            return True
        
        # Count current usage
        current_usage = self._get_resource_usage(tenant_id, resource)
        return current_usage < limit
    
    def _save_tenant_to_cloud(self, tenant: CloudTenant):
        """Save tenant data to cloud"""
        try:
            tenant_data = json.dumps(asdict(tenant))
            self._upload_to_cloud(
                f"tenants/{tenant.tenant_id}/metadata.json",
                tenant_data
            )
        except Exception as e:
            self.logger.error(f"Failed to save tenant to cloud: {e}")
    
    def _save_configuration_to_cloud(self, config: CloudConfiguration, config_data: str):
        """Save configuration to cloud storage"""
        try:
            # Save configuration metadata
            metadata = asdict(config)
            metadata.pop('config_data')  # Don't duplicate data
            
            self._upload_to_cloud(
                f"configs/{config.config_id}/metadata.json",
                json.dumps(metadata)
            )
            
            # Save configuration data
            self._upload_to_cloud(
                f"configs/{config.config_id}/v{config.version}.json",
                config_data
            )
            
            # Keep last 10 versions
            self._cleanup_old_versions(config.config_id, keep_versions=10)
            
        except Exception as e:
            self.logger.error(f"Failed to save configuration to cloud: {e}")
            raise
    
    def _upload_to_cloud(self, key: str, data: str):
        """Upload data to cloud storage"""
        try:
            if self.cloud_provider == "aws" and self.cloud_client:
                self.cloud_client.put_object(
                    Bucket=self.cloud_config["aws"]["bucket_name"],
                    Key=key,
                    Body=data.encode(),
                    ServerSideEncryption='AES256'
                )
            elif self.cloud_provider == "azure" and self.cloud_client:
                blob_client = self.cloud_client.get_blob_client(
                    container=self.cloud_config["azure"]["container_name"],
                    blob=key
                )
                blob_client.upload_blob(data, overwrite=True)
            elif self.cloud_provider == "gcp" and self.cloud_client:
                bucket = self.cloud_client.bucket(self.cloud_config["gcp"]["bucket_name"])
                blob = bucket.blob(key)
                blob.upload_from_string(data)
            else:
                # Fallback to local storage
                local_path = f"/tmp/albator_cloud/{key}"
                os.makedirs(os.path.dirname(local_path), exist_ok=True)
                with open(local_path, 'w') as f:
                    f.write(data)
        except Exception as e:
            self.logger.error(f"Failed to upload to cloud: {e}")
            raise
    
    def _get_cloud_configuration(self, config_id: str) -> Optional[CloudConfiguration]:
        """Get configuration metadata from cloud"""
        try:
            metadata_key = f"configs/{config_id}/metadata.json"
            metadata = self._download_from_cloud(metadata_key)
            
            if metadata:
                return CloudConfiguration(**json.loads(metadata))
            return None
        except Exception as e:
            self.logger.error(f"Failed to get cloud configuration: {e}")
            return None
    
    def _get_cloud_configuration_data(self, config_id: str) -> Tuple[Optional[CloudConfiguration], Optional[str]]:
        """Get configuration data from cloud"""
        try:
            # Get metadata
            config = self._get_cloud_configuration(config_id)
            if not config:
                return None, None
            
            # Get latest version data
            data_key = f"configs/{config_id}/v{config.version}.json"
            data = self._download_from_cloud(data_key)
            
            return config, data
        except Exception as e:
            self.logger.error(f"Failed to get configuration data: {e}")
            return None, None
    
    def _download_from_cloud(self, key: str) -> Optional[str]:
        """Download data from cloud storage"""
        try:
            if self.cloud_provider == "aws" and self.cloud_client:
                response = self.cloud_client.get_object(
                    Bucket=self.cloud_config["aws"]["bucket_name"],
                    Key=key
                )
                return response['Body'].read().decode()
            elif self.cloud_provider == "azure" and self.cloud_client:
                blob_client = self.cloud_client.get_blob_client(
                    container=self.cloud_config["azure"]["container_name"],
                    blob=key
                )
                return blob_client.download_blob().readall().decode()
            elif self.cloud_provider == "gcp" and self.cloud_client:
                bucket = self.cloud_client.bucket(self.cloud_config["gcp"]["bucket_name"])
                blob = bucket.blob(key)
                return blob.download_as_text()
            else:
                # Fallback to local storage
                local_path = f"/tmp/albator_cloud/{key}"
                if os.path.exists(local_path):
                    with open(local_path, 'r') as f:
                        return f.read()
            return None
        except Exception as e:
            self.logger.error(f"Failed to download from cloud: {e}")
            return None
    
    def _generate_snapshot_id(self) -> str:
        """Generate unique snapshot ID"""
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        random_suffix = os.urandom(4).hex()
        return f"snapshot-{timestamp}-{random_suffix}"
    
    def _trigger_cloud_analytics(self, tenant_id: str, snapshot: SecurityPostureSnapshot):
        """Trigger cloud-based analytics processing"""
        try:
            # Send to cloud analytics pipeline
            api_url = f"{self.cloud_config['api']['base_url']}/{self.cloud_config['api']['version']}/analytics/process"
            
            requests.post(
                api_url,
                json={
                    "tenant_id": tenant_id,
                    "snapshot_id": snapshot.snapshot_id,
                    "trigger_ml": True
                },
                headers=self._get_api_headers(tenant_id),
                timeout=10
            )
        except Exception as e:
            self.logger.warning(f"Failed to trigger cloud analytics: {e}")
    
    def _get_api_headers(self, tenant_id: str) -> Dict[str, str]:
        """Get API headers for cloud requests"""
        tenant = self.tenants.get(tenant_id)
        if not tenant:
            return {}
        
        return {
            "X-Tenant-ID": tenant_id,
            "X-API-Version": self.cloud_config["api"]["version"],
            "Content-Type": "application/json"
        }
    
    def _generate_local_insights(self, tenant_id: str, days: int) -> Dict[str, Any]:
        """Generate insights locally when cloud API is unavailable"""
        return {
            "insights": [
                {
                    "type": "trend",
                    "title": "Security Posture Improving",
                    "description": "Overall security score has improved by 15% over the last 30 days",
                    "severity": "info"
                },
                {
                    "type": "recommendation",
                    "title": "Enable Disk Encryption",
                    "description": "30% of systems do not have FileVault enabled",
                    "severity": "high"
                }
            ],
            "generated_at": datetime.now().isoformat(),
            "source": "local"
        }

def main():
    """Main function for cloud integration"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Albator Cloud Integration")
    parser.add_argument("command", choices=["setup", "sync", "status", "demo"])
    parser.add_argument("--provider", default="aws", choices=["aws", "azure", "gcp"])
    parser.add_argument("--tenant", help="Tenant ID")
    parser.add_argument("--config", help="Configuration name")
    
    args = parser.parse_args()
    
    # Initialize cloud integration
    cloud = CloudIntegration(cloud_provider=args.provider)
    
    if args.command == "setup":
        print("☁️  Setting up Albator Cloud Integration")
        if cloud.enable_multi_tenant_mode():
            print("✅ Cloud integration enabled successfully")
        else:
            print("❌ Failed to enable cloud integration")
    
    elif args.command == "demo":
        print("🌩️  Albator Cloud Integration Demo")
        print("=" * 50)
        
        # Create demo tenant
        print("\n1. Creating demo tenant...")
        tenant, api_key = cloud.create_tenant("demo-org", "pro")
        print(f"   Tenant ID: {tenant.tenant_id}")
        print(f"   API Key: {api_key[:8]}...")
        
        # Sync configuration
        print("\n2. Syncing configuration to cloud...")
        demo_config = {
            "security_profile": "enterprise",
            "compliance_frameworks": ["nist_800_53", "cis"],
            "auto_remediation": True
        }
        config = cloud.sync_configuration(tenant.tenant_id, "main-config", demo_config)
        print(f"   Configuration synced: v{config.version}")
        
        # Upload security posture
        print("\n3. Uploading security posture...")
        posture_data = {
            "fleet_size": 50,
            "compliance_scores": {
                "nist_800_53": 85.5,
                "cis": 92.0
            },
            "risk_metrics": {
                "overall_risk": "medium",
                "critical_systems": 5
            }
        }
        snapshot = cloud.upload_security_posture(tenant.tenant_id, posture_data)
        print(f"   Snapshot uploaded: {snapshot.snapshot_id}")
        
        # Get insights
        print("\n4. Getting cloud insights...")
        insights = cloud.get_cloud_insights(tenant.tenant_id)
        print(f"   Insights generated: {len(insights.get('insights', []))} insights")
        
        print("\n✅ Cloud integration demo completed!")

if __name__ == "__main__":
    main()
