#!/usr/bin/env python3
"""
Albator Web Interface
Modern web-based GUI for macOS security hardening
"""

import os
import sys
import json
import yaml
import subprocess
import threading
import time
import logging
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_from_directory
from typing import Dict, List, Any, Optional

try:
    from flask_socketio import SocketIO, emit
    SOCKETIO_AVAILABLE = True
except Exception:
    SOCKETIO_AVAILABLE = False

    class SocketIO:  # type: ignore[override]
        def __init__(self, app, cors_allowed_origins="*"):
            self.app = app

        def run(self, app, host="127.0.0.1", port=5000, debug=False):
            app.run(host=host, port=port, debug=debug)

        def emit(self, *args, **kwargs):
            return None

        def on(self, _event):
            def decorator(func):
                return func
            return decorator

    def emit(*args, **kwargs):  # type: ignore[override]
        return None

# Add lib directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lib'))


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


class _FallbackConfigManager:
    def __init__(self, config_path: str = "config/albator.yaml"):
        self.config_path = config_path
        self._config = self._load()

    def _load(self) -> Dict[str, Any]:
        try:
            with open(self.config_path, "r") as f:
                return yaml.safe_load(f) or {}
        except Exception:
            return {}

    def get_profiles(self) -> List[str]:
        return list((self._config.get("profiles") or {}).keys())

    def get_profile(self, profile_name: str) -> Dict[str, Any]:
        return (self._config.get("profiles") or {}).get(profile_name)

    def get_profile_summary(self, profile_name: str) -> Dict[str, Any]:
        profile = self.get_profile(profile_name) or {}
        return {
            "name": profile_name,
            "description": profile.get("description", "No description"),
            "keys": sorted([k for k in profile.keys() if k != "description"]),
        }


class _FallbackRollbackManager:
    def list_rollback_points(self) -> List[Dict[str, Any]]:
        return []

    def rollback(self, rollback_id: str, dry_run: bool = False) -> bool:
        return False


try:
    from logger import get_logger, log_operation_start, log_operation_success, log_operation_failure
    from config_manager import ConfigurationManager
    from rollback import RollbackManager
    OPTIONAL_BACKEND_AVAILABLE = True
except Exception as e:
    print(f"Warning: Optional web backend modules unavailable: {e}")
    print("Using config-only fallback backend.")
    get_logger = _fallback_logger
    log_operation_start = _noop
    log_operation_success = _noop
    log_operation_failure = _noop
    ConfigurationManager = _FallbackConfigManager
    RollbackManager = _FallbackRollbackManager
    OPTIONAL_BACKEND_AVAILABLE = False

app = Flask(__name__)
# Use environment variable for secret key, fallback to generated key
app.config['SECRET_KEY'] = os.environ.get('ALBATOR_SECRET_KEY', os.urandom(24).hex())
socketio = SocketIO(app, cors_allowed_origins="*")

# Global instances
logger = get_logger("web_interface")
config_manager = ConfigurationManager()
rollback_manager = RollbackManager()

# Global state
current_operations = {}
operation_logs = {}

class OperationRunner:
    """Handles running security operations with real-time updates"""
    
    def __init__(self, operation_id: str, script_name: str, args: List[str] = None):
        self.operation_id = operation_id
        self.script_name = script_name
        self.args = args or []
        self.process = None
        self.status = "pending"
        self.output = []
        self.start_time = None
        self.end_time = None
        
    def run(self):
        """Run the operation in a separate thread"""
        self.status = "running"
        self.start_time = datetime.now()
        
        try:
            # Build command
            cmd = [f"./{self.script_name}"] + self.args
            
            # Start process
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Read output line by line
            for line in iter(self.process.stdout.readline, ''):
                if line:
                    self.output.append(line.strip())
                    # Emit real-time update
                    socketio.emit('operation_update', {
                        'operation_id': self.operation_id,
                        'status': self.status,
                        'output': line.strip(),
                        'timestamp': datetime.now().isoformat()
                    })
            
            # Wait for completion
            self.process.wait()
            
            # Set final status
            if self.process.returncode == 0:
                self.status = "completed"
            else:
                self.status = "failed"
                
        except Exception as e:
            self.status = "error"
            self.output.append(f"Error: {str(e)}")
            logger.error(f"Operation {self.operation_id} failed: {e}")
        
        finally:
            self.end_time = datetime.now()
            
            # Emit completion
            socketio.emit('operation_complete', {
                'operation_id': self.operation_id,
                'status': self.status,
                'duration': (self.end_time - self.start_time).total_seconds(),
                'output': self.output
            })
            
            # Clean up
            if self.operation_id in current_operations:
                del current_operations[self.operation_id]

@app.route('/')
def index():
    """Main dashboard"""
    return render_template('index.html')

@app.route('/api/profiles')
def get_profiles():
    """Get available security profiles"""
    try:
        profiles = []
        for profile_name in config_manager.get_profiles():
            summary = config_manager.get_profile_summary(profile_name)
            profiles.append(summary)
        
        return jsonify({
            'success': True,
            'profiles': profiles
        })
    except Exception as e:
        logger.error(f"Error getting profiles: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/profile/<profile_name>')
def get_profile(profile_name):
    """Get specific profile details"""
    try:
        profile = config_manager.get_profile(profile_name)
        if not profile:
            return jsonify({
                'success': False,
                'error': 'Profile not found'
            }), 404
        
        summary = config_manager.get_profile_summary(profile_name)
        
        return jsonify({
            'success': True,
            'profile': profile,
            'summary': summary
        })
    except Exception as e:
        logger.error(f"Error getting profile {profile_name}: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/system-status')
def get_system_status():
    """Get current system security status"""
    try:
        status = {
            'timestamp': datetime.now().isoformat(),
            'macos_version': subprocess.check_output(['sw_vers', '-productVersion'], text=True).strip(),
            'components': {}
        }
        
        # Check firewall status
        try:
            firewall_output = subprocess.check_output([
                'sudo', '/usr/libexec/ApplicationFirewall/socketfilterfw', '--getglobalstate'
            ], text=True)
            status['components']['firewall'] = {
                'enabled': 'enabled' in firewall_output.lower(),
                'status': firewall_output.strip()
            }
        except:
            status['components']['firewall'] = {'enabled': False, 'status': 'Unknown'}
        
        # Check FileVault status
        try:
            filevault_output = subprocess.check_output(['fdesetup', 'status'], text=True)
            status['components']['encryption'] = {
                'enabled': 'FileVault is On' in filevault_output,
                'status': filevault_output.strip()
            }
        except:
            status['components']['encryption'] = {'enabled': False, 'status': 'Unknown'}
        
        # Check Gatekeeper status
        try:
            gatekeeper_output = subprocess.check_output(['spctl', '--status'], text=True)
            status['components']['gatekeeper'] = {
                'enabled': 'assessments enabled' in gatekeeper_output.lower(),
                'status': gatekeeper_output.strip()
            }
        except:
            status['components']['gatekeeper'] = {'enabled': False, 'status': 'Unknown'}
        
        # Check SIP status
        try:
            sip_output = subprocess.check_output(['csrutil', 'status'], text=True)
            status['components']['sip'] = {
                'enabled': 'enabled' in sip_output.lower(),
                'status': sip_output.strip()
            }
        except:
            status['components']['sip'] = {'enabled': False, 'status': 'Unknown'}
        
        return jsonify({
            'success': True,
            'status': status
        })
    except Exception as e:
        logger.error(f"Error getting system status: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/run-operation', methods=['POST'])
def run_operation():
    """Start a security operation"""
    try:
        data = request.get_json()
        operation_type = data.get('operation')
        profile = data.get('profile', 'basic')
        dry_run = data.get('dry_run', False)
        
        if not operation_type:
            return jsonify({
                'success': False,
                'error': 'Operation type required'
            }), 400
        
        # Generate operation ID
        operation_id = f"{operation_type}_{int(time.time())}"
        
        # Map operation types to scripts
        script_mapping = {
            'privacy': 'privacy.sh',
            'firewall': 'firewall.sh',
            'encryption': 'encryption.sh',
            'app_security': 'app_security.sh',
            'cve_fetch': 'cve_fetch.sh',
            'apple_updates': 'apple_updates.sh'
        }
        
        script_name = script_mapping.get(operation_type)
        if not script_name:
            return jsonify({
                'success': False,
                'error': 'Unknown operation type'
            }), 400
        
        # Build arguments
        args = []
        if dry_run:
            args.append('--dry-run')
        
        # Create operation runner
        runner = OperationRunner(operation_id, script_name, args)
        current_operations[operation_id] = runner
        
        # Start operation in background thread
        thread = threading.Thread(target=runner.run)
        thread.daemon = True
        thread.start()
        
        log_operation_start(f"web_operation: {operation_type}", {
            'operation_id': operation_id,
            'profile': profile,
            'dry_run': dry_run
        })
        
        return jsonify({
            'success': True,
            'operation_id': operation_id,
            'status': 'started'
        })
        
    except Exception as e:
        logger.error(f"Error starting operation: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/operation/<operation_id>')
def get_operation_status(operation_id):
    """Get status of a running operation"""
    try:
        if operation_id in current_operations:
            runner = current_operations[operation_id]
            return jsonify({
                'success': True,
                'operation_id': operation_id,
                'status': runner.status,
                'output': runner.output,
                'start_time': runner.start_time.isoformat() if runner.start_time else None,
                'end_time': runner.end_time.isoformat() if runner.end_time else None
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Operation not found'
            }), 404
    except Exception as e:
        logger.error(f"Error getting operation status: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/rollback-points')
def get_rollback_points():
    """Get available rollback points"""
    try:
        points = rollback_manager.list_rollback_points()
        return jsonify({
            'success': True,
            'rollback_points': points
        })
    except Exception as e:
        logger.error(f"Error getting rollback points: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/rollback', methods=['POST'])
def perform_rollback():
    """Perform rollback to a specific point"""
    try:
        data = request.get_json()
        rollback_id = data.get('rollback_id')
        dry_run = data.get('dry_run', False)
        
        if not rollback_id:
            return jsonify({
                'success': False,
                'error': 'Rollback ID required'
            }), 400
        
        # Perform rollback
        success = rollback_manager.rollback(rollback_id, dry_run)
        
        if success:
            log_operation_success(f"web_rollback: {rollback_id}", {'dry_run': dry_run})
            return jsonify({
                'success': True,
                'message': 'Rollback completed successfully'
            })
        else:
            log_operation_failure(f"web_rollback: {rollback_id}", "Rollback failed")
            return jsonify({
                'success': False,
                'error': 'Rollback failed'
            }), 500
            
    except Exception as e:
        logger.error(f"Error performing rollback: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/test-connection')
def test_connection():
    """Test API connection"""
    return jsonify({
        'success': True,
        'message': 'Albator Web Interface is running',
        'optional_backend_available': OPTIONAL_BACKEND_AVAILABLE,
        'socketio_available': SOCKETIO_AVAILABLE,
        'timestamp': datetime.now().isoformat()
    })

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logger.info("Client connected to WebSocket")
    emit('connected', {'message': 'Connected to Albator Web Interface'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info("Client disconnected from WebSocket")

@socketio.on('subscribe_operations')
def handle_subscribe_operations():
    """Subscribe to operation updates"""
    emit('subscribed', {'message': 'Subscribed to operation updates'})

if __name__ == '__main__':
    # Ensure we're in the right directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(script_dir)
    os.chdir(parent_dir)
    
    logger.info("Starting Albator Web Interface")
    
    # Run the Flask app with SocketIO
    socketio.run(app, host='127.0.0.1', port=5000, debug=False)
