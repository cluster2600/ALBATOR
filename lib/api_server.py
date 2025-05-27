#!/usr/bin/env python3
"""
Albator REST API Server
Provides remote management capabilities for Albator
"""

import os
import sys
import json
import uuid
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pathlib import Path
import subprocess
import hashlib
import secrets

# Flask and async support
from flask import Flask, request, jsonify, abort
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps

# Add lib directory to path for imports
sys.path.insert(0, os.path.dirname(__file__))
from logger import get_logger, log_operation_start, log_operation_success, log_operation_failure
from config_manager import ConfigurationManager
from compliance_reporter import ComplianceReporter
from analytics_dashboard import AnalyticsDashboard
from fleet_manager import FleetManager
from rollback import RollbackManager

# Configuration
SECRET_KEY = os.environ.get('ALBATOR_SECRET_KEY', secrets.token_hex(32))
API_VERSION = 'v1'
TOKEN_EXPIRY = 3600  # 1 hour

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
CORS(app, origins=['http://localhost:*'])

# Initialize managers
config_manager = ConfigurationManager()
compliance_reporter = ComplianceReporter()
analytics_dashboard = AnalyticsDashboard()
fleet_manager = FleetManager()
rollback_manager = RollbackManager()
logger = get_logger("api_server")

# In-memory token storage (use Redis in production)
active_tokens = {}

# API Authentication
def generate_api_token(username: str) -> str:
    """Generate JWT token for API authentication"""
    payload = {
        'username': username,
        'exp': datetime.utcnow() + timedelta(seconds=TOKEN_EXPIRY),
        'iat': datetime.utcnow(),
        'jti': str(uuid.uuid4())
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    active_tokens[payload['jti']] = {
        'username': username,
        'created_at': datetime.utcnow().isoformat()
    }
    return token

def require_auth(f):
    """Decorator to require authentication for API endpoints"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        
        if auth_header:
            try:
                token = auth_header.split(' ')[1]  # Bearer <token>
            except IndexError:
                return jsonify({'error': 'Invalid token format'}), 401
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            if data['jti'] not in active_tokens:
                return jsonify({'error': 'Token has been revoked'}), 401
            request.current_user = data['username']
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(*args, **kwargs)
    
    return decorated_function

# API Routes
@app.route(f'/api/{API_VERSION}/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'version': API_VERSION,
        'timestamp': datetime.utcnow().isoformat()
    })

@app.route(f'/api/{API_VERSION}/auth/login', methods=['POST'])
def login():
    """Authenticate and receive API token"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    # Simple authentication (use proper auth in production)
    # For demo, accept admin/admin
    if username == 'admin' and password == 'admin':
        token = generate_api_token(username)
        log_operation_success('api_login', {'username': username})
        return jsonify({
            'token': token,
            'expires_in': TOKEN_EXPIRY
        })
    
    log_operation_failure('api_login', 'Invalid credentials')
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route(f'/api/{API_VERSION}/auth/logout', methods=['POST'])
@require_auth
def logout():
    """Logout and revoke token"""
    auth_header = request.headers.get('Authorization')
    token = auth_header.split(' ')[1]
    
    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        if data['jti'] in active_tokens:
            del active_tokens[data['jti']]
        return jsonify({'message': 'Logged out successfully'})
    except:
        return jsonify({'error': 'Invalid token'}), 401

# Profile Management
@app.route(f'/api/{API_VERSION}/profiles', methods=['GET'])
@require_auth
def get_profiles():
    """Get all security profiles"""
    log_operation_start('api_get_profiles')
    
    try:
        profiles = config_manager.list_profiles()
        profile_data = []
        
        for profile_name in profiles:
            info = config_manager.get_profile_info(profile_name)
            profile_data.append({
                'name': profile_name,
                'description': info.get('description', ''),
                'security_level': info.get('security_level', 0)
            })
        
        log_operation_success('api_get_profiles', {'count': len(profiles)})
        return jsonify({'profiles': profile_data})
        
    except Exception as e:
        log_operation_failure('api_get_profiles', str(e))
        return jsonify({'error': str(e)}), 500

@app.route(f'/api/{API_VERSION}/profiles/<profile_name>', methods=['GET'])
@require_auth
def get_profile(profile_name):
    """Get specific profile details"""
    log_operation_start(f'api_get_profile: {profile_name}')
    
    try:
        info = config_manager.get_profile_info(profile_name)
        if info:
            log_operation_success(f'api_get_profile: {profile_name}')
            return jsonify({'profile': info})
        else:
            return jsonify({'error': 'Profile not found'}), 404
            
    except Exception as e:
        log_operation_failure(f'api_get_profile: {profile_name}', str(e))
        return jsonify({'error': str(e)}), 500

@app.route(f'/api/{API_VERSION}/profiles', methods=['POST'])
@require_auth
def create_profile():
    """Create new security profile"""
    data = request.get_json()
    profile_name = data.get('name')
    
    if not profile_name:
        return jsonify({'error': 'Profile name is required'}), 400
    
    log_operation_start(f'api_create_profile: {profile_name}')
    
    try:
        success = config_manager.create_profile(profile_name, data)
        if success:
            log_operation_success(f'api_create_profile: {profile_name}')
            return jsonify({'message': f'Profile {profile_name} created successfully'}), 201
        else:
            return jsonify({'error': 'Failed to create profile'}), 500
            
    except Exception as e:
        log_operation_failure(f'api_create_profile: {profile_name}', str(e))
        return jsonify({'error': str(e)}), 500

# Hardening Operations
@app.route(f'/api/{API_VERSION}/harden', methods=['POST'])
@require_auth
def run_hardening():
    """Execute hardening operations"""
    data = request.get_json()
    profile = data.get('profile', 'basic')
    scripts = data.get('scripts', ['privacy', 'firewall', 'encryption', 'app_security'])
    dry_run = data.get('dry_run', False)
    
    log_operation_start('api_hardening')
    
    # Create task ID for async tracking
    task_id = str(uuid.uuid4())
    
    # In production, use Celery or similar for async tasks
    # For now, we'll execute synchronously
    results = []
    
    for script in scripts:
        script_path = f"./{script}.sh"
        if os.path.exists(script_path):
            cmd = [script_path]
            if dry_run:
                cmd.append('--dry-run')
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                results.append({
                    'script': script,
                    'success': result.returncode == 0,
                    'output': result.stdout,
                    'error': result.stderr
                })
            except subprocess.TimeoutExpired:
                results.append({
                    'script': script,
                    'success': False,
                    'error': 'Script timed out'
                })
            except Exception as e:
                results.append({
                    'script': script,
                    'success': False,
                    'error': str(e)
                })
    
    success_count = sum(1 for r in results if r['success'])
    
    log_operation_success('api_hardening', {
        'profile': profile,
        'scripts': len(scripts),
        'successful': success_count
    })
    
    return jsonify({
        'task_id': task_id,
        'profile': profile,
        'dry_run': dry_run,
        'results': results,
        'summary': {
            'total': len(scripts),
            'successful': success_count,
            'failed': len(scripts) - success_count
        }
    })

# Compliance Scanning
@app.route(f'/api/{API_VERSION}/compliance/scan', methods=['POST'])
@require_auth
def run_compliance_scan():
    """Run compliance scan"""
    data = request.get_json()
    framework = data.get('framework', 'custom')
    profile = data.get('profile', 'basic')
    
    log_operation_start(f'api_compliance_scan: {framework}')
    
    try:
        report = compliance_reporter.generate_compliance_report(framework, profile)
        
        # Record in analytics
        analytics_dashboard.record_compliance_report(report)
        
        log_operation_success(f'api_compliance_scan: {framework}', {
            'compliance_score': report.summary['compliance_score']
        })
        
        return jsonify({
            'report_id': report.report_id,
            'framework': framework,
            'compliance_score': report.summary['compliance_score'],
            'summary': report.summary,
            'generated_at': report.generated_at
        })
        
    except Exception as e:
        log_operation_failure(f'api_compliance_scan: {framework}', str(e))
        return jsonify({'error': str(e)}), 500

@app.route(f'/api/{API_VERSION}/compliance/frameworks', methods=['GET'])
@require_auth
def get_compliance_frameworks():
    """Get available compliance frameworks"""
    frameworks = compliance_reporter.get_available_frameworks()
    framework_data = []
    
    for fw in frameworks:
        info = compliance_reporter.get_framework_info(fw)
        framework_data.append({
            'id': fw,
            'name': info['name'],
            'version': info['version'],
            'description': info['description']
        })
    
    return jsonify({'frameworks': framework_data})

# Analytics
@app.route(f'/api/{API_VERSION}/analytics/trends', methods=['GET'])
@require_auth
def get_trends():
    """Get compliance trends"""
    days = request.args.get('days', 30, type=int)
    system_id = request.args.get('system_id')
    framework = request.args.get('framework')
    
    log_operation_start('api_get_trends')
    
    try:
        trends = analytics_dashboard.get_compliance_trends(
            system_id=system_id,
            framework=framework,
            days=days
        )
        
        trend_data = []
        for trend in trends:
            trend_data.append({
                'metric_name': trend.metric_name,
                'trend_direction': trend.trend_direction,
                'trend_strength': trend.trend_strength,
                'current_value': trend.current_value,
                'previous_value': trend.previous_value,
                'change_percentage': trend.change_percentage,
                'recommendation': trend.recommendation
            })
        
        log_operation_success('api_get_trends', {'count': len(trends)})
        return jsonify({'trends': trend_data})
        
    except Exception as e:
        log_operation_failure('api_get_trends', str(e))
        return jsonify({'error': str(e)}), 500

# Fleet Management
@app.route(f'/api/{API_VERSION}/fleet/hosts', methods=['GET'])
@require_auth
def get_fleet_hosts():
    """Get all fleet hosts"""
    hosts = fleet_manager.list_hosts()
    return jsonify({'hosts': hosts})

@app.route(f'/api/{API_VERSION}/fleet/hosts', methods=['POST'])
@require_auth
def add_fleet_host():
    """Add host to fleet"""
    data = request.get_json()
    host_id = data.get('host_id')
    hostname = data.get('hostname')
    
    if not host_id or not hostname:
        return jsonify({'error': 'host_id and hostname are required'}), 400
    
    log_operation_start(f'api_add_fleet_host: {host_id}')
    
    try:
        success = fleet_manager.add_host(host_id, hostname, data)
        if success:
            log_operation_success(f'api_add_fleet_host: {host_id}')
            return jsonify({'message': f'Host {host_id} added successfully'}), 201
        else:
            return jsonify({'error': 'Failed to add host'}), 500
            
    except Exception as e:
        log_operation_failure(f'api_add_fleet_host: {host_id}', str(e))
        return jsonify({'error': str(e)}), 500

@app.route(f'/api/{API_VERSION}/fleet/deploy', methods=['POST'])
@require_auth
def deploy_to_fleet():
    """Deploy to fleet"""
    data = request.get_json()
    profile = data.get('profile', 'basic')
    hosts = data.get('hosts', [])  # Optional specific hosts
    
    log_operation_start('api_fleet_deploy')
    
    try:
        # Deploy to specific hosts or all
        if hosts:
            results = {}
            for host_id in hosts:
                result = fleet_manager.execute_on_host(
                    host_id,
                    f"python3 albator_enhanced.py harden --profile {profile}"
                )
                results[host_id] = result
        else:
            results = fleet_manager.deploy_to_fleet(profile)
        
        success_count = sum(1 for r in results.values() if r.get('success'))
        
        log_operation_success('api_fleet_deploy', {
            'profile': profile,
            'hosts': len(results),
            'successful': success_count
        })
        
        return jsonify({
            'profile': profile,
            'results': results,
            'summary': {
                'total': len(results),
                'successful': success_count,
                'failed': len(results) - success_count
            }
        })
        
    except Exception as e:
        log_operation_failure('api_fleet_deploy', str(e))
        return jsonify({'error': str(e)}), 500

# Rollback Management
@app.route(f'/api/{API_VERSION}/rollback/points', methods=['GET'])
@require_auth
def get_rollback_points():
    """Get rollback points"""
    points = rollback_manager.list_rollback_points()
    return jsonify({'rollback_points': points})

@app.route(f'/api/{API_VERSION}/rollback/create', methods=['POST'])
@require_auth
def create_rollback_point():
    """Create rollback point"""
    data = request.get_json()
    description = data.get('description', 'API-created rollback point')
    
    log_operation_start('api_create_rollback')
    
    try:
        rollback_id = rollback_manager.create_rollback_point('api', description)
        if rollback_id:
            log_operation_success('api_create_rollback', {'id': rollback_id})
            return jsonify({
                'rollback_id': rollback_id,
                'message': 'Rollback point created successfully'
            }), 201
        else:
            return jsonify({'error': 'Failed to create rollback point'}), 500
            
    except Exception as e:
        log_operation_failure('api_create_rollback', str(e))
        return jsonify({'error': str(e)}), 500

@app.route(f'/api/{API_VERSION}/rollback/restore/<rollback_id>', methods=['POST'])
@require_auth
def restore_rollback(rollback_id):
    """Restore to rollback point"""
    data = request.get_json()
    dry_run = data.get('dry_run', False)
    
    log_operation_start(f'api_restore_rollback: {rollback_id}')
    
    try:
        success = rollback_manager.rollback_to_point(rollback_id, dry_run)
        if success:
            log_operation_success(f'api_restore_rollback: {rollback_id}')
            return jsonify({
                'message': f'{"Would restore" if dry_run else "Restored"} to rollback point {rollback_id}'
            })
        else:
            return jsonify({'error': 'Failed to restore rollback point'}), 500
            
    except Exception as e:
        log_operation_failure(f'api_restore_rollback: {rollback_id}', str(e))
        return jsonify({'error': str(e)}), 500

# System Information
@app.route(f'/api/{API_VERSION}/system/info', methods=['GET'])
@require_auth
def get_system_info():
    """Get system information"""
    try:
        info = {
            'hostname': subprocess.check_output(['hostname'], text=True).strip(),
            'macos_version': subprocess.check_output(['sw_vers', '-productVersion'], text=True).strip(),
            'macos_build': subprocess.check_output(['sw_vers', '-buildVersion'], text=True).strip(),
            'hardware_model': subprocess.check_output(['sysctl', '-n', 'hw.model'], text=True).strip(),
            'albator_version': '3.0.0',
            'api_version': API_VERSION
        }
        return jsonify(info)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

def main():
    """Main function to run the API server"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Albator REST API Server")
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind to')
    parser.add_argument('--port', type=int, default=5001, help='Port to bind to')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    
    args = parser.parse_args()
    
    logger.info(f"Starting Albator API server on {args.host}:{args.port}")
    
    if args.debug:
        app.run(host=args.host, port=args.port, debug=True)
    else:
        # In production, use a proper WSGI server like gunicorn
        app.run(host=args.host, port=args.port, debug=False)

if __name__ == '__main__':
    main()
