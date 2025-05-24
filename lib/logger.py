#!/usr/bin/env python3
"""
Albator Logging Framework
Provides centralized logging capabilities for all Albator components
"""

import logging
import logging.handlers
import os
import sys
import yaml
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

class AlbatorLogger:
    """Centralized logging system for Albator"""
    
    def __init__(self, config_path: str = "config/albator.yaml"):
        """Initialize the logger with configuration"""
        self.config = self._load_config(config_path)
        self.logger = None
        self._setup_logger()
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                return config.get('global', {})
        except FileNotFoundError:
            # Default configuration if file not found
            return {
                'log_level': 'INFO',
                'log_file': '/var/log/albator.log',
                'backup_settings': True
            }
        except Exception as e:
            print(f"Error loading config: {e}", file=sys.stderr)
            return {}
    
    def _setup_logger(self):
        """Setup the main logger with handlers"""
        self.logger = logging.getLogger('albator')
        
        # Set log level
        log_level = getattr(logging, self.config.get('log_level', 'INFO').upper())
        self.logger.setLevel(log_level)
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
        # File handler
        log_file = self.config.get('log_file', '/var/log/albator.log')
        try:
            # Create log directory if it doesn't exist
            log_dir = os.path.dirname(log_file)
            os.makedirs(log_dir, exist_ok=True)
            
            # Rotating file handler (10MB max, 5 backups)
            file_handler = logging.handlers.RotatingFileHandler(
                log_file, maxBytes=10*1024*1024, backupCount=5
            )
            file_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
            )
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)
        except PermissionError:
            # Fallback to user's home directory if can't write to /var/log
            fallback_log = os.path.expanduser("~/albator.log")
            file_handler = logging.handlers.RotatingFileHandler(
                fallback_log, maxBytes=10*1024*1024, backupCount=5
            )
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)
            self.logger.warning(f"Could not write to {log_file}, using {fallback_log}")
    
    def get_logger(self, name: str = None) -> logging.Logger:
        """Get a logger instance"""
        if name:
            return logging.getLogger(f'albator.{name}')
        return self.logger
    
    def log_operation_start(self, operation: str, details: Dict[str, Any] = None):
        """Log the start of an operation"""
        msg = f"Starting operation: {operation}"
        if details:
            msg += f" - Details: {details}"
        self.logger.info(msg)
    
    def log_operation_success(self, operation: str, details: Dict[str, Any] = None):
        """Log successful completion of an operation"""
        msg = f"Operation completed successfully: {operation}"
        if details:
            msg += f" - Details: {details}"
        self.logger.info(msg)
    
    def log_operation_failure(self, operation: str, error: str, details: Dict[str, Any] = None):
        """Log failure of an operation"""
        msg = f"Operation failed: {operation} - Error: {error}"
        if details:
            msg += f" - Details: {details}"
        self.logger.error(msg)
    
    def log_security_event(self, event_type: str, description: str, severity: str = "INFO"):
        """Log security-related events"""
        msg = f"SECURITY EVENT [{event_type}]: {description}"
        level = getattr(logging, severity.upper(), logging.INFO)
        self.logger.log(level, msg)
    
    def log_system_change(self, change_type: str, before: str, after: str, component: str):
        """Log system configuration changes"""
        msg = f"SYSTEM CHANGE [{component}] {change_type}: {before} -> {after}"
        self.logger.info(msg)
    
    def log_verification(self, check: str, result: bool, expected: str, actual: str):
        """Log verification results"""
        status = "PASS" if result else "FAIL"
        msg = f"VERIFICATION [{status}] {check}: Expected '{expected}', Got '{actual}'"
        if result:
            self.logger.info(msg)
        else:
            self.logger.warning(msg)

# Global logger instance
_logger_instance = None

def get_logger(name: str = None) -> logging.Logger:
    """Get the global logger instance"""
    global _logger_instance
    if _logger_instance is None:
        _logger_instance = AlbatorLogger()
    return _logger_instance.get_logger(name)

def log_operation_start(operation: str, details: Dict[str, Any] = None):
    """Convenience function for logging operation start"""
    global _logger_instance
    if _logger_instance is None:
        _logger_instance = AlbatorLogger()
    _logger_instance.log_operation_start(operation, details)

def log_operation_success(operation: str, details: Dict[str, Any] = None):
    """Convenience function for logging operation success"""
    global _logger_instance
    if _logger_instance is None:
        _logger_instance = AlbatorLogger()
    _logger_instance.log_operation_success(operation, details)

def log_operation_failure(operation: str, error: str, details: Dict[str, Any] = None):
    """Convenience function for logging operation failure"""
    global _logger_instance
    if _logger_instance is None:
        _logger_instance = AlbatorLogger()
    _logger_instance.log_operation_failure(operation, error, details)

def log_security_event(event_type: str, description: str, severity: str = "INFO"):
    """Convenience function for logging security events"""
    global _logger_instance
    if _logger_instance is None:
        _logger_instance = AlbatorLogger()
    _logger_instance.log_security_event(event_type, description, severity)

def log_system_change(change_type: str, before: str, after: str, component: str):
    """Convenience function for logging system changes"""
    global _logger_instance
    if _logger_instance is None:
        _logger_instance = AlbatorLogger()
    _logger_instance.log_system_change(change_type, before, after, component)

def log_verification(check: str, result: bool, expected: str, actual: str):
    """Convenience function for logging verification results"""
    global _logger_instance
    if _logger_instance is None:
        _logger_instance = AlbatorLogger()
    _logger_instance.log_verification(check, result, expected, actual)

if __name__ == "__main__":
    # Test the logger
    logger = get_logger("test")
    logger.info("Logger test successful")
    log_operation_start("test_operation", {"param": "value"})
    log_operation_success("test_operation")
    log_security_event("TEST", "This is a test security event")
    log_system_change("SETTING", "old_value", "new_value", "test_component")
    log_verification("test_check", True, "expected", "expected")
