#!/usr/bin/env python3
"""
Albator CLI Enhancements
Provides auto-completion, command history, and interactive features
"""

import os
import sys
import json
import readline
import rlcompleter
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable
from datetime import datetime
import argparse
import cmd
import shlex

# Add lib directory to path for imports
sys.path.insert(0, os.path.dirname(__file__))
from logger import get_logger, log_operation_start, log_operation_success, log_operation_failure
from config_manager import ConfigManager
from compliance_reporter import ComplianceReporter
from fleet_manager import FleetManager

class AlbatorCompleter:
    """Auto-completion handler for Albator CLI"""
    
    def __init__(self):
        """Initialize the completer"""
        self.commands = {
            'harden': {
                'options': ['--profile', '--dry-run', '--force', '--backup', '--target'],
                'profiles': ['basic', 'advanced', 'enterprise', 'custom'],
                'help': 'Apply security hardening to the system'
            },
            'compliance': {
                'options': ['--framework', '--format', '--output', '--verbose'],
                'frameworks': ['nist_800_53', 'cis_macos', 'iso27001', 'custom'],
                'formats': ['console', 'json', 'html', 'pdf'],
                'help': 'Run compliance scanning'
            },
            'rollback': {
                'options': ['--point', '--list', '--dry-run', '--force'],
                'help': 'Rollback to a previous configuration'
            },
            'profile': {
                'subcommands': ['list', 'show', 'create', 'delete', 'export', 'import', 'compare'],
                'options': ['--name', '--file', '--format'],
                'help': 'Manage security profiles'
            },
            'fleet': {
                'subcommands': ['list', 'add', 'remove', 'status', 'deploy', 'scan'],
                'options': ['--host', '--tag', '--profile', '--parallel'],
                'help': 'Fleet management operations'
            },
            'dashboard': {
                'options': ['--days', '--format', '--metrics', '--export'],
                'help': 'Display analytics dashboard'
            },
            'history': {
                'options': ['--limit', '--search', '--clear'],
                'help': 'View command history'
            },
            'batch': {
                'options': ['--file', '--validate', '--parallel', '--continue-on-error'],
                'help': 'Execute batch operations'
            },
            'plugin': {
                'subcommands': ['list', 'install', 'remove', 'enable', 'disable'],
                'options': ['--name', '--source', '--version'],
                'help': 'Manage plugins'
            },
            'help': {
                'help': 'Show help information'
            },
            'exit': {
                'help': 'Exit the interactive mode'
            }
        }
        
        self.all_options = set()
        for cmd_data in self.commands.values():
            if 'options' in cmd_data:
                self.all_options.update(cmd_data['options'])
    
    def complete(self, text, state):
        """Auto-completion function for readline"""
        line = readline.get_line_buffer()
        words = line.split()
        
        # If we're at the beginning, complete commands
        if not words or (len(words) == 1 and not line.endswith(' ')):
            matches = [cmd for cmd in self.commands if cmd.startswith(text)]
        
        # If we have a command, complete its options or subcommands
        elif words[0] in self.commands:
            cmd_data = self.commands[words[0]]
            matches = []
            
            # Complete subcommands if available
            if 'subcommands' in cmd_data and len(words) == 1:
                matches = [sub for sub in cmd_data['subcommands'] if sub.startswith(text)]
            
            # Complete options
            elif text.startswith('-'):
                if 'options' in cmd_data:
                    matches = [opt for opt in cmd_data['options'] if opt.startswith(text)]
            
            # Complete specific option values
            else:
                last_option = None
                for word in reversed(words[:-1]):
                    if word.startswith('-'):
                        last_option = word
                        break
                
                if last_option == '--profile' and 'profiles' in cmd_data:
                    matches = [p for p in cmd_data['profiles'] if p.startswith(text)]
                elif last_option == '--framework' and 'frameworks' in cmd_data:
                    matches = [f for f in cmd_data['frameworks'] if f.startswith(text)]
                elif last_option == '--format' and 'formats' in cmd_data:
                    matches = [f for f in cmd_data['formats'] if f.startswith(text)]
        
        try:
            return matches[state]
        except IndexError:
            return None

class CommandHistory:
    """Manage command history with persistence"""
    
    def __init__(self, history_file: str = "~/.albator/cli_history.json"):
        """Initialize command history"""
        self.history_file = Path(history_file).expanduser()
        self.history = []
        self.favorites = []
        self.logger = get_logger("command_history")
        self._load_history()
    
    def _load_history(self):
        """Load history from file"""
        try:
            if self.history_file.exists():
                with open(self.history_file, 'r') as f:
                    data = json.load(f)
                    self.history = data.get('history', [])
                    self.favorites = data.get('favorites', [])
        except Exception as e:
            self.logger.error(f"Failed to load history: {e}")
    
    def _save_history(self):
        """Save history to file"""
        try:
            self.history_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.history_file, 'w') as f:
                json.dump({
                    'history': self.history[-1000:],  # Keep last 1000 commands
                    'favorites': self.favorites
                }, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save history: {e}")
    
    def add_command(self, command: str):
        """Add command to history"""
        entry = {
            'command': command,
            'timestamp': datetime.now().isoformat(),
            'success': True  # Will be updated after execution
        }
        self.history.append(entry)
        self._save_history()
    
    def mark_favorite(self, command: str):
        """Mark command as favorite"""
        if command not in self.favorites:
            self.favorites.append(command)
            self._save_history()
    
    def search_history(self, pattern: str) -> List[Dict[str, Any]]:
        """Search command history"""
        results = []
        for entry in reversed(self.history):
            if pattern.lower() in entry['command'].lower():
                results.append(entry)
        return results
    
    def get_favorites(self) -> List[str]:
        """Get favorite commands"""
        return self.favorites
    
    def clear_history(self):
        """Clear command history"""
        self.history = []
        self._save_history()

class BatchProcessor:
    """Process batch operations from file"""
    
    def __init__(self):
        """Initialize batch processor"""
        self.logger = get_logger("batch_processor")
        self.results = []
    
    def validate_batch_file(self, file_path: str) -> bool:
        """Validate batch file format"""
        try:
            with open(file_path, 'r') as f:
                commands = []
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Try to parse the command
                        try:
                            shlex.split(line)
                            commands.append(line)
                        except ValueError as e:
                            self.logger.error(f"Invalid command syntax: {line}")
                            return False
            
            self.logger.info(f"Validated {len(commands)} commands")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to validate batch file: {e}")
            return False
    
    def execute_batch(self, file_path: str, parallel: bool = False, 
                     continue_on_error: bool = False) -> List[Dict[str, Any]]:
        """Execute commands from batch file"""
        log_operation_start("execute_batch", {"file": file_path})
        
        try:
            with open(file_path, 'r') as f:
                commands = []
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        commands.append(line)
            
            results = []
            for i, command in enumerate(commands, 1):
                self.logger.info(f"Executing command {i}/{len(commands)}: {command}")
                
                try:
                    # Parse and execute command
                    args = shlex.split(command)
                    result = self._execute_command(args)
                    results.append({
                        'command': command,
                        'success': result['success'],
                        'output': result.get('output', ''),
                        'error': result.get('error', '')
                    })
                    
                except Exception as e:
                    error_result = {
                        'command': command,
                        'success': False,
                        'output': '',
                        'error': str(e)
                    }
                    results.append(error_result)
                    
                    if not continue_on_error:
                        self.logger.error(f"Batch execution stopped due to error: {e}")
                        break
            
            log_operation_success("execute_batch", {"total": len(commands), "successful": sum(1 for r in results if r['success'])})
            return results
            
        except Exception as e:
            log_operation_failure("execute_batch", str(e))
            raise
    
    def _execute_command(self, args: List[str]) -> Dict[str, Any]:
        """Execute a single command"""
        # This would integrate with the main Albator CLI
        # For now, return a placeholder result
        return {
            'success': True,
            'output': f"Executed: {' '.join(args)}"
        }

class PluginManager:
    """Manage Albator plugins"""
    
    def __init__(self, plugin_dir: str = "~/.albator/plugins"):
        """Initialize plugin manager"""
        self.plugin_dir = Path(plugin_dir).expanduser()
        self.logger = get_logger("plugin_manager")
        self.plugins = {}
        self._load_plugins()
    
    def _load_plugins(self):
        """Load installed plugins"""
        try:
            self.plugin_dir.mkdir(parents=True, exist_ok=True)
            
            # Load plugin metadata
            metadata_file = self.plugin_dir / "plugins.json"
            if metadata_file.exists():
                with open(metadata_file, 'r') as f:
                    self.plugins = json.load(f)
                    
        except Exception as e:
            self.logger.error(f"Failed to load plugins: {e}")
    
    def _save_metadata(self):
        """Save plugin metadata"""
        try:
            metadata_file = self.plugin_dir / "plugins.json"
            with open(metadata_file, 'w') as f:
                json.dump(self.plugins, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save plugin metadata: {e}")
    
    def list_plugins(self) -> List[Dict[str, Any]]:
        """List installed plugins"""
        return list(self.plugins.values())
    
    def install_plugin(self, name: str, source: str, version: str = "latest") -> bool:
        """Install a plugin"""
        log_operation_start("install_plugin", {"name": name, "source": source})
        
        try:
            # Plugin installation logic would go here
            # For now, just register the plugin
            self.plugins[name] = {
                'name': name,
                'source': source,
                'version': version,
                'enabled': True,
                'installed_at': datetime.now().isoformat()
            }
            
            self._save_metadata()
            log_operation_success("install_plugin", {"name": name})
            return True
            
        except Exception as e:
            log_operation_failure("install_plugin", str(e))
            return False
    
    def enable_plugin(self, name: str) -> bool:
        """Enable a plugin"""
        if name in self.plugins:
            self.plugins[name]['enabled'] = True
            self._save_metadata()
            return True
        return False
    
    def disable_plugin(self, name: str) -> bool:
        """Disable a plugin"""
        if name in self.plugins:
            self.plugins[name]['enabled'] = False
            self._save_metadata()
            return True
        return False

class InteractiveShell(cmd.Cmd):
    """Interactive shell for Albator"""
    
    intro = """
    ╔══════════════════════════════════════════════════════════════════╗
    ║                    ALBATOR INTERACTIVE SHELL                     ║
    ║                 Enhanced macOS Security Platform                  ║
    ╚══════════════════════════════════════════════════════════════════╝
    
    Type 'help' for available commands or 'exit' to quit.
    """
    
    prompt = 'albator> '
    
    def __init__(self):
        super().__init__()
        self.completer = AlbatorCompleter()
        self.history = CommandHistory()
        self.batch_processor = BatchProcessor()
        self.plugin_manager = PluginManager()
        
        # Setup auto-completion
        readline.set_completer(self.completer.complete)
        readline.parse_and_bind('tab: complete')
        
        # Load command history
        history_file = Path("~/.albator/shell_history").expanduser()
        history_file.parent.mkdir(parents=True, exist_ok=True)
        readline.set_history_length(1000)
        if history_file.exists():
            readline.read_history_file(str(history_file))
        
        self.history_file = history_file
    
    def do_harden(self, args):
        """Apply security hardening: harden --profile <profile> [--dry-run]"""
        self.history.add_command(f"harden {args}")
        print(f"Executing: harden {args}")
        # Integration with main hardening logic would go here
    
    def do_compliance(self, args):
        """Run compliance scan: compliance --framework <framework> [--format <format>]"""
        self.history.add_command(f"compliance {args}")
        print(f"Executing: compliance {args}")
        # Integration with compliance scanning would go here
    
    def do_profile(self, args):
        """Manage profiles: profile <list|show|create|delete> [options]"""
        self.history.add_command(f"profile {args}")
        print(f"Executing: profile {args}")
    
    def do_fleet(self, args):
        """Fleet management: fleet <list|deploy|scan> [options]"""
        self.history.add_command(f"fleet {args}")
        print(f"Executing: fleet {args}")
    
    def do_history(self, args):
        """View command history: history [--search <pattern>] [--limit <n>]"""
        parser = argparse.ArgumentParser()
        parser.add_argument('--search', help='Search pattern')
        parser.add_argument('--limit', type=int, default=20, help='Number of entries')
        parser.add_argument('--clear', action='store_true', help='Clear history')
        
        try:
            parsed_args = parser.parse_args(shlex.split(args))
            
            if parsed_args.clear:
                self.history.clear_history()
                print("Command history cleared.")
                return
            
            if parsed_args.search:
                results = self.history.search_history(parsed_args.search)
                print(f"\nSearch results for '{parsed_args.search}':")
                for entry in results[:parsed_args.limit]:
                    print(f"  [{entry['timestamp']}] {entry['command']}")
            else:
                print("\nRecent commands:")
                for entry in self.history.history[-parsed_args.limit:]:
                    print(f"  [{entry['timestamp']}] {entry['command']}")
                    
        except SystemExit:
            pass
    
    def do_favorites(self, args):
        """Manage favorite commands: favorites [add <command>]"""
        if args.startswith('add '):
            command = args[4:]
            self.history.mark_favorite(command)
            print(f"Added to favorites: {command}")
        else:
            favorites = self.history.get_favorites()
            if favorites:
                print("\nFavorite commands:")
                for i, cmd in enumerate(favorites, 1):
                    print(f"  {i}. {cmd}")
            else:
                print("No favorite commands saved.")
    
    def do_batch(self, args):
        """Execute batch operations: batch <file> [--validate] [--continue-on-error]"""
        parser = argparse.ArgumentParser()
        parser.add_argument('file', help='Batch file path')
        parser.add_argument('--validate', action='store_true', help='Validate only')
        parser.add_argument('--continue-on-error', action='store_true', help='Continue on error')
        
        try:
            parsed_args = parser.parse_args(shlex.split(args))
            
            if parsed_args.validate:
                if self.batch_processor.validate_batch_file(parsed_args.file):
                    print("✅ Batch file is valid")
                else:
                    print("❌ Batch file validation failed")
            else:
                results = self.batch_processor.execute_batch(
                    parsed_args.file,
                    continue_on_error=parsed_args.continue_on_error
                )
                
                # Display results
                successful = sum(1 for r in results if r['success'])
                print(f"\nBatch execution complete: {successful}/{len(results)} successful")
                
        except SystemExit:
            pass
    
    def do_plugin(self, args):
        """Manage plugins: plugin <list|install|enable|disable> [options]"""
        parts = shlex.split(args)
        if not parts:
            print("Usage: plugin <list|install|enable|disable> [options]")
            return
        
        subcommand = parts[0]
        
        if subcommand == 'list':
            plugins = self.plugin_manager.list_plugins()
            if plugins:
                print("\nInstalled plugins:")
                for plugin in plugins:
                    status = "enabled" if plugin['enabled'] else "disabled"
                    print(f"  - {plugin['name']} v{plugin['version']} ({status})")
            else:
                print("No plugins installed.")
                
        elif subcommand == 'install' and len(parts) >= 3:
            name = parts[1]
            source = parts[2]
            version = parts[3] if len(parts) > 3 else "latest"
            
            if self.plugin_manager.install_plugin(name, source, version):
                print(f"✅ Plugin '{name}' installed successfully")
            else:
                print(f"❌ Failed to install plugin '{name}'")
                
        elif subcommand in ['enable', 'disable'] and len(parts) >= 2:
            name = parts[1]
            if subcommand == 'enable':
                if self.plugin_manager.enable_plugin(name):
                    print(f"✅ Plugin '{name}' enabled")
                else:
                    print(f"❌ Plugin '{name}' not found")
            else:
                if self.plugin_manager.disable_plugin(name):
                    print(f"✅ Plugin '{name}' disabled")
                else:
                    print(f"❌ Plugin '{name}' not found")
    
    def do_exit(self, args):
        """Exit the interactive shell"""
        print("Goodbye!")
        # Save history
        readline.write_history_file(str(self.history_file))
        return True
    
    def do_quit(self, args):
        """Exit the interactive shell"""
        return self.do_exit(args)
    
    def default(self, line):
        """Handle unknown commands"""
        print(f"Unknown command: {line}")
        print("Type 'help' for available commands")
    
    def emptyline(self):
        """Don't repeat last command on empty line"""
        pass

def setup_cli_completion():
    """Setup command-line completion for the main albator command"""
    completion_script = """
# Albator CLI completion for bash
_albator_completion() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    
    # Main commands
    opts="harden compliance rollback profile fleet dashboard history batch plugin help"
    
    case "${prev}" in
        albator|albator_enhanced.py)
            COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
            return 0
            ;;
        --profile)
            local profiles="basic advanced enterprise custom"
            COMPREPLY=( $(compgen -W "${profiles}" -- ${cur}) )
            return 0
            ;;
        --framework)
            local frameworks="nist_800_53 cis_macos iso27001 custom"
            COMPREPLY=( $(compgen -W "${frameworks}" -- ${cur}) )
            return 0
            ;;
        --format)
            local formats="console json html pdf"
            COMPREPLY=( $(compgen -W "${formats}" -- ${cur}) )
            return 0
            ;;
        profile)
            local subcommands="list show create delete export import compare"
            COMPREPLY=( $(compgen -W "${subcommands}" -- ${cur}) )
            return 0
            ;;
        fleet)
            local subcommands="list add remove status deploy scan"
            COMPREPLY=( $(compgen -W "${subcommands}" -- ${cur}) )
            return 0
            ;;
        plugin)
            local subcommands="list install remove enable disable"
            COMPREPLY=( $(compgen -W "${subcommands}" -- ${cur}) )
            return 0
            ;;
    esac
    
    # Handle options
    if [[ ${cur} == -* ]] ; then
        case "${COMP_WORDS[1]}" in
            harden)
                local opts="--profile --dry-run --force --backup --target"
                COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
                ;;
            compliance)
                local opts="--framework --format --output --verbose"
                COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
                ;;
            rollback)
                local opts="--point --list --dry-run --force"
                COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
                ;;
            fleet)
                local opts="--host --tag --profile --parallel"
                COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
                ;;
            dashboard)
                local opts="--days --format --metrics --export"
                COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
                ;;
            batch)
                local opts="--file --validate --parallel --continue-on-error"
                COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
                ;;
        esac
    fi
}

complete -F _albator_completion albator
complete -F _albator_completion albator_enhanced.py
complete -F _albator_completion ./albator_enhanced.py
"""
    
    # Save completion script
    completion_file = Path("~/.albator/albator_completion.bash").expanduser()
    completion_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(completion_file, 'w') as f:
        f.write(completion_script)
    
    print(f"Bash completion script saved to: {completion_file}")
    print(f"To enable: echo 'source {completion_file}' >> ~/.bashrc")

def main():
    """Main function for CLI enhancements"""
    parser = argparse.ArgumentParser(description="Albator CLI Enhancements")
    parser.add_argument('command', choices=['shell', 'setup-completion', 'demo'],
                       help='Enhancement command')
    
    args = parser.parse_args()
    
    if args.command == 'shell':
        # Launch interactive shell
        shell = InteractiveShell()
        shell.cmdloop()
        
    elif args.command == 'setup-completion':
        # Setup bash completion
        setup_cli_completion()
        
    elif args.command == 'demo':
        print("🎯 Albator CLI Enhancements Demo")
        print("=" * 50)
        
        # Demo auto-completion
        print("\n1. Auto-completion is now available:")
        print("   - Command completion: har<TAB> → harden")
        print("   - Option completion: --pro<TAB> → --profile")
        print("   - Value completion: --profile ba<TAB> → --profile basic")
        
        # Demo command history
        print("\n2. Command History:")
        history = CommandHistory()
        history.add_command("harden --profile enterprise --dry-run")
        history.add_command("compliance --framework nist_800_53")
        print("   Recent commands are saved and searchable")
        
        # Demo batch processing
        print("\n3. Batch Operations:")
        print("   Execute multiple commands from a file:")
        print("   $ albator batch commands.txt --continue-on-error")
        
        # Demo plugin system
        print("\n4. Plugin System:")
        print("   - Install plugins: plugin install security-extras https://github.com/...")
        print("   - List plugins: plugin list")
        print("   - Enable/disable plugins dynamically")
        
        print("\n✅ CLI enhancements are ready!")
        print("   Launch interactive shell: python3 lib/cli_enhancements.py shell")

if __name__ == "__main__":
    main()
