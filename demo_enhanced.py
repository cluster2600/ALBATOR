#!/usr/bin/env python3
"""
Albator Enhanced Demo Script
Demonstrates the new unified CLI and enterprise features
"""

import os
import sys
import time
import subprocess
from datetime import datetime

def print_banner():
    """Print demo banner"""
    print("=" * 80)
    print("🛡️  ALBATOR ENHANCED - ENTERPRISE SECURITY PLATFORM DEMO")
    print("=" * 80)
    print(f"Demo started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

def print_section(title):
    """Print section header"""
    print(f"\n{'='*20} {title} {'='*20}")

def run_demo_command(description, command, dry_run=True):
    """Run a demo command with description"""
    print(f"\n📋 {description}")
    print(f"💻 Command: {' '.join(command)}")
    
    if dry_run:
        print("🔍 [DRY RUN MODE - No actual changes made]")
        # Simulate command execution
        time.sleep(1)
        print("✅ Command would execute successfully")
        return True
    else:
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                print("✅ Command executed successfully")
                if result.stdout:
                    print(f"📤 Output: {result.stdout[:200]}...")
                return True
            else:
                print(f"❌ Command failed: {result.stderr}")
                return False
        except subprocess.TimeoutExpired:
            print("⏰ Command timed out")
            return False
        except Exception as e:
            print(f"❌ Error: {e}")
            return False

def demo_profile_management():
    """Demo profile management features"""
    print_section("PROFILE MANAGEMENT")
    
    # List available profiles
    run_demo_command(
        "List available security profiles",
        ["python3", "albator_enhanced.py", "profile", "list"]
    )
    
    # Create custom profile
    run_demo_command(
        "Create custom security profile",
        ["python3", "albator_enhanced.py", "profile", "create", "demo_profile", 
         "--description", "Demo security profile", "--security-level", "75"]
    )
    
    # Show profile info
    run_demo_command(
        "Show profile information",
        ["python3", "albator_enhanced.py", "profile", "info", "basic"]
    )

def demo_hardening():
    """Demo hardening capabilities"""
    print_section("SECURITY HARDENING")
    
    # Comprehensive hardening with dry run
    run_demo_command(
        "Run comprehensive hardening (dry-run)",
        ["python3", "albator_enhanced.py", "harden", "--profile", "advanced", "--dry-run"]
    )
    
    # Individual script hardening
    run_demo_command(
        "Run privacy hardening only",
        ["python3", "albator_enhanced.py", "harden", "--script", "privacy", "--dry-run"]
    )

def demo_compliance():
    """Demo compliance scanning"""
    print_section("COMPLIANCE SCANNING")
    
    # NIST 800-53 compliance scan
    run_demo_command(
        "Run NIST 800-53 compliance scan",
        ["python3", "albator_enhanced.py", "compliance", "--framework", "nist_800_53", "--format", "html"]
    )
    
    # CIS macOS compliance scan
    run_demo_command(
        "Run CIS macOS compliance scan",
        ["python3", "albator_enhanced.py", "compliance", "--framework", "cis_macos", "--format", "json"]
    )

def demo_analytics():
    """Demo analytics dashboard"""
    print_section("ANALYTICS DASHBOARD")
    
    # Generate security dashboard
    run_demo_command(
        "Generate security analytics dashboard",
        ["python3", "albator_enhanced.py", "dashboard", "--days", "30"]
    )
    
    # Show compliance trends
    run_demo_command(
        "Analyze compliance trends",
        ["python3", "lib/analytics_dashboard.py", "trends", "--days", "30"]
    )

def demo_fleet_management():
    """Demo fleet management (simulated)"""
    print_section("FLEET MANAGEMENT")
    
    # List fleet systems
    run_demo_command(
        "List fleet systems",
        ["python3", "albator_enhanced.py", "fleet", "list"]
    )
    
    # Add system to fleet (demo)
    run_demo_command(
        "Add system to fleet",
        ["python3", "albator_enhanced.py", "fleet", "add", "demo-mac-01", "192.168.1.100", 
         "--username", "admin"]
    )

def demo_rollback():
    """Demo rollback management"""
    print_section("ROLLBACK MANAGEMENT")
    
    # List rollback points
    run_demo_command(
        "List available rollback points",
        ["python3", "albator_enhanced.py", "rollback", "list"]
    )
    
    # Create rollback point
    run_demo_command(
        "Create rollback point",
        ["python3", "albator_enhanced.py", "rollback", "create", 
         "--description", "Demo rollback point"]
    )

def demo_legacy_integration():
    """Demo legacy tool integration"""
    print_section("LEGACY TOOL INTEGRATION")
    
    # Show legacy CLI capabilities
    run_demo_command(
        "List legacy baseline tags",
        ["python3", "albator_cli.py", "legacy", "list_tags"]
    )
    
    # Individual script execution
    run_demo_command(
        "Run individual privacy script",
        ["./privacy.sh", "--dry-run"]
    )

def demo_web_interface():
    """Demo web interface"""
    print_section("WEB INTERFACE")
    
    print("🌐 Web Interface Features:")
    print("   • Real-time security dashboard")
    print("   • Interactive compliance reports")
    print("   • Fleet management interface")
    print("   • Profile management GUI")
    print("   • Live operation monitoring")
    print("   • Mobile-responsive design")
    print()
    print("💡 To start the web interface:")
    print("   python3 web/app.py")
    print("   Then open: http://localhost:5000")

def main():
    """Main demo function"""
    print_banner()
    
    # Check if we're in the right directory
    if not os.path.exists("albator_enhanced.py"):
        print("❌ Error: Please run this demo from the Albator root directory")
        print("   The albator_enhanced.py file should be in the current directory")
        sys.exit(1)
    
    print("🎯 This demo showcases Albator's enhanced enterprise features:")
    print("   • Unified CLI interface")
    print("   • Profile-based security management")
    print("   • Multi-framework compliance scanning")
    print("   • Advanced analytics and reporting")
    print("   • Fleet management capabilities")
    print("   • Comprehensive rollback system")
    print("   • Legacy tool integration")
    print()
    
    # Ask user for demo mode
    print("Demo Modes:")
    print("1. Full Demo (all features)")
    print("2. Quick Demo (core features only)")
    print("3. Interactive Demo (step-by-step)")
    
    try:
        choice = input("\nSelect demo mode (1-3): ").strip()
    except KeyboardInterrupt:
        print("\n\n👋 Demo cancelled by user")
        sys.exit(0)
    
    if choice == "1":
        # Full demo
        demo_profile_management()
        demo_hardening()
        demo_compliance()
        demo_analytics()
        demo_fleet_management()
        demo_rollback()
        demo_legacy_integration()
        demo_web_interface()
        
    elif choice == "2":
        # Quick demo
        demo_profile_management()
        demo_hardening()
        demo_compliance()
        demo_web_interface()
        
    elif choice == "3":
        # Interactive demo
        sections = [
            ("Profile Management", demo_profile_management),
            ("Security Hardening", demo_hardening),
            ("Compliance Scanning", demo_compliance),
            ("Analytics Dashboard", demo_analytics),
            ("Fleet Management", demo_fleet_management),
            ("Rollback Management", demo_rollback),
            ("Legacy Integration", demo_legacy_integration),
            ("Web Interface", demo_web_interface)
        ]
        
        for name, func in sections:
            try:
                input(f"\nPress Enter to demo {name}...")
                func()
            except KeyboardInterrupt:
                print(f"\n\n👋 Demo stopped at {name}")
                break
    else:
        print("❌ Invalid choice. Running quick demo...")
        demo_profile_management()
        demo_hardening()
        demo_compliance()
    
    print("\n" + "="*80)
    print("🎉 DEMO COMPLETED")
    print("="*80)
    print("📚 Next Steps:")
    print("   • Review the generated reports and dashboards")
    print("   • Explore the web interface at http://localhost:5000")
    print("   • Check the CHANGELOG.md for detailed feature information")
    print("   • Read the README.md for comprehensive usage instructions")
    print()
    print("🔗 Key Files:")
    print("   • albator_enhanced.py - Main enhanced CLI")
    print("   • config/albator.yaml - Configuration management")
    print("   • web/app.py - Web interface")
    print("   • lib/ - Enterprise feature libraries")
    print()
    print("💡 For production use, remove --dry-run flags and configure")
    print("   your security profiles according to organizational requirements.")
    print()
    print("🛡️  Thank you for exploring Albator Enhanced!")

if __name__ == "__main__":
    main()
