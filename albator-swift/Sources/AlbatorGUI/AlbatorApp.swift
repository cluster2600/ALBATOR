//
//  AlbatorApp.swift
//  Albator-Swift
//
//  Created by Albator Migration Tool
//  Original Python codebase: https://github.com/cluster2600/ALBATOR
//
//  This is the main application entry point for the Swift version of Albator,
//  a comprehensive macOS security hardening and compliance tool.
//

import SwiftUI
import AlbatorCore

@main
struct AlbatorApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    
    var body: some Scene {
        WindowGroup {
            MainWindowView()
                .environmentObject(SecurityEngine.shared)
                .environmentObject(ConfigurationManager.shared)
                .environmentObject(NotificationManager.shared)
        }
        .windowStyle(.titleBar)
        .windowToolbarStyle(.unifiedCompact)
        .commands {
            AppCommands()
            SecurityCommands()
            ViewCommands()
        }
        
        Settings {
            SettingsView()
        }
    }
}

// MARK: - App Delegate
@MainActor
class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        Logger.shared.info("Albator Swift application launched")
        setupCoreServices()
        configureSecurityMonitoring()
        setupPeriodicTasks()
    }
    
    func applicationWillTerminate(_ notification: Notification) {
        Logger.shared.info("Albator Swift application terminating")
        saveApplicationState()
        cleanupResources()
    }
    
    private func setupCoreServices() {
        _ = SecurityEngine.shared
        _ = ConfigurationManager.shared
        _ = NotificationManager.shared
        setupDataPersistence()
    }
    
    private func configureSecurityMonitoring() {
        SystemMonitor.shared.startMonitoring()
        SecurityEventHandler.shared.startHandling()
    }
    
    private func setupPeriodicTasks() {
        BackgroundTaskScheduler.shared.scheduleSecurityScans()
        BackgroundTaskScheduler.shared.scheduleCleanupTasks()
    }
    
    private func setupDataPersistence() {
        CoreDataManager.shared.setup()
        DataMigrationManager.shared.performMigrationIfNeeded()
    }
    
    private func saveApplicationState() {
        ConfigurationManager.shared.saveCurrentState()
        UserInterfaceStateManager.shared.saveState()
    }
    
    private func cleanupResources() {
        SystemMonitor.shared.stopMonitoring()
        BackgroundTaskScheduler.shared.cancelAllTasks()
        CoreDataManager.shared.cleanup()
    }
}

// MARK: - Command Groups
struct AppCommands: Commands {
    var body: some Commands {
        CommandGroup(replacing: .appInfo) {
            Button("About Albator") {
                NSApp.orderFrontStandardAboutPanel()
            }
        }
        
        CommandGroup(replacing: .appTermination) {
            Button("Quit Albator") {
                NSApp.terminate(nil)
            }
            .keyboardShortcut("q", modifiers: .command)
        }
    }
}

struct SecurityCommands: Commands {
    @ObservedObject var securityEngine = SecurityEngine.shared
    
    var body: some Commands {
        CommandGroup(after: .toolbar) {
            Button("Start Security Scan") {
                Task {
                    await securityEngine.performComprehensiveScan()
                }
            }
            .keyboardShortcut("s", modifiers: [.command, .shift])
            .disabled(securityEngine.isScanning)
            
            Button("Generate Report") {
                Task {
                    await ReportGenerator.shared.generateComprehensiveReport()
                }
            }
            .keyboardShortcut("r", modifiers: [.command, .shift])
            
            Divider()
            
            Button("Emergency Stop") {
                securityEngine.emergencyStop()
            }
            .keyboardShortcut("e", modifiers: [.command, .shift])
        }
    }
}

struct ViewCommands: Commands {
    var body: some Commands {
        CommandGroup(after: .sidebar) {
            Button("Show Dashboard") {
                NotificationCenter.default.post(name: .showDashboard, object: nil)
            }
            .keyboardShortcut("1", modifiers: .command)
            
            Button("Show Network Scanner") {
                NotificationCenter.default.post(name: .showNetworkScanner, object: nil)
            }
            .keyboardShortcut("2", modifiers: .command)
            
            Button("Show Compliance") {
                NotificationCenter.default.post(name: .showCompliance, object: nil)
            }
            .keyboardShortcut("3", modifiers: .command)
            
            Button("Show Reports") {
                NotificationCenter.default.post(name: .showReports, object: nil)
            }
            .keyboardShortcut("4", modifiers: .command)
        }
    }
}
