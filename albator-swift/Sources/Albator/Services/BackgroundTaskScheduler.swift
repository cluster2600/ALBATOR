//
//  BackgroundTaskScheduler.swift
//  Albator-Swift
//
//  Manages background tasks and scheduling for macOS.
//

import Foundation

class BackgroundTaskScheduler {
    static let shared = BackgroundTaskScheduler()

    private var securityScanTimer: Timer?
    private var cleanupTimer: Timer?

    private init() {
        Logger.shared.info("Background task scheduler initialized")
    }

    func scheduleSecurityScans() {
        // Cancel existing timer if any
        securityScanTimer?.invalidate()

        // Schedule new security scan every hour
        securityScanTimer = Timer.scheduledTimer(withTimeInterval: 3600, repeats: true) { [weak self] _ in
            Task {
                await SecurityEngine.shared.performComprehensiveScan()
            }
        }

        Logger.shared.info("Security scan scheduled every hour")
    }

    func scheduleCleanupTasks() {
        // Cancel existing timer if any
        cleanupTimer?.invalidate()

        // Schedule cleanup every 24 hours
        cleanupTimer = Timer.scheduledTimer(withTimeInterval: 86400, repeats: true) { [weak self] _ in
            self?.performCleanup()
        }

        Logger.shared.info("Cleanup task scheduled every 24 hours")
    }

    func cancelAllTasks() {
        securityScanTimer?.invalidate()
        cleanupTimer?.invalidate()
        securityScanTimer = nil
        cleanupTimer = nil
        Logger.shared.info("All background tasks cancelled")
    }

    private func performCleanup() {
        Logger.shared.info("Background cleanup started")

        // Clean up old log files
        Logger.shared.clearLogs()

        // Clean up temporary files
        // In a real implementation, this would clean up temp files

        Logger.shared.info("Cleanup completed")
    }

    deinit {
        cancelAllTasks()
    }
}
