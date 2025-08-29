//
//  BackgroundTaskScheduler.swift
//  Albator-Swift
//
//  Manages background tasks and scheduling.
//

import Foundation
import BackgroundTasks

class BackgroundTaskScheduler {
    static let shared = BackgroundTaskScheduler()

    private init() {
        registerBackgroundTasks()
    }

    func registerBackgroundTasks() {
        BGTaskScheduler.shared.register(forTaskWithIdentifier: "com.albator.security.scan", using: nil) { task in
            self.handleSecurityScan(task: task as! BGProcessingTask)
        }

        BGTaskScheduler.shared.register(forTaskWithIdentifier: "com.albator.cleanup", using: nil) { task in
            self.handleCleanup(task: task as! BGProcessingTask)
        }

        Logger.shared.info("Background tasks registered")
    }

    func scheduleSecurityScans() {
        let request = BGProcessingTaskRequest(identifier: "com.albator.security.scan")
        request.requiresNetworkConnectivity = false
        request.requiresExternalPower = false
        request.earliestBeginDate = Date(timeIntervalSinceNow: 3600) // 1 hour from now

        do {
            try BGTaskScheduler.shared.submit(request)
            Logger.shared.info("Security scan task scheduled")
        } catch {
            Logger.shared.error("Failed to schedule security scan: \(error.localizedDescription)")
        }
    }

    func scheduleCleanupTasks() {
        let request = BGProcessingTaskRequest(identifier: "com.albator.cleanup")
        request.requiresNetworkConnectivity = false
        request.requiresExternalPower = false
        request.earliestBeginDate = Date(timeIntervalSinceNow: 86400) // 24 hours from now

        do {
            try BGTaskScheduler.shared.submit(request)
            Logger.shared.info("Cleanup task scheduled")
        } catch {
            Logger.shared.error("Failed to schedule cleanup: \(error.localizedDescription)")
        }
    }

    func cancelAllTasks() {
        BGTaskScheduler.shared.cancelAllTaskRequests()
        Logger.shared.info("All background tasks cancelled")
    }

    private func handleSecurityScan(task: BGProcessingTask) {
        Logger.shared.info("Background security scan started")

        // Perform security scan
        Task {
            await SecurityEngine.shared.performComprehensiveScan()
            task.setTaskCompleted(success: true)
        }

        // Schedule next scan
        scheduleSecurityScans()
    }

    private func handleCleanup(task: BGProcessingTask) {
        Logger.shared.info("Background cleanup started")

        // Perform cleanup operations
        performCleanup()

        task.setTaskCompleted(success: true)

        // Schedule next cleanup
        scheduleCleanupTasks()
    }

    private func performCleanup() {
        // Clean up old log files
        Logger.shared.clearLogs()

        // Clean up temporary files
        // In a real implementation, this would clean up temp files

        Logger.shared.info("Cleanup completed")
    }
}
