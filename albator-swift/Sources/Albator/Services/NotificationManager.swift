//
//  NotificationManager.swift
//  Albator-Swift
//
//  Manages notifications and alerts for the Albator security application.
//

import Foundation
import UserNotifications
import SwiftUI

// MARK: - Notification Type
enum NotificationType {
    case securityAlert
    case scanComplete
    case systemUpdate
    case criticalAlert
    case info
}

// MARK: - Notification Manager
class NotificationManager: ObservableObject {
    static let shared = NotificationManager()

    @Published var notificationsEnabled = true
    @Published var pendingNotifications: [AlbatorNotification] = []

    private let notificationCenter = UNUserNotificationCenter.current()
    private let notificationKey = "albator_notifications"

    private init() {
        requestAuthorization()
        loadPendingNotifications()
    }

    func requestAuthorization() {
        notificationCenter.requestAuthorization(options: [.alert, .sound, .badge]) { granted, error in
            if let error = error {
                Logger.shared.error("Notification authorization failed: \(error.localizedDescription)")
            }

            DispatchQueue.main.async {
                self.notificationsEnabled = granted
            }
        }
    }

    func scheduleNotification(
        title: String,
        body: String,
        type: NotificationType,
        delay: TimeInterval = 0,
        userInfo: [String: Any]? = nil
    ) {
        guard notificationsEnabled else { return }

        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = .default
        content.userInfo = userInfo ?? [:]

        // Set category based on type
        switch type {
        case .securityAlert:
            content.categoryIdentifier = "SECURITY_ALERT"
            content.sound = .defaultCritical
        case .criticalAlert:
            content.categoryIdentifier = "CRITICAL_ALERT"
            content.sound = .defaultCritical
        case .scanComplete:
            content.categoryIdentifier = "SCAN_COMPLETE"
        case .systemUpdate:
            content.categoryIdentifier = "SYSTEM_UPDATE"
        case .info:
            content.categoryIdentifier = "INFO"
        }

        let trigger: UNNotificationTrigger
        if delay > 0 {
            trigger = UNTimeIntervalNotificationTrigger(timeInterval: delay, repeats: false)
        } else {
            trigger = UNTimeIntervalNotificationTrigger(timeInterval: 1, repeats: false)
        }

        let request = UNNotificationRequest(
            identifier: UUID().uuidString,
            content: content,
            trigger: trigger
        )

        notificationCenter.add(request) { error in
            if let error = error {
                Logger.shared.error("Failed to schedule notification: \(error.localizedDescription)")
            } else {
                Logger.shared.info("Notification scheduled: \(title)")
            }
        }

        // Add to pending notifications
        let notification = AlbatorNotification(
            id: request.identifier,
            title: title,
            body: body,
            type: type,
            timestamp: Date().addingTimeInterval(delay),
            isDelivered: false
        )

        DispatchQueue.main.async {
            self.pendingNotifications.append(notification)
            self.savePendingNotifications()
        }
    }

    func showImmediateNotification(
        title: String,
        body: String,
        type: NotificationType = .info
    ) {
        scheduleNotification(title: title, body: body, type: type, delay: 0)
    }

    func cancelNotification(identifier: String) {
        notificationCenter.removePendingNotificationRequests(withIdentifiers: [identifier])

        DispatchQueue.main.async {
            self.pendingNotifications.removeAll { $0.id == identifier }
            self.savePendingNotifications()
        }
    }

    func cancelAllNotifications() {
        notificationCenter.removeAllPendingNotificationRequests()
        notificationCenter.removeAllDeliveredNotifications()

        DispatchQueue.main.async {
            self.pendingNotifications.removeAll()
            self.savePendingNotifications()
        }
    }

    func markNotificationAsRead(_ notification: AlbatorNotification) {
        DispatchQueue.main.async {
            if let index = self.pendingNotifications.firstIndex(where: { $0.id == notification.id }) {
                self.pendingNotifications[index].isDelivered = true
                self.savePendingNotifications()
            }
        }
    }

    private func loadPendingNotifications() {
        if let data = UserDefaults.standard.data(forKey: notificationKey),
           let notifications = try? JSONDecoder().decode([AlbatorNotification].self, from: data) {
            self.pendingNotifications = notifications
        }
    }

    private func savePendingNotifications() {
        if let data = try? JSONEncoder().encode(pendingNotifications) {
            UserDefaults.standard.set(data, forKey: notificationKey)
        }
    }

    // MARK: - Convenience Methods
    func showSecurityAlert(title: String, body: String) {
        showImmediateNotification(title: title, body: body, type: .securityAlert)
    }

    func showScanComplete() {
        showImmediateNotification(
            title: "Security Scan Complete",
            body: "Your system security scan has finished successfully.",
            type: .scanComplete
        )
    }

    func showCriticalAlert(title: String, body: String) {
        showImmediateNotification(title: title, body: body, type: .criticalAlert)
    }

    func showSystemUpdateAvailable() {
        showImmediateNotification(
            title: "System Updates Available",
            body: "Security updates are available for your system.",
            type: .systemUpdate
        )
    }
}

// MARK: - Albator Notification Model
struct AlbatorNotification: Identifiable, Codable {
    let id: String
    let title: String
    let body: String
    let type: NotificationType
    let timestamp: Date
    var isDelivered: Bool

    enum CodingKeys: String, CodingKey {
        case id, title, body, timestamp, isDelivered
        case typeString
    }

    init(id: String, title: String, body: String, type: NotificationType, timestamp: Date, isDelivered: Bool) {
        self.id = id
        self.title = title
        self.body = body
        self.type = type
        self.timestamp = timestamp
        self.isDelivered = isDelivered
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        title = try container.decode(String.self, forKey: .title)
        body = try container.decode(String.self, forKey: .body)
        timestamp = try container.decode(Date.self, forKey: .timestamp)
        isDelivered = try container.decode(Bool.self, forKey: .isDelivered)

        let typeString = try container.decode(String.self, forKey: .typeString)
        switch typeString {
        case "securityAlert": type = .securityAlert
        case "scanComplete": type = .scanComplete
        case "systemUpdate": type = .systemUpdate
        case "criticalAlert": type = .criticalAlert
        default: type = .info
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(title, forKey: .title)
        try container.encode(body, forKey: .body)
        try container.encode(timestamp, forKey: .timestamp)
        try container.encode(isDelivered, forKey: .isDelivered)

        let typeString: String
        switch type {
        case .securityAlert: typeString = "securityAlert"
        case .scanComplete: typeString = "scanComplete"
        case .systemUpdate: typeString = "systemUpdate"
        case .criticalAlert: typeString = "criticalAlert"
        case .info: typeString = "info"
        }
        try container.encode(typeString, forKey: .typeString)
    }
}
