import Foundation

public extension Notification.Name {
    static let showDashboard = Notification.Name("showDashboard")
    static let showNetworkScanner = Notification.Name("showNetworkScanner")
    static let showCompliance = Notification.Name("showCompliance")
    static let showReports = Notification.Name("showReports")
    static let securityScanCompleted = Notification.Name("securityScanCompleted")
    static let criticalAlertDetected = Notification.Name("criticalAlertDetected")
}
