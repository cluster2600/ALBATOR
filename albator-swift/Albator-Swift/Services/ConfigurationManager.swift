//
//  ConfigurationManager.swift
//  Albator-Swift
//
//  Manages application configuration and user preferences
//  for the Albator macOS security hardening tool.
//

import Foundation
import SwiftUI
import Combine

// MARK: - Configuration Keys
enum ConfigurationKey: String {
    case autoScanEnabled = "autoScanEnabled"
    case scanInterval = "scanInterval"
    case notificationsEnabled = "notificationsEnabled"
    case logLevel = "logLevel"
    case theme = "theme"
    case language = "language"
    case exportPath = "exportPath"
}

// MARK: - Theme Enum
enum AppTheme: String, CaseIterable {
    case system = "System"
    case light = "Light"
    case dark = "Dark"
}

// MARK: - Log Level Enum
enum LogLevel: String, CaseIterable {
    case debug = "Debug"
    case info = "Info"
    case warning = "Warning"
    case error = "Error"
}

// MARK: - Configuration Manager
class ConfigurationManager: ObservableObject {
    static let shared = ConfigurationManager()

    @Published var autoScanEnabled: Bool = true
    @Published var scanInterval: TimeInterval = 3600 // 1 hour
    @Published var notificationsEnabled: Bool = true
    @Published var logLevel: LogLevel = .info
    @Published var theme: AppTheme = .system
    @Published var language: String = "en"
    @Published var exportPath: String = "~/Desktop"

    private let userDefaults = UserDefaults.standard
    private let configurationKey = "albator_configuration"

    private init() {
        loadConfiguration()
    }

    func saveCurrentState() {
        let configuration: [String: Any] = [
            ConfigurationKey.autoScanEnabled.rawValue: autoScanEnabled,
            ConfigurationKey.scanInterval.rawValue: scanInterval,
            ConfigurationKey.notificationsEnabled.rawValue: notificationsEnabled,
            ConfigurationKey.logLevel.rawValue: logLevel.rawValue,
            ConfigurationKey.theme.rawValue: theme.rawValue,
            ConfigurationKey.language.rawValue: language,
            ConfigurationKey.exportPath.rawValue: exportPath
        ]

        userDefaults.set(configuration, forKey: configurationKey)
        userDefaults.synchronize()
    }

    private func loadConfiguration() {
        guard let configuration = userDefaults.dictionary(forKey: configurationKey) else {
            return
        }

        autoScanEnabled = configuration[ConfigurationKey.autoScanEnabled.rawValue] as? Bool ?? true
        scanInterval = configuration[ConfigurationKey.scanInterval.rawValue] as? TimeInterval ?? 3600
        notificationsEnabled = configuration[ConfigurationKey.notificationsEnabled.rawValue] as? Bool ?? true

        if let logLevelString = configuration[ConfigurationKey.logLevel.rawValue] as? String,
           let logLevelValue = LogLevel(rawValue: logLevelString) {
            logLevel = logLevelValue
        }

        if let themeString = configuration[ConfigurationKey.theme.rawValue] as? String,
           let themeValue = AppTheme(rawValue: themeString) {
            theme = themeValue
        }

        language = configuration[ConfigurationKey.language.rawValue] as? String ?? "en"
        exportPath = configuration[ConfigurationKey.exportPath.rawValue] as? String ?? "~/Desktop"
    }

    func resetToDefaults() {
        autoScanEnabled = true
        scanInterval = 3600
        notificationsEnabled = true
        logLevel = .info
        theme = .system
        language = "en"
        exportPath = "~/Desktop"

        saveCurrentState()
    }

    func exportConfiguration() -> Data? {
        let configuration: [String: Any] = [
            ConfigurationKey.autoScanEnabled.rawValue: autoScanEnabled,
            ConfigurationKey.scanInterval.rawValue: scanInterval,
            ConfigurationKey.notificationsEnabled.rawValue: notificationsEnabled,
            ConfigurationKey.logLevel.rawValue: logLevel.rawValue,
            ConfigurationKey.theme.rawValue: theme.rawValue,
            ConfigurationKey.language.rawValue: language,
            ConfigurationKey.exportPath.rawValue: exportPath
        ]

        return try? JSONSerialization.data(withJSONObject: configuration, options: .prettyPrinted)
    }

    func importConfiguration(from data: Data) -> Bool {
        do {
            let configuration = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any]

            if let config = configuration {
                autoScanEnabled = config[ConfigurationKey.autoScanEnabled.rawValue] as? Bool ?? autoScanEnabled
                scanInterval = config[ConfigurationKey.scanInterval.rawValue] as? TimeInterval ?? scanInterval
                notificationsEnabled = config[ConfigurationKey.notificationsEnabled.rawValue] as? Bool ?? notificationsEnabled

                if let logLevelString = config[ConfigurationKey.logLevel.rawValue] as? String,
                   let logLevelValue = LogLevel(rawValue: logLevelString) {
                    logLevel = logLevelValue
                }

                if let themeString = config[ConfigurationKey.theme.rawValue] as? String,
                   let themeValue = AppTheme(rawValue: themeString) {
                    theme = themeValue
                }

                language = config[ConfigurationKey.language.rawValue] as? String ?? language
                exportPath = config[ConfigurationKey.exportPath.rawValue] as? String ?? exportPath

                saveCurrentState()
                return true
            }
        } catch {
            Logger.shared.error("Failed to import configuration: \(error.localizedDescription)")
        }

        return false
    }
}
