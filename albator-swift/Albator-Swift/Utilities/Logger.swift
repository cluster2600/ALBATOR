//
//  Logger.swift
//  Albator-Swift
//
//  Centralized logging utility for the Albator application.
//

import Foundation
import os.log

// MARK: - Log Level
enum LogLevel: Int {
    case debug = 0
    case info = 1
    case warning = 2
    case error = 3

    var description: String {
        switch self {
        case .debug: return "DEBUG"
        case .info: return "INFO"
        case .warning: return "WARNING"
        case .error: return "ERROR"
        }
    }

    var osLogType: OSLogType {
        switch self {
        case .debug: return .debug
        case .info: return .info
        case .warning: return .default
        case .error: return .error
        }
    }
}

// MARK: - Logger
class Logger {
    static let shared = Logger()

    private let subsystem = "com.albator.security"
    private var loggers: [String: OSLog] = [:]
    private let dateFormatter: DateFormatter
    private let logQueue = DispatchQueue(label: "com.albator.logger", qos: .background)

    private init() {
        dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
        dateFormatter.locale = Locale(identifier: "en_US_POSIX")
    }

    private func logger(for category: String) -> OSLog {
        if let existingLogger = loggers[category] {
            return existingLogger
        }

        let newLogger = OSLog(subsystem: subsystem, category: category)
        loggers[category] = newLogger
        return newLogger
    }

    // MARK: - Public Logging Methods
    func debug(_ message: String, category: String = "general", file: String = #file, function: String = #function, line: Int = #line) {
        log(message, level: .debug, category: category, file: file, function: function, line: line)
    }

    func info(_ message: String, category: String = "general", file: String = #file, function: String = #function, line: Int = #line) {
        log(message, level: .info, category: category, file: file, function: function, line: line)
    }

    func warning(_ message: String, category: String = "general", file: String = #file, function: String = #function, line: Int = #line) {
        log(message, level: .warning, category: category, file: file, function: function, line: line)
    }

    func error(_ message: String, category: String = "general", file: String = #file, function: String = #function, line: Int = #line) {
        log(message, level: .error, category: category, file: file, function: function, line: line)
    }

    // MARK: - Private Logging Method
    private func log(_ message: String, level: LogLevel, category: String, file: String, function: String, line: Int) {
        let osLogger = logger(for: category)
        let timestamp = dateFormatter.string(from: Date())
        let filename = (file as NSString).lastPathComponent
        let formattedMessage = "[\(timestamp)] [\(level.description)] [\(filename):\(line)] \(function) - \(message)"

        // Log to system log
        os_log("%{public}@", log: osLogger, type: level.osLogType, formattedMessage)

        // Also log to console in debug mode
        #if DEBUG
        print(formattedMessage)
        #endif

        // Store log entry if needed
        storeLogEntry(formattedMessage, level: level)
    }

    // MARK: - Log Storage
    private func storeLogEntry(_ message: String, level: LogLevel) {
        logQueue.async {
            // In a real implementation, you might want to store logs to a file
            // or send them to a logging service
            self.appendToLogFile(message)
        }
    }

    private func appendToLogFile(_ message: String) {
        guard let documentsDirectory = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first else {
            return
        }

        let logFileURL = documentsDirectory.appendingPathComponent("albator.log")

        do {
            let logEntry = message + "\n"
            if FileManager.default.fileExists(atPath: logFileURL.path) {
                let fileHandle = try FileHandle(forWritingTo: logFileURL)
                fileHandle.seekToEndOfFile()
                if let data = logEntry.data(using: .utf8) {
                    fileHandle.write(data)
                }
                fileHandle.closeFile()
            } else {
                try logEntry.write(to: logFileURL, atomically: true, encoding: .utf8)
            }
        } catch {
            // If we can't write to the log file, we'll just continue
            // In a production app, you might want to handle this differently
            print("Failed to write to log file: \(error)")
        }
    }

    // MARK: - Log Retrieval
    func getRecentLogs(limit: Int = 100) -> [String] {
        guard let documentsDirectory = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first else {
            return []
        }

        let logFileURL = documentsDirectory.appendingPathComponent("albator.log")

        do {
            let logContent = try String(contentsOf: logFileURL, encoding: .utf8)
            let lines = logContent.components(separatedBy: .newlines)
            return Array(lines.reversed().prefix(limit).reversed())
        } catch {
            return []
        }
    }

    func clearLogs() {
        guard let documentsDirectory = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first else {
            return
        }

        let logFileURL = documentsDirectory.appendingPathComponent("albator.log")

        do {
            try FileManager.default.removeItem(at: logFileURL)
        } catch {
            self.error("Failed to clear logs: \(error.localizedDescription)")
        }
    }

    // MARK: - Performance Logging
    func logPerformance(_ operation: String, duration: TimeInterval, category: String = "performance") {
        let message = "\(operation) completed in \(String(format: "%.3f", duration)) seconds"
        info(message, category: category)
    }

    // MARK: - Security Event Logging
    func logSecurityEvent(_ event: String, details: [String: Any]? = nil, category: String = "security") {
        var message = "Security Event: \(event)"
        if let details = details {
            message += " - Details: \(details)"
        }
        warning(message, category: category)
    }

    // MARK: - Error Logging with Context
    func logError(_ error: Error, context: String? = nil, category: String = "error") {
        var message = "Error: \(error.localizedDescription)"
        if let context = context {
            message = "\(context) - \(message)"
        }
        self.error(message, category: category)
    }
}

// MARK: - Convenience Extensions
extension Logger {
    static func debug(_ message: String, category: String = "general", file: String = #file, function: String = #function, line: Int = #line) {
        shared.debug(message, category: category, file: file, function: function, line: line)
    }

    static func info(_ message: String, category: String = "general", file: String = #file, function: String = #function, line: Int = #line) {
        shared.info(message, category: category, file: file, function: function, line: line)
    }

    static func warning(_ message: String, category: String = "general", file: String = #file, function: String = #function, line: Int = #line) {
        shared.warning(message, category: category, file: file, function: function, line: line)
    }

    static func error(_ message: String, category: String = "general", file: String = #file, function: String = #function, line: Int = #line) {
        shared.error(message, category: category, file: file, function: function, line: line)
    }
}
