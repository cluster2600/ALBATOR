//
//  DataMigrationManager.swift
//  Albator-Swift
//
//  Handles data migration between app versions.
//

import Foundation

public class DataMigrationManager {
    public static let shared = DataMigrationManager()

    private let migrationKey = "albator_migration_version"
    private let currentVersion = "1.0.0"

    private init() {}

    public func performMigrationIfNeeded() {
        let lastVersion = UserDefaults.standard.string(forKey: migrationKey) ?? "0.0.0"

        if lastVersion != currentVersion {
            Logger.shared.info("Performing data migration from \(lastVersion) to \(currentVersion)")
            performMigration(from: lastVersion, to: currentVersion)
            UserDefaults.standard.set(currentVersion, forKey: migrationKey)
        } else {
            Logger.shared.debug("No migration needed, already at version \(currentVersion)")
        }
    }

    private func performMigration(from oldVersion: String, to newVersion: String) {
        // Handle migrations based on version differences
        switch (oldVersion, newVersion) {
        case ("0.0.0", "1.0.0"):
            migrateFrom0To1()
        default:
            Logger.shared.warning("Unknown migration path from \(oldVersion) to \(newVersion)")
        }
    }

    private func migrateFrom0To1() {
        // Migration logic for initial version
        Logger.shared.info("Migrating from version 0.0.0 to 1.0.0")

        // Reset configuration to defaults if needed
        ConfigurationManager.shared.resetToDefaults()

        // Clear any old cached data
        UserDefaults.standard.removeObject(forKey: "old_cache_key")

        Logger.shared.info("Migration to version 1.0.0 completed")
    }
}
