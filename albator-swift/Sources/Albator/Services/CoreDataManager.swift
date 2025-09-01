//
//  CoreDataManager.swift
//  Albator-Swift
//
//  Manages Core Data persistence for the application.
//

import Foundation
import CoreData

class CoreDataManager {
    static let shared = CoreDataManager()

    lazy var persistentContainer: NSPersistentContainer = {
        // Create a simple in-memory store instead of requiring a model file
        let container = NSPersistentContainer(name: "Albator")

        // Use in-memory store for now to avoid model file requirement
        let description = NSPersistentStoreDescription()
        description.type = NSInMemoryStoreType
        container.persistentStoreDescriptions = [description]

        container.loadPersistentStores { description, error in
            if let error = error {
                Logger.shared.warning("Failed to load Core Data stores (using in-memory): \(error.localizedDescription)")
                // Don't fatal error, just log and continue
            } else {
                Logger.shared.debug("Core Data store loaded successfully")
            }
        }
        return container
    }()

    var context: NSManagedObjectContext {
        return persistentContainer.viewContext
    }

    private init() {}

    func setup() {
        Logger.shared.info("Core Data setup completed (in-memory store)")
    }

    func saveContext() {
        if context.hasChanges {
            do {
                try context.save()
                Logger.shared.debug("Core Data context saved")
            } catch {
                Logger.shared.error("Failed to save Core Data context: \(error.localizedDescription)")
            }
        }
    }

    func cleanup() {
        saveContext()
        Logger.shared.info("Core Data cleanup completed")
    }
}
