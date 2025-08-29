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
        let container = NSPersistentContainer(name: "Albator")
        container.loadPersistentStores { description, error in
            if let error = error {
                Logger.shared.error("Failed to load Core Data stores: \(error.localizedDescription)")
                fatalError("Unresolved error \(error)")
            }
        }
        return container
    }()

    var context: NSManagedObjectContext {
        return persistentContainer.viewContext
    }

    private init() {}

    func setup() {
        Logger.shared.info("Core Data setup completed")
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
