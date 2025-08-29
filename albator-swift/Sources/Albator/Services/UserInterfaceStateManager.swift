//
//  UserInterfaceStateManager.swift
//  Albator-Swift
//
//  Manages UI state persistence and restoration.
//

import Foundation
import SwiftUI

class UserInterfaceStateManager {
    static let shared = UserInterfaceStateManager()

    private let stateKey = "albator_ui_state"

    @Published var selectedView: String = "dashboard"
    @Published var sidebarCollapsed: Bool = false
    @Published var windowSize: CGSize = CGSize(width: 1000, height: 700)

    private init() {
        loadState()
    }

    func saveState() {
        let state: [String: Any] = [
            "selectedView": selectedView,
            "sidebarCollapsed": sidebarCollapsed,
            "windowWidth": windowSize.width,
            "windowHeight": windowSize.height
        ]

        UserDefaults.standard.set(state, forKey: stateKey)
        Logger.shared.debug("UI state saved")
    }

    private func loadState() {
        guard let state = UserDefaults.standard.dictionary(forKey: stateKey) else {
            return
        }

        selectedView = state["selectedView"] as? String ?? "dashboard"
        sidebarCollapsed = state["sidebarCollapsed"] as? Bool ?? false

        if let width = state["windowWidth"] as? CGFloat,
           let height = state["windowHeight"] as? CGFloat {
            windowSize = CGSize(width: width, height: height)
        }

        Logger.shared.debug("UI state loaded")
    }

    func resetToDefaults() {
        selectedView = "dashboard"
        sidebarCollapsed = false
        windowSize = CGSize(width: 1000, height: 700)
        saveState()
    }
}
