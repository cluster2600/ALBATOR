//
//  SettingsView.swift
//  Albator-Swift
//
//  Settings view for application configuration.
//

import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var configManager: ConfigurationManager
    @State private var showingResetAlert = false

    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                // Header
                VStack(alignment: .leading, spacing: 8) {
                    Text("Settings")
                        .font(.largeTitle)
                        .fontWeight(.bold)

                    Text("Configure Albator security preferences")
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal)

                // General Settings
                VStack(alignment: .leading, spacing: 16) {
                    Text("General")
                        .font(.title2)
                        .fontWeight(.semibold)

                    Toggle("Automatic Security Scans", isOn: $configManager.autoScanEnabled)
                        .padding(.vertical, 8)

                    HStack {
                        Text("Scan Interval")
                        Spacer()
                        Text("\(Int(configManager.scanInterval / 3600)) hours")
                            .foregroundColor(.secondary)
                    }

                    Slider(value: $configManager.scanInterval, in: 1800...86400, step: 1800)
                        .padding(.vertical, 8)

                    Toggle("Enable Notifications", isOn: $configManager.notificationsEnabled)
                        .padding(.vertical, 8)
                }
                .padding()
                .background(Color(.windowBackgroundColor))
                .cornerRadius(12)
                .padding(.horizontal)

                // Appearance
                VStack(alignment: .leading, spacing: 16) {
                    Text("Appearance")
                        .font(.title2)
                        .fontWeight(.semibold)

                    Picker("Theme", selection: $configManager.theme) {
                        ForEach(AppTheme.allCases, id: \.self) { theme in
                            Text(theme.rawValue).tag(theme)
                        }
                    }
                    .pickerStyle(.segmented)
                    .padding(.vertical, 8)

                    HStack {
                        Text("Language")
                        Spacer()
                        Text(configManager.language.uppercased())
                            .foregroundColor(.secondary)
                    }
                    .padding(.vertical, 8)
                }
                .padding()
                .background(Color(.windowBackgroundColor))
                .cornerRadius(12)
                .padding(.horizontal)

                // Logging
                VStack(alignment: .leading, spacing: 16) {
                    Text("Logging")
                        .font(.title2)
                        .fontWeight(.semibold)

                    Picker("Log Level", selection: $configManager.logLevel) {
                        ForEach(LogLevel.allCases, id: \.self) { level in
                            Text(level.rawValue).tag(level)
                        }
                    }
                    .pickerStyle(.segmented)
                    .padding(.vertical, 8)

                    HStack {
                        Text("Export Path")
                        Spacer()
                        Text(configManager.exportPath)
                            .foregroundColor(.secondary)
                            .lineLimit(1)
                    }
                    .padding(.vertical, 8)
                }
                .padding()
                .background(Color(.windowBackgroundColor))
                .cornerRadius(12)
                .padding(.horizontal)

                // Actions
                VStack(spacing: 12) {
                    Button(action: {
                        configManager.saveCurrentState()
                    }) {
                        Text("Save Settings")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .padding(.horizontal)

                    Button(action: {
                        showingResetAlert = true
                    }) {
                        Text("Reset to Defaults")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                    .padding(.horizontal)
                }
                .padding(.vertical)
            }
            .padding(.vertical)
        }
        .alert("Reset Settings", isPresented: $showingResetAlert) {
            Button("Cancel", role: .cancel) {}
            Button("Reset", role: .destructive) {
                configManager.resetToDefaults()
            }
        } message: {
            Text("This will reset all settings to their default values. This action cannot be undone.")
        }
    }
}

struct SettingsView_Previews: PreviewProvider {
    static var previews: some View {
        SettingsView()
            .environmentObject(ConfigurationManager.shared)
    }
}
