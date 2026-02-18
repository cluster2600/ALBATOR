import XCTest
@testable import AlbatorCore

final class SystemSecurityProbeTests: XCTestCase {
    func testVersionComparison() {
        XCTAssertTrue(SystemSecurityProbe.versionMeetsMinimum(current: "26.3", minimum: "26.3"))
        XCTAssertTrue(SystemSecurityProbe.versionMeetsMinimum(current: "26.4", minimum: "26.3"))
        XCTAssertFalse(SystemSecurityProbe.versionMeetsMinimum(current: "26.2", minimum: "26.3"))
        XCTAssertTrue(SystemSecurityProbe.versionMeetsMinimum(current: "27.0", minimum: "26.3"))
    }

    func testStatusFromOutput() {
        XCTAssertEqual(SystemSecurityProbe.statusFromOutput("Firewall is enabled.", expectedTokens: ["enabled"]), .secure)
        XCTAssertEqual(SystemSecurityProbe.statusFromOutput("assessments disabled", expectedTokens: ["enabled"]), .warning)
    }

    func testDefaultBaselineVersion() {
        let baseline = SystemSecurityProbe.defaultBaselineVersion()
        XCTAssertFalse(baseline.isEmpty)
    }
}
