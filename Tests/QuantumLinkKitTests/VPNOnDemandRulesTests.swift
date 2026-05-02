import Foundation
import XCTest
@testable import QuantumLinkKit

#if canImport(NetworkExtension)
import NetworkExtension
#endif

final class VPNOnDemandRulesTests: XCTestCase {

    // MARK: Action / interface enum payload values

    func testActionPayloadValuesMatchAppleSpelling() {
        // Apple is case-sensitive on these wire strings; if any of these
        // change the resulting profile silently breaks at install time.
        XCTAssertEqual(OnDemandRuleAction.connect.payloadValue, "Connect")
        XCTAssertEqual(OnDemandRuleAction.disconnect.payloadValue, "Disconnect")
        XCTAssertEqual(OnDemandRuleAction.evaluateConnection.payloadValue, "EvaluateConnection")
        XCTAssertEqual(OnDemandRuleAction.ignore.payloadValue, "Ignore")
    }

    func testInterfaceTypePayloadValuesMatchAppleSpelling() {
        XCTAssertEqual(OnDemandInterfaceType.wifi.payloadValue, "WiFi")
        XCTAssertEqual(OnDemandInterfaceType.ethernet.payloadValue, "Ethernet")
        XCTAssertEqual(OnDemandInterfaceType.cellular.payloadValue, "Cellular")
    }

    // MARK: Plist round-trip per match type

    func testRulePlistInterfaceTypeMatch() {
        let rule = OnDemandRule(
            action: .connect,
            matches: [.interfaceType(.wifi)]
        )
        let dict = rule.toPlistDictionary()
        XCTAssertEqual(dict["Action"] as? String, "Connect")
        XCTAssertEqual(dict["InterfaceTypeMatch"] as? String, "WiFi")
    }

    func testRulePlistSSIDMatch() {
        let rule = OnDemandRule(
            action: .connect,
            matches: [.ssid(["Acme-Corp", "Acme-Guest"])]
        )
        let dict = rule.toPlistDictionary()
        XCTAssertEqual(dict["SSIDMatch"] as? [String], ["Acme-Corp", "Acme-Guest"])
    }

    func testRulePlistDNSSearchDomainMatch() {
        let rule = OnDemandRule(
            action: .evaluateConnection,
            matches: [.dnsSearchDomain(["corp.acme.com", "acme.local"])]
        )
        let dict = rule.toPlistDictionary()
        XCTAssertEqual(dict["DNSDomainMatch"] as? [String], ["corp.acme.com", "acme.local"])
    }

    func testRulePlistDNSServerAddressMatch() {
        let rule = OnDemandRule(
            action: .connect,
            matches: [.dnsServerAddress(["10.0.0.1", "10.0.0.2"])]
        )
        let dict = rule.toPlistDictionary()
        XCTAssertEqual(dict["DNSServerAddressMatch"] as? [String], ["10.0.0.1", "10.0.0.2"])
    }

    func testRulePlistURLStringProbe() {
        let rule = OnDemandRule(
            action: .connect,
            matches: [.urlStringProbe("https://captive.acme.com/probe")]
        )
        let dict = rule.toPlistDictionary()
        XCTAssertEqual(dict["URLStringProbe"] as? String, "https://captive.acme.com/probe")
    }

    func testRulePlistMixedMatchesAreFlattenedAtTopLevel() {
        // Apple's payload schema flattens — multiple match types on a
        // single rule become sibling top-level keys, not a nested
        // structure.
        let rule = OnDemandRule(
            action: .evaluateConnection,
            matches: [
                .interfaceType(.wifi),
                .ssid(["Acme-Corp"]),
                .dnsSearchDomain(["corp.acme.com"]),
            ]
        )
        let dict = rule.toPlistDictionary()
        XCTAssertEqual(dict["Action"] as? String, "EvaluateConnection")
        XCTAssertEqual(dict["InterfaceTypeMatch"] as? String, "WiFi")
        XCTAssertEqual(dict["SSIDMatch"] as? [String], ["Acme-Corp"])
        XCTAssertEqual(dict["DNSDomainMatch"] as? [String], ["corp.acme.com"])
    }

    func testRulePlistEmptyMatchesIsAlwaysMatchRule() {
        // Apple's "default" rule pattern: an action with no match
        // conditions — used as the last entry to express "anything not
        // already matched".
        let rule = OnDemandRule(action: .disconnect, matches: [])
        let dict = rule.toPlistDictionary()
        XCTAssertEqual(dict["Action"] as? String, "Disconnect")
        XCTAssertEqual(dict.count, 1, "No-match rule should only have Action key")
    }

    func testPlistArrayPreservesRuleOrder() {
        // Order matters: Apple evaluates rules in the array order and
        // first match wins.
        let rules = [
            OnDemandRule(action: .connect, matches: [.ssid(["Corp"])]),
            OnDemandRule(action: .disconnect, matches: []),
        ]
        let array = OnDemandRule.plistArray(from: rules)
        XCTAssertEqual(array.count, 2)
        XCTAssertEqual(array[0]["Action"] as? String, "Connect")
        XCTAssertEqual(array[1]["Action"] as? String, "Disconnect")
    }

    // MARK: OnDemandPayloadFragment

    func testFragmentEmitsEnabledAndRules() {
        let fragment = OnDemandPayloadFragment(
            enabled: true,
            rules: [OnDemandRule(action: .disconnect)]
        )
        let dict = fragment.plistKeys()
        XCTAssertEqual(dict["OnDemandEnabled"] as? Int, 1)
        let rules = dict["OnDemandRules"] as? [[String: Any]]
        XCTAssertEqual(rules?.count, 1)
        XCTAssertEqual(rules?.first?["Action"] as? String, "Disconnect")
    }

    func testFragmentDisabledFlagSerializesAsZero() {
        let fragment = OnDemandPayloadFragment(enabled: false, rules: [])
        let dict = fragment.plistKeys()
        XCTAssertEqual(dict["OnDemandEnabled"] as? Int, 0)
    }

    // MARK: NEOnDemandRule conversion

    #if canImport(NetworkExtension)

    func testActionMapsToCorrectNEOnDemandRuleSubclass() {
        let connect = OnDemandRule(action: .connect).toNEOnDemandRule()
        XCTAssertTrue(connect is NEOnDemandRuleConnect, "Got \(type(of: connect))")

        let disconnect = OnDemandRule(action: .disconnect).toNEOnDemandRule()
        XCTAssertTrue(disconnect is NEOnDemandRuleDisconnect, "Got \(type(of: disconnect))")

        let evaluate = OnDemandRule(action: .evaluateConnection).toNEOnDemandRule()
        XCTAssertTrue(
            evaluate is NEOnDemandRuleEvaluateConnection,
            "Got \(type(of: evaluate))"
        )

        let ignore = OnDemandRule(action: .ignore).toNEOnDemandRule()
        XCTAssertTrue(ignore is NEOnDemandRuleIgnore, "Got \(type(of: ignore))")
    }

    func testWifiInterfaceMatchPropagatesToNEOnDemandRule() {
        let rule = OnDemandRule(
            action: .connect,
            matches: [.interfaceType(.wifi)]
        ).toNEOnDemandRule()
        XCTAssertEqual(rule.interfaceTypeMatch, .wiFi)
    }

    func testEthernetInterfaceMatchPropagatesToNEOnDemandRule() {
        let rule = OnDemandRule(
            action: .connect,
            matches: [.interfaceType(.ethernet)]
        ).toNEOnDemandRule()
        XCTAssertEqual(rule.interfaceTypeMatch, .ethernet)
    }

    func testCellularInterfaceFallsBackToAnyOnMacOS() {
        // On macOS NEOnDemandRuleInterfaceType has no `.cellular`; the
        // converter degrades to `.any` rather than crashing. The plist
        // form still emits "Cellular" (covered by other tests).
        let rule = OnDemandRule(
            action: .connect,
            matches: [.interfaceType(.cellular)]
        ).toNEOnDemandRule()
        #if os(macOS)
        XCTAssertEqual(rule.interfaceTypeMatch, .any)
        #else
        XCTAssertEqual(rule.interfaceTypeMatch, .cellular)
        #endif
    }

    func testSSIDMatchPropagatesToNEOnDemandRule() {
        let rule = OnDemandRule(
            action: .connect,
            matches: [.ssid(["Corp", "Guest"])]
        ).toNEOnDemandRule()
        XCTAssertEqual(rule.ssidMatch, ["Corp", "Guest"])
    }

    func testDNSSearchDomainPropagatesToNEOnDemandRule() {
        let rule = OnDemandRule(
            action: .evaluateConnection,
            matches: [.dnsSearchDomain(["corp.acme.com"])]
        ).toNEOnDemandRule()
        XCTAssertEqual(rule.dnsSearchDomainMatch, ["corp.acme.com"])
    }

    func testDNSServerAddressPropagatesToNEOnDemandRule() {
        let rule = OnDemandRule(
            action: .connect,
            matches: [.dnsServerAddress(["10.0.0.1"])]
        ).toNEOnDemandRule()
        XCTAssertEqual(rule.dnsServerAddressMatch, ["10.0.0.1"])
    }

    func testURLStringProbePropagatesToNEOnDemandRule() {
        let urlString = "https://captive.acme.com/probe"
        let rule = OnDemandRule(
            action: .connect,
            matches: [.urlStringProbe(urlString)]
        ).toNEOnDemandRule()
        XCTAssertEqual(rule.probeURL, URL(string: urlString))
    }

    func testNoMatchesProducesUnconstrainedRule() {
        let rule = OnDemandRule(action: .disconnect).toNEOnDemandRule()
        XCTAssertEqual(rule.interfaceTypeMatch, .any)
        XCTAssertNil(rule.ssidMatch)
        XCTAssertNil(rule.dnsSearchDomainMatch)
        XCTAssertNil(rule.dnsServerAddressMatch)
        XCTAssertNil(rule.probeURL)
    }

    #endif
}
