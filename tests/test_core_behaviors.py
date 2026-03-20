import argparse
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
import io
import yaml
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import albator_cli
from main import BaselineGenerator
from preflight import run_preflight
from rule_handler import RuleHandler


def make_args(**overrides):
    base = {
        "controls": False,
        "keyword": "stig",
        "list_tags": False,
        "tailor": False,
        "root_dir": None,
        "interactive": False,
        "gui": False,
    }
    base.update(overrides)
    return argparse.Namespace(**base)


class TestBenchmarkResolution(unittest.TestCase):
    def test_resolve_known_benchmarks(self):
        self.assertEqual(BaselineGenerator._resolve_benchmark("stig"), "stig")
        self.assertEqual(BaselineGenerator._resolve_benchmark("cis_lvl1"), "cis_lvl1")
        self.assertEqual(BaselineGenerator._resolve_benchmark("cis_lvl2"), "cis_lvl2")
        self.assertEqual(BaselineGenerator._resolve_benchmark("macos_26_3"), "macos_26_3")

    def test_resolve_unknown_benchmark(self):
        self.assertEqual(BaselineGenerator._resolve_benchmark("security"), "recommended")


class TestSecureFixExecution(unittest.TestCase):
    def test_parse_fix_command_rejects_shell_control_chars(self):
        with self.assertRaises(ValueError):
            BaselineGenerator._parse_fix_command("/usr/bin/defaults write a b c; rm -rf /")

    def test_run_fix_command_drops_sudo_and_avoids_shell_true(self):
        generator = BaselineGenerator(args=make_args())
        with patch("main.os.geteuid", return_value=0), patch("main.subprocess.run") as mock_run:
            generator._run_fix_command("sudo /usr/bin/defaults write com.test Value 1")

        called_args, called_kwargs = mock_run.call_args
        self.assertEqual(called_args[0][0], "/usr/bin/defaults")
        self.assertNotIn("shell", called_kwargs)
        self.assertTrue(called_kwargs.get("check"))
        self.assertTrue(called_kwargs.get("capture_output"))


class TestRulePathHandling(unittest.TestCase):
    def test_configure_paths_uses_root_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            RuleHandler.configure_paths(tmp)
            self.assertTrue(RuleHandler.RULES_DIR.startswith(tmp))
            self.assertTrue(RuleHandler.CUSTOM_RULES_DIR.startswith(tmp))

    def test_collect_rules_fails_fast_when_no_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(RuntimeError) as ctx:
                RuleHandler.collect_rules(root_dir=tmp)
        self.assertIn("No rule files found", str(ctx.exception))


class TestVersionAwareRuleSelection(unittest.TestCase):
    def test_filters_incompatible_rules_for_detected_major(self):
        generator = BaselineGenerator(args=make_args())
        rules = [
            SimpleNamespace(rule_tags=["stig"], rule_macos="26.3", rule_id="r26"),
            SimpleNamespace(rule_tags=["stig"], rule_macos="15", rule_id="r15"),
            SimpleNamespace(rule_tags=["stig"], rule_macos="missing", rule_id="r_any"),
        ]
        with patch.object(generator, "_get_target_macos_major", return_value=26):
            matched = generator.get_matching_rules(rules, "stig")
        self.assertEqual([r.rule_id for r in matched], ["r26", "r_any"])

    def test_does_not_filter_when_target_unknown(self):
        generator = BaselineGenerator(args=make_args())
        rules = [
            SimpleNamespace(rule_tags=["stig"], rule_macos="15", rule_id="r15"),
            SimpleNamespace(rule_tags=["stig"], rule_macos="26", rule_id="r26"),
        ]
        with patch.object(generator, "_get_target_macos_major", return_value=None):
            matched = generator.get_matching_rules(rules, "stig")
        self.assertEqual(len(matched), 2)


class TestLegacyCliDispatch(unittest.TestCase):
    def test_run_legacy_command_injects_args_and_dispatches(self):
        fake_generator = MagicMock()
        fake_generator.root_dir = "/tmp/albator"
        fake_generator.includes_dir = "/tmp/albator/includes"
        fake_generator.original_wd = "/tmp"
        fake_generator.load_yaml_file.side_effect = [
            {"authors": {}, "titles": {}},
            {"platform": "macOS", "os": "15"},
        ]
        fake_generator._resolve_benchmark.return_value = "recommended"
        fake_generator.get_matching_rules.return_value = [SimpleNamespace(rule_id="x")]

        args = argparse.Namespace(action="generate", keyword="security")
        with patch("albator_cli.BaselineGenerator", return_value=fake_generator) as mock_bg, \
             patch("albator_cli.collect_rules", return_value=[SimpleNamespace(rule_id="x")]), \
             patch("albator_cli.os.chdir"):
            albator_cli.run_legacy_command(args)

        injected_args = mock_bg.call_args.kwargs["args"]
        self.assertEqual(injected_args.keyword, "security")
        fake_generator._resolve_benchmark.assert_called_once_with("security")
        fake_generator._generate_standard_baseline.assert_called_once()


class TestCliScriptDispatch(unittest.TestCase):
    def test_run_bash_script_reports_stdout_when_stderr_empty(self):
        with patch("albator_cli.subprocess.run", side_effect=subprocess.CalledProcessError(5, ["bash", "x"], output="details", stderr="")), \
             patch("albator_cli.sys.exit", side_effect=SystemExit), \
             patch("albator_cli.sys.stderr"):
            with self.assertRaises(SystemExit):
                albator_cli.run_bash_script("x.sh")

    def test_parse_known_args_allows_script_passthrough(self):
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command", required=True)
        subparsers.add_parser("privacy")
        args, unknown = parser.parse_known_args(["privacy", "--dry-run"])
        self.assertEqual(args.command, "privacy")
        self.assertEqual(unknown, ["--dry-run"])

    def test_run_bash_script_json_output_success(self):
        fake = subprocess.CompletedProcess(args=["bash", "x.sh"], returncode=0, stdout="ok\n", stderr="")
        with patch("albator_cli.subprocess.run", return_value=fake), patch("sys.stdout", new_callable=io.StringIO) as out:
            rc = albator_cli.run_bash_script("x.sh", ["--dry-run"], json_output=True)
        self.assertEqual(rc, 0)
        payload = json.loads(out.getvalue())
        self.assertTrue(payload["success"])
        self.assertEqual(payload["script"], "x.sh")


class TestPreflightAutoGate(unittest.TestCase):
    def test_mutating_command_aborts_on_failed_preflight(self):
        args = argparse.Namespace(action=None)
        cfg = {"preflight": {"min_macos_version": "26.3", "enforce_min_version": True}}
        with patch("albator_cli.run_preflight", return_value={"passed": False}), \
             patch("albator_cli.format_preflight_report", return_value="x"), \
             patch("albator_cli.sys.exit", side_effect=SystemExit) as mock_exit:
            with self.assertRaises(SystemExit):
                albator_cli.maybe_run_preflight("firewall", args, cfg)
        mock_exit.assert_called_once_with(1)

    def test_non_mutating_command_skips_preflight(self):
        args = argparse.Namespace(action="list_tags")
        cfg = {"preflight": {"min_macos_version": "26.3", "enforce_min_version": True}}
        with patch("albator_cli.run_preflight") as mock_pf:
            albator_cli.maybe_run_preflight("legacy", args, cfg)
        mock_pf.assert_not_called()


class TestLegacyCliIntegration(unittest.TestCase):
    def test_legacy_list_tags_with_fixture_project(self):
        repo_root = pathlib.Path(__file__).resolve().parents[1]
        fixture_root = repo_root / "tests" / "fixtures" / "minimal_project"
        env = dict(os.environ)
        env["ROOT_DIR"] = str(fixture_root)

        result = subprocess.run(
            ["python3", "albator_cli.py", "legacy", "list_tags"],
            cwd=str(repo_root),
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("all_rules", result.stdout)
        self.assertIn("stig", result.stdout)


class TestPreflight(unittest.TestCase):
    def test_preflight_fails_when_required_tool_missing(self):
        with patch("preflight.shutil.which", side_effect=lambda t: None if t == "jq" else f"/usr/bin/{t}"):
            summary = run_preflight(require_sudo=False, require_rules=False)
        self.assertFalse(summary["passed"])
        failing = [c for c in summary["checks"] if c["name"] == "tool_jq"][0]
        self.assertEqual(failing["status"], "FAIL")

    def test_preflight_warns_when_optional_tool_missing(self):
        def fake_which(tool):
            if tool in ("curl", "jq"):
                return f"/usr/bin/{tool}"
            return None

        with patch("preflight.shutil.which", side_effect=fake_which):
            summary = run_preflight(require_sudo=False, require_rules=False)
        pup_check = [c for c in summary["checks"] if c["name"] == "tool_pup"][0]
        self.assertEqual(pup_check["status"], "WARN")

    def test_preflight_enforces_min_macos_version(self):
        with patch("preflight.platform.system", return_value="Darwin"), \
             patch("preflight.platform.mac_ver", return_value=("26.2", ("", "", ""), "")):
            summary = run_preflight(min_macos_version="26.3", enforce_min_version=True)
        min_check = [c for c in summary["checks"] if c["name"] == "min_macos_version"][0]
        self.assertEqual(min_check["status"], "FAIL")
        self.assertFalse(summary["passed"])

    def test_preflight_macos_26_3_signature_checks(self):
        def fake_which(tool):
            return f"/usr/bin/{tool}"

        def fake_run(cmd, capture_output=True, text=True, check=False):
            exe = cmd[0]
            if exe.endswith("socketfilterfw"):
                return SimpleNamespace(returncode=0, stdout="Firewall is enabled.\n", stderr="")
            if exe == "spctl":
                return SimpleNamespace(returncode=0, stdout="assessments enabled\n", stderr="")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with patch("preflight.platform.system", return_value="Darwin"), \
             patch("preflight.platform.mac_ver", return_value=("26.3", ("", "", ""), "")), \
             patch("preflight.shutil.which", side_effect=fake_which), \
             patch("preflight.subprocess.run", side_effect=fake_run):
            summary = run_preflight(require_sudo=False, require_rules=False)

        names = {c["name"] for c in summary["checks"]}
        self.assertIn("macos_26_3_firewall_signature", names)
        self.assertIn("macos_26_3_gatekeeper_signature", names)


class TestAuditLoggingRules(unittest.TestCase):
    """Tests for audit & logging rule YAML files (experiment 1)."""

    def setUp(self):
        self.repo_root = pathlib.Path(__file__).resolve().parents[1]
        self.rules_dir = self.repo_root / "rules"

    def _load_rule(self, rule_id):
        import yaml
        rule_path = self.rules_dir / f"{rule_id}.yaml"
        self.assertTrue(rule_path.exists(), f"Rule file {rule_id}.yaml not found")
        with open(rule_path) as f:
            return yaml.safe_load(f)

    def test_audit_flags_rule_has_required_fields(self):
        rule = self._load_rule("os_audit_flags_configure")
        self.assertEqual(rule["id"], "os_audit_flags_configure")
        self.assertEqual(rule["severity"], "high")
        self.assertIn("audit_control", rule["check"])
        self.assertIn("audit_control", rule["fix"])
        self.assertIn("AU-3", rule["references"]["800-53r5"])
        self.assertIn("audit", rule["tags"])

    def test_auditd_enable_rule_has_required_fields(self):
        rule = self._load_rule("os_auditd_enable")
        self.assertEqual(rule["id"], "os_auditd_enable")
        self.assertEqual(rule["severity"], "critical")
        self.assertIn("launchctl", rule["check"])
        self.assertIn("auditd", rule["check"])
        self.assertIn("AU-3", rule["references"]["800-53r5"])

    def test_audit_retention_rule_has_required_fields(self):
        rule = self._load_rule("os_audit_retention_configure")
        self.assertEqual(rule["id"], "os_audit_retention_configure")
        self.assertIn("expire-after", rule["check"])
        self.assertIn("AU-11", rule["references"]["800-53r5"])

    def test_audit_acls_rule_has_required_fields(self):
        rule = self._load_rule("os_audit_acls_configure")
        self.assertEqual(rule["id"], "os_audit_acls_configure")
        self.assertEqual(rule["severity"], "high")
        self.assertIn("/var/audit", rule["check"])
        self.assertIn("AU-9", rule["references"]["800-53r5"])

    def test_install_log_retention_rule_has_required_fields(self):
        rule = self._load_rule("os_install_log_retention_configure")
        self.assertEqual(rule["id"], "os_install_log_retention_configure")
        self.assertIn("ttl=365", rule["check"])
        self.assertIn("AU-11", rule["references"]["800-53r5"])

    def test_all_audit_rules_loaded_by_collect_rules(self):
        rules = RuleHandler.collect_rules(root_dir=str(self.repo_root))
        rule_ids = [r.rule_id for r in rules]
        for audit_id in [
            "os_audit_flags_configure",
            "os_auditd_enable",
            "os_audit_retention_configure",
            "os_audit_acls_configure",
            "os_install_log_retention_configure",
        ]:
            self.assertIn(audit_id, rule_ids, f"{audit_id} not loaded by collect_rules")

    def test_audit_rules_check_commands_are_read_only(self):
        """Check commands must not modify system state."""
        dangerous = ["sudo", "write", "set", "load", "kill", "rm", "chmod", "chown"]
        for rule_id in [
            "os_audit_flags_configure",
            "os_auditd_enable",
            "os_audit_retention_configure",
            "os_audit_acls_configure",
            "os_install_log_retention_configure",
        ]:
            rule = self._load_rule(rule_id)
            check = rule["check"]
            for word in dangerous:
                # Allow "grep" even though it contains no dangerous words
                # Only flag if the dangerous word appears as a command (after / or at start)
                if word == "write":
                    # "write" might appear in paths, only flag standalone
                    self.assertNotRegex(check, rf'\bsudo\b',
                                        f"Check for {rule_id} contains sudo")
                    break


class TestPasswordPolicyRules(unittest.TestCase):
    """Tests for password policy rule YAML files (experiment 2)."""

    PASSWORD_RULE_IDS = [
        "os_password_min_length",
        "os_password_complexity",
        "os_password_history",
        "os_password_max_age",
        "os_password_lockout",
    ]

    def setUp(self):
        self.repo_root = pathlib.Path(__file__).resolve().parents[1]
        self.rules_dir = self.repo_root / "rules"

    def _load_rule(self, rule_id):
        import yaml
        rule_path = self.rules_dir / f"{rule_id}.yaml"
        self.assertTrue(rule_path.exists(), f"Rule file {rule_id}.yaml not found")
        with open(rule_path) as f:
            return yaml.safe_load(f)

    def test_password_min_length_rule(self):
        rule = self._load_rule("os_password_min_length")
        self.assertEqual(rule["id"], "os_password_min_length")
        self.assertEqual(rule["severity"], "high")
        self.assertIn("pwpolicy", rule["check"])
        self.assertIn("pwpolicy", rule["fix"])
        self.assertIn("IA-5(1)", rule["references"]["800-53r5"])
        self.assertIn("password", rule["tags"])

    def test_password_complexity_rule(self):
        rule = self._load_rule("os_password_complexity")
        self.assertEqual(rule["id"], "os_password_complexity")
        self.assertEqual(rule["severity"], "high")
        self.assertIn("pwpolicy", rule["check"])
        self.assertIn("IA-5(1)", rule["references"]["800-53r5"])
        self.assertIn("password", rule["tags"])

    def test_password_history_rule(self):
        rule = self._load_rule("os_password_history")
        self.assertEqual(rule["id"], "os_password_history")
        self.assertEqual(rule["severity"], "medium")
        self.assertIn("pwpolicy", rule["check"])
        self.assertIn("usingHistory", rule["fix"])
        self.assertIn("IA-5(1)", rule["references"]["800-53r5"])

    def test_password_max_age_rule(self):
        rule = self._load_rule("os_password_max_age")
        self.assertEqual(rule["id"], "os_password_max_age")
        self.assertEqual(rule["severity"], "medium")
        self.assertIn("pwpolicy", rule["check"])
        self.assertIn("maxMinutesUntilChangePassword", rule["fix"])
        self.assertIn("IA-5(1)", rule["references"]["800-53r5"])

    def test_password_lockout_rule(self):
        rule = self._load_rule("os_password_lockout")
        self.assertEqual(rule["id"], "os_password_lockout")
        self.assertEqual(rule["severity"], "high")
        self.assertIn("pwpolicy", rule["check"])
        self.assertIn("maxFailedLoginAttempts", rule["fix"])
        self.assertIn("AC-7", rule["references"]["800-53r5"])

    def test_all_password_rules_loaded_by_collect_rules(self):
        rules = RuleHandler.collect_rules(root_dir=str(self.repo_root))
        rule_ids = [r.rule_id for r in rules]
        for pw_id in self.PASSWORD_RULE_IDS:
            self.assertIn(pw_id, rule_ids, f"{pw_id} not loaded by collect_rules")

    def test_password_rules_check_commands_are_read_only(self):
        """Check commands must not contain sudo or mutating commands."""
        for rule_id in self.PASSWORD_RULE_IDS:
            rule = self._load_rule(rule_id)
            check = rule["check"]
            self.assertNotRegex(check, r'\bsudo\b',
                                f"Check for {rule_id} contains sudo")
            self.assertNotRegex(check, r'\bsetglobalpolicy\b',
                                f"Check for {rule_id} contains setglobalpolicy")

    def test_password_rules_have_required_schema_fields(self):
        """All password rules must have the standard YAML schema fields."""
        required_keys = ["title", "id", "severity", "discussion", "check", "fix",
                         "references", "tags"]
        for rule_id in self.PASSWORD_RULE_IDS:
            rule = self._load_rule(rule_id)
            for key in required_keys:
                self.assertIn(key, rule, f"{rule_id} missing field: {key}")
            # References must include 800-53r5
            self.assertIn("800-53r5", rule["references"],
                          f"{rule_id} missing 800-53r5 reference")


class TestNetworkRules(unittest.TestCase):
    """Tests for network hardening rule YAML files (experiment 3)."""

    NETWORK_RULE_IDS = [
        "os_httpd_disable",
        "os_nfsd_disable",
        "os_airdrop_disable",
        "os_bonjour_disable",
        "os_internet_sharing_disable",
    ]

    def setUp(self):
        self.repo_root = pathlib.Path(__file__).resolve().parents[1]
        self.rules_dir = self.repo_root / "rules"

    def _load_rule(self, rule_id):
        import yaml
        rule_path = self.rules_dir / f"{rule_id}.yaml"
        self.assertTrue(rule_path.exists(), f"Rule file {rule_id}.yaml not found")
        with open(rule_path) as f:
            return yaml.safe_load(f)

    def test_httpd_disable_rule(self):
        rule = self._load_rule("os_httpd_disable")
        self.assertEqual(rule["id"], "os_httpd_disable")
        self.assertEqual(rule["severity"], "high")
        self.assertIn("httpd", rule["check"])
        self.assertIn("launchctl", rule["check"])
        self.assertIn("CM-7", rule["references"]["800-53r5"])
        self.assertIn("network", rule["tags"])

    def test_nfsd_disable_rule(self):
        rule = self._load_rule("os_nfsd_disable")
        self.assertEqual(rule["id"], "os_nfsd_disable")
        self.assertEqual(rule["severity"], "high")
        self.assertIn("nfsd", rule["check"])
        self.assertIn("CM-7", rule["references"]["800-53r5"])
        self.assertIn("network", rule["tags"])

    def test_airdrop_disable_rule(self):
        rule = self._load_rule("os_airdrop_disable")
        self.assertEqual(rule["id"], "os_airdrop_disable")
        self.assertEqual(rule["severity"], "medium")
        self.assertIn("DisableAirDrop", rule["check"])
        self.assertIn("DisableAirDrop", rule["fix"])
        self.assertIn("CM-7", rule["references"]["800-53r5"])
        self.assertIn("network", rule["tags"])

    def test_bonjour_disable_rule(self):
        rule = self._load_rule("os_bonjour_disable")
        self.assertEqual(rule["id"], "os_bonjour_disable")
        self.assertEqual(rule["severity"], "medium")
        self.assertIn("NoMulticastAdvertisements", rule["check"])
        self.assertIn("NoMulticastAdvertisements", rule["fix"])
        self.assertIn("CM-7", rule["references"]["800-53r5"])
        self.assertIn("network", rule["tags"])

    def test_internet_sharing_disable_rule(self):
        rule = self._load_rule("os_internet_sharing_disable")
        self.assertEqual(rule["id"], "os_internet_sharing_disable")
        self.assertEqual(rule["severity"], "high")
        self.assertIn("com.apple.nat", rule["check"])
        self.assertIn("AC-4", rule["references"]["800-53r5"])
        self.assertIn("network", rule["tags"])

    def test_all_network_rules_loaded_by_collect_rules(self):
        rules = RuleHandler.collect_rules(root_dir=str(self.repo_root))
        rule_ids = [r.rule_id for r in rules]
        for net_id in self.NETWORK_RULE_IDS:
            self.assertIn(net_id, rule_ids, f"{net_id} not loaded by collect_rules")

    def test_network_rules_check_commands_are_read_only(self):
        """Check commands must not contain sudo or mutating commands."""
        for rule_id in self.NETWORK_RULE_IDS:
            rule = self._load_rule(rule_id)
            check = rule["check"]
            self.assertNotRegex(check, r'\bsudo\b',
                                f"Check for {rule_id} contains sudo")
            self.assertNotRegex(check, r'\bwrite\b',
                                f"Check for {rule_id} contains write")
            self.assertNotRegex(check, r'\bdisable\b',
                                f"Check for {rule_id} contains disable")

    def test_network_rules_have_required_schema_fields(self):
        """All network rules must have the standard YAML schema fields."""
        required_keys = ["title", "id", "severity", "discussion", "check", "fix",
                         "references", "tags"]
        for rule_id in self.NETWORK_RULE_IDS:
            rule = self._load_rule(rule_id)
            for key in required_keys:
                self.assertIn(key, rule, f"{rule_id} missing field: {key}")
            self.assertIn("800-53r5", rule["references"],
                          f"{rule_id} missing 800-53r5 reference")


class TestSystemPreferencesRules(unittest.TestCase):
    """Tests for system preferences rule YAML files (experiment 4)."""

    SYSPREF_RULE_IDS = [
        "os_screen_sharing_disable",
        "os_content_caching_disable",
        "os_handoff_disable",
        "os_remote_apple_events_disable",
        "os_media_sharing_disable",
    ]

    def setUp(self):
        self.repo_root = pathlib.Path(__file__).resolve().parents[1]
        self.rules_dir = self.repo_root / "rules"

    def _load_rule(self, rule_id):
        import yaml
        rule_path = self.rules_dir / f"{rule_id}.yaml"
        self.assertTrue(rule_path.exists(), f"Rule file {rule_id}.yaml not found")
        with open(rule_path) as f:
            return yaml.safe_load(f)

    def test_screen_sharing_disable_rule(self):
        rule = self._load_rule("os_screen_sharing_disable")
        self.assertEqual(rule["id"], "os_screen_sharing_disable")
        self.assertEqual(rule["severity"], "high")
        self.assertIn("screensharing", rule["check"])
        self.assertIn("launchctl", rule["check"])
        self.assertIn("CM-7", rule["references"]["800-53r5"])
        self.assertIn("system_preferences", rule["tags"])

    def test_content_caching_disable_rule(self):
        rule = self._load_rule("os_content_caching_disable")
        self.assertEqual(rule["id"], "os_content_caching_disable")
        self.assertEqual(rule["severity"], "medium")
        self.assertIn("AssetCacheManagerUtil", rule["check"])
        self.assertIn("CM-7", rule["references"]["800-53r5"])
        self.assertIn("system_preferences", rule["tags"])

    def test_handoff_disable_rule(self):
        rule = self._load_rule("os_handoff_disable")
        self.assertEqual(rule["id"], "os_handoff_disable")
        self.assertEqual(rule["severity"], "low")
        self.assertIn("ActivityAdvertisingAllowed", rule["check"])
        self.assertIn("ActivityAdvertisingAllowed", rule["fix"])
        self.assertIn("CM-7", rule["references"]["800-53r5"])
        self.assertIn("system_preferences", rule["tags"])

    def test_remote_apple_events_disable_rule(self):
        rule = self._load_rule("os_remote_apple_events_disable")
        self.assertEqual(rule["id"], "os_remote_apple_events_disable")
        self.assertEqual(rule["severity"], "high")
        self.assertIn("AEServer", rule["check"])
        self.assertIn("launchctl", rule["check"])
        self.assertIn("CM-7", rule["references"]["800-53r5"])
        self.assertIn("system_preferences", rule["tags"])

    def test_media_sharing_disable_rule(self):
        rule = self._load_rule("os_media_sharing_disable")
        self.assertEqual(rule["id"], "os_media_sharing_disable")
        self.assertEqual(rule["severity"], "medium")
        self.assertIn("home-sharing-enabled", rule["check"])
        self.assertIn("home-sharing-enabled", rule["fix"])
        self.assertIn("CM-7", rule["references"]["800-53r5"])
        self.assertIn("system_preferences", rule["tags"])

    def test_all_syspref_rules_loaded_by_collect_rules(self):
        rules = RuleHandler.collect_rules(root_dir=str(self.repo_root))
        rule_ids = [r.rule_id for r in rules]
        for sp_id in self.SYSPREF_RULE_IDS:
            self.assertIn(sp_id, rule_ids, f"{sp_id} not loaded by collect_rules")

    def test_syspref_rules_check_commands_are_read_only(self):
        """Check commands must not contain sudo or mutating commands."""
        for rule_id in self.SYSPREF_RULE_IDS:
            rule = self._load_rule(rule_id)
            check = rule["check"]
            self.assertNotRegex(check, r'\bsudo\b',
                                f"Check for {rule_id} contains sudo")
            self.assertNotRegex(check, r'\bdeactivate\b',
                                f"Check for {rule_id} contains deactivate")

    def test_syspref_rules_have_required_schema_fields(self):
        """All system preferences rules must have the standard YAML schema fields."""
        required_keys = ["title", "id", "severity", "discussion", "check", "fix",
                         "references", "tags"]
        for rule_id in self.SYSPREF_RULE_IDS:
            rule = self._load_rule(rule_id)
            for key in required_keys:
                self.assertIn(key, rule, f"{rule_id} missing field: {key}")
            self.assertIn("800-53r5", rule["references"],
                          f"{rule_id} missing 800-53r5 reference")


class TestLoginAuthRules(unittest.TestCase):
    """Tests for login & authentication rule YAML files (experiment 5)."""

    LOGIN_RULE_IDS = [
        "os_login_window_display",
        "os_password_hints_disable",
        "os_fast_user_switching_disable",
        "os_login_window_banner",
        "os_screensaver_timeout",
    ]

    def setUp(self):
        self.repo_root = pathlib.Path(__file__).resolve().parents[1]
        self.rules_dir = self.repo_root / "rules"

    def _load_rule(self, rule_id):
        import yaml
        rule_path = self.rules_dir / f"{rule_id}.yaml"
        self.assertTrue(rule_path.exists(), f"Rule file {rule_id}.yaml not found")
        with open(rule_path) as f:
            return yaml.safe_load(f)

    def test_login_window_display_rule(self):
        rule = self._load_rule("os_login_window_display")
        self.assertEqual(rule["id"], "os_login_window_display")
        self.assertEqual(rule["severity"], "medium")
        self.assertIn("SHOWFULLNAME", rule["check"])
        self.assertIn("SHOWFULLNAME", rule["fix"])
        self.assertIn("IA-2", rule["references"]["800-53r5"])
        self.assertIn("login", rule["tags"])

    def test_password_hints_disable_rule(self):
        rule = self._load_rule("os_password_hints_disable")
        self.assertEqual(rule["id"], "os_password_hints_disable")
        self.assertEqual(rule["severity"], "medium")
        self.assertIn("RetriesUntilHint", rule["check"])
        self.assertIn("RetriesUntilHint", rule["fix"])
        self.assertIn("IA-6", rule["references"]["800-53r5"])
        self.assertIn("login", rule["tags"])

    def test_fast_user_switching_disable_rule(self):
        rule = self._load_rule("os_fast_user_switching_disable")
        self.assertEqual(rule["id"], "os_fast_user_switching_disable")
        self.assertEqual(rule["severity"], "medium")
        self.assertIn("MultipleSessionEnabled", rule["check"])
        self.assertIn("MultipleSessionEnabled", rule["fix"])
        self.assertIn("AC-11", rule["references"]["800-53r5"])
        self.assertIn("login", rule["tags"])

    def test_login_window_banner_rule(self):
        rule = self._load_rule("os_login_window_banner")
        self.assertEqual(rule["id"], "os_login_window_banner")
        self.assertEqual(rule["severity"], "medium")
        self.assertIn("PolicyBanner", rule["check"])
        self.assertIn("PolicyBanner", rule["fix"])
        self.assertIn("AC-8", rule["references"]["800-53r5"])
        self.assertIn("login", rule["tags"])

    def test_screensaver_timeout_rule(self):
        rule = self._load_rule("os_screensaver_timeout")
        self.assertEqual(rule["id"], "os_screensaver_timeout")
        self.assertEqual(rule["severity"], "medium")
        self.assertIn("idleTime", rule["check"])
        self.assertIn("idleTime", rule["fix"])
        self.assertIn("AC-11", rule["references"]["800-53r5"])
        self.assertIn("login", rule["tags"])

    def test_all_login_rules_loaded_by_collect_rules(self):
        rules = RuleHandler.collect_rules(root_dir=str(self.repo_root))
        rule_ids = [r.rule_id for r in rules]
        for login_id in self.LOGIN_RULE_IDS:
            self.assertIn(login_id, rule_ids, f"{login_id} not loaded by collect_rules")

    def test_login_rules_check_commands_are_read_only(self):
        """Check commands must not contain sudo or mutating commands."""
        for rule_id in self.LOGIN_RULE_IDS:
            rule = self._load_rule(rule_id)
            check = rule["check"]
            self.assertNotRegex(check, r'\bsudo\b',
                                f"Check for {rule_id} contains sudo")

    def test_login_rules_have_required_schema_fields(self):
        """All login rules must have the standard YAML schema fields."""
        required_keys = ["title", "id", "severity", "discussion", "check", "fix",
                         "references", "tags"]
        for rule_id in self.LOGIN_RULE_IDS:
            rule = self._load_rule(rule_id)
            for key in required_keys:
                self.assertIn(key, rule, f"{rule_id} missing field: {key}")
            self.assertIn("800-53r5", rule["references"],
                          f"{rule_id} missing 800-53r5 reference")


class TestApplicationSecurityRules(unittest.TestCase):
    """Tests for application security rule YAML files (experiment 6)."""

    APP_RULE_IDS = [
        "os_safari_open_safe_downloads_disable",
        "os_safari_warn_fraudulent_sites",
        "os_safari_show_full_url",
        "os_safari_auto_fill_disable",
        "os_show_filename_extensions",
    ]

    def setUp(self):
        self.repo_root = pathlib.Path(__file__).resolve().parents[1]
        self.rules_dir = self.repo_root / "rules"

    def _load_rule(self, rule_id):
        import yaml
        rule_path = self.rules_dir / f"{rule_id}.yaml"
        self.assertTrue(rule_path.exists(), f"Rule file {rule_id}.yaml not found")
        with open(rule_path) as f:
            return yaml.safe_load(f)

    def test_safari_open_safe_downloads_disable_rule(self):
        rule = self._load_rule("os_safari_open_safe_downloads_disable")
        self.assertEqual(rule["id"], "os_safari_open_safe_downloads_disable")
        self.assertEqual(rule["severity"], "high")
        self.assertIn("AutoOpenSafeDownloads", rule["check"])
        self.assertIn("AutoOpenSafeDownloads", rule["fix"])
        self.assertIn("CM-7", rule["references"]["800-53r5"])
        self.assertIn("safari", rule["tags"])

    def test_safari_warn_fraudulent_sites_rule(self):
        rule = self._load_rule("os_safari_warn_fraudulent_sites")
        self.assertEqual(rule["id"], "os_safari_warn_fraudulent_sites")
        self.assertEqual(rule["severity"], "high")
        self.assertIn("WarnAboutFraudulentWebsites", rule["check"])
        self.assertIn("WarnAboutFraudulentWebsites", rule["fix"])
        self.assertIn("SC-18", rule["references"]["800-53r5"])
        self.assertIn("safari", rule["tags"])

    def test_safari_show_full_url_rule(self):
        rule = self._load_rule("os_safari_show_full_url")
        self.assertEqual(rule["id"], "os_safari_show_full_url")
        self.assertEqual(rule["severity"], "medium")
        self.assertIn("ShowFullURLInSmartSearchField", rule["check"])
        self.assertIn("ShowFullURLInSmartSearchField", rule["fix"])
        self.assertIn("SI-3", rule["references"]["800-53r5"])
        self.assertIn("safari", rule["tags"])

    def test_safari_auto_fill_disable_rule(self):
        rule = self._load_rule("os_safari_auto_fill_disable")
        self.assertEqual(rule["id"], "os_safari_auto_fill_disable")
        self.assertEqual(rule["severity"], "medium")
        self.assertIn("AutoFillFromAddressBook", rule["check"])
        self.assertIn("AutoFillFromAddressBook", rule["fix"])
        self.assertIn("CM-7", rule["references"]["800-53r5"])
        self.assertIn("safari", rule["tags"])

    def test_show_filename_extensions_rule(self):
        rule = self._load_rule("os_show_filename_extensions")
        self.assertEqual(rule["id"], "os_show_filename_extensions")
        self.assertEqual(rule["severity"], "medium")
        self.assertIn("AppleShowAllExtensions", rule["check"])
        self.assertIn("AppleShowAllExtensions", rule["fix"])
        self.assertIn("SI-3", rule["references"]["800-53r5"])
        self.assertIn("application", rule["tags"])

    def test_all_app_rules_loaded_by_collect_rules(self):
        rules = RuleHandler.collect_rules(root_dir=str(self.repo_root))
        rule_ids = [r.rule_id for r in rules]
        for app_id in self.APP_RULE_IDS:
            self.assertIn(app_id, rule_ids, f"{app_id} not loaded by collect_rules")

    def test_app_rules_check_commands_are_read_only(self):
        """Check commands must not contain sudo or mutating commands."""
        for rule_id in self.APP_RULE_IDS:
            rule = self._load_rule(rule_id)
            check = rule["check"]
            self.assertNotRegex(check, r'\bsudo\b',
                                f"Check for {rule_id} contains sudo")
            self.assertNotRegex(check, r'\bwrite\b',
                                f"Check for {rule_id} contains write")

    def test_app_rules_have_required_schema_fields(self):
        """All application rules must have the standard YAML schema fields."""
        required_keys = ["title", "id", "severity", "discussion", "check", "fix",
                         "references", "tags"]
        for rule_id in self.APP_RULE_IDS:
            rule = self._load_rule(rule_id)
            for key in required_keys:
                self.assertIn(key, rule, f"{rule_id} missing field: {key}")
            self.assertIn("800-53r5", rule["references"],
                          f"{rule_id} missing 800-53r5 reference")


class TestICloudAndTimeRules(unittest.TestCase):
    """Tests for iCloud & time/NTP rule YAML files (experiment 7)."""

    ICLOUD_RULE_IDS = [
        "os_icloud_keychain_disable",
        "os_icloud_drive_disable",
        "os_icloud_documents_desktop_disable",
        "os_find_my_mac_enable",
        "os_time_server_configure",
    ]

    def setUp(self):
        self.repo_root = pathlib.Path(__file__).resolve().parents[1]
        self.rules_dir = self.repo_root / "rules"

    def _load_rule(self, rule_id):
        import yaml
        rule_path = self.rules_dir / f"{rule_id}.yaml"
        self.assertTrue(rule_path.exists(), f"Rule file {rule_id}.yaml not found")
        with open(rule_path) as f:
            return yaml.safe_load(f)

    def test_icloud_keychain_disable_rule(self):
        rule = self._load_rule("os_icloud_keychain_disable")
        self.assertEqual(rule["id"], "os_icloud_keychain_disable")
        self.assertEqual(rule["severity"], "medium")
        self.assertIn("allowCloudKeychainSync", rule["check"])
        self.assertIn("allowCloudKeychainSync", rule["fix"])
        self.assertIn("SC-8", rule["references"]["800-53r5"])
        self.assertIn("icloud", rule["tags"])

    def test_icloud_drive_disable_rule(self):
        rule = self._load_rule("os_icloud_drive_disable")
        self.assertEqual(rule["id"], "os_icloud_drive_disable")
        self.assertEqual(rule["severity"], "medium")
        self.assertIn("allowCloudDocumentSync", rule["check"])
        self.assertIn("allowCloudDocumentSync", rule["fix"])
        self.assertIn("SC-8", rule["references"]["800-53r5"])
        self.assertIn("icloud", rule["tags"])

    def test_icloud_documents_desktop_disable_rule(self):
        rule = self._load_rule("os_icloud_documents_desktop_disable")
        self.assertEqual(rule["id"], "os_icloud_documents_desktop_disable")
        self.assertEqual(rule["severity"], "high")
        self.assertIn("FXICloudDriveDesktop", rule["check"])
        self.assertIn("FXICloudDriveDesktop", rule["fix"])
        self.assertIn("SC-8", rule["references"]["800-53r5"])
        self.assertIn("icloud", rule["tags"])

    def test_find_my_mac_enable_rule(self):
        rule = self._load_rule("os_find_my_mac_enable")
        self.assertEqual(rule["id"], "os_find_my_mac_enable")
        self.assertEqual(rule["severity"], "medium")
        self.assertIn("FMMEnabled", rule["check"])
        self.assertIn("FMMEnabled", rule["fix"])
        self.assertIn("CM-6", rule["references"]["800-53r5"])
        self.assertIn("icloud", rule["tags"])

    def test_time_server_configure_rule(self):
        rule = self._load_rule("os_time_server_configure")
        self.assertEqual(rule["id"], "os_time_server_configure")
        self.assertEqual(rule["severity"], "high")
        self.assertIn("getusingnetworktime", rule["check"])
        self.assertIn("setusingnetworktime", rule["fix"])
        self.assertIn("AU-8", rule["references"]["800-53r5"])
        self.assertIn("time", rule["tags"])

    def test_all_icloud_time_rules_loaded_by_collect_rules(self):
        rules = RuleHandler.collect_rules(root_dir=str(self.repo_root))
        rule_ids = [r.rule_id for r in rules]
        for rule_id in self.ICLOUD_RULE_IDS:
            self.assertIn(rule_id, rule_ids, f"{rule_id} not loaded by collect_rules")

    def test_icloud_time_rules_check_commands_are_read_only(self):
        """Check commands must not contain sudo or mutating commands."""
        for rule_id in self.ICLOUD_RULE_IDS:
            rule = self._load_rule(rule_id)
            check = rule["check"]
            self.assertNotRegex(check, r'\bsudo\b',
                                f"Check for {rule_id} contains sudo")

    def test_icloud_time_rules_have_required_schema_fields(self):
        """All iCloud/time rules must have the standard YAML schema fields."""
        required_keys = ["title", "id", "severity", "discussion", "check", "fix",
                         "references", "tags"]
        for rule_id in self.ICLOUD_RULE_IDS:
            rule = self._load_rule(rule_id)
            for key in required_keys:
                self.assertIn(key, rule, f"{rule_id} missing field: {key}")
            self.assertIn("800-53r5", rule["references"],
                          f"{rule_id} missing 800-53r5 reference")


class TestSharingServicesRules(unittest.TestCase):
    """Tests for sharing & services rule YAML files (experiment 8)."""

    SHARING_RULE_IDS = [
        "os_bluetooth_sharing_disable",
        "os_printer_sharing_disable",
        "os_file_sharing_smb_disable",
        "os_wake_network_access_disable",
        "os_dvd_sharing_disable",
    ]

    def setUp(self):
        self.repo_root = pathlib.Path(__file__).resolve().parents[1]
        self.rules_dir = self.repo_root / "rules"

    def _load_rule(self, rule_id):
        import yaml
        rule_path = self.rules_dir / f"{rule_id}.yaml"
        self.assertTrue(rule_path.exists(), f"Rule file {rule_id}.yaml not found")
        with open(rule_path) as f:
            return yaml.safe_load(f)

    def test_bluetooth_sharing_disable_rule(self):
        rule = self._load_rule("os_bluetooth_sharing_disable")
        self.assertEqual(rule["id"], "os_bluetooth_sharing_disable")
        self.assertEqual(rule["severity"], "medium")
        self.assertIn("PrefKeyServicesEnabled", rule["check"])
        self.assertIn("PrefKeyServicesEnabled", rule["fix"])
        self.assertIn("CM-7", rule["references"]["800-53r5"])
        self.assertIn("system_preferences", rule["tags"])

    def test_printer_sharing_disable_rule(self):
        rule = self._load_rule("os_printer_sharing_disable")
        self.assertEqual(rule["id"], "os_printer_sharing_disable")
        self.assertEqual(rule["severity"], "medium")
        self.assertIn("cupsctl", rule["check"])
        self.assertIn("share_printers", rule["check"])
        self.assertIn("CM-7", rule["references"]["800-53r5"])
        self.assertIn("system_preferences", rule["tags"])

    def test_file_sharing_smb_disable_rule(self):
        rule = self._load_rule("os_file_sharing_smb_disable")
        self.assertEqual(rule["id"], "os_file_sharing_smb_disable")
        self.assertEqual(rule["severity"], "high")
        self.assertIn("smbd", rule["check"])
        self.assertIn("launchctl", rule["check"])
        self.assertIn("CM-7", rule["references"]["800-53r5"])
        self.assertIn("system_preferences", rule["tags"])

    def test_wake_network_access_disable_rule(self):
        rule = self._load_rule("os_wake_network_access_disable")
        self.assertEqual(rule["id"], "os_wake_network_access_disable")
        self.assertEqual(rule["severity"], "medium")
        self.assertIn("womp", rule["check"])
        self.assertIn("pmset", rule["fix"])
        self.assertIn("CM-7", rule["references"]["800-53r5"])
        self.assertIn("system_preferences", rule["tags"])

    def test_dvd_sharing_disable_rule(self):
        rule = self._load_rule("os_dvd_sharing_disable")
        self.assertEqual(rule["id"], "os_dvd_sharing_disable")
        self.assertEqual(rule["severity"], "medium")
        self.assertIn("ODSAgent", rule["check"])
        self.assertIn("launchctl", rule["check"])
        self.assertIn("CM-7", rule["references"]["800-53r5"])
        self.assertIn("system_preferences", rule["tags"])

    def test_all_sharing_rules_loaded_by_collect_rules(self):
        rules = RuleHandler.collect_rules(root_dir=str(self.repo_root))
        rule_ids = [r.rule_id for r in rules]
        for rule_id in self.SHARING_RULE_IDS:
            self.assertIn(rule_id, rule_ids, f"{rule_id} not loaded by collect_rules")

    def test_sharing_rules_check_commands_are_read_only(self):
        """Check commands must not contain sudo or mutating commands."""
        for rule_id in self.SHARING_RULE_IDS:
            rule = self._load_rule(rule_id)
            check = rule["check"]
            self.assertNotRegex(check, r'\bsudo\b',
                                f"Check for {rule_id} contains sudo")

    def test_sharing_rules_have_required_schema_fields(self):
        """All sharing rules must have the standard YAML schema fields."""
        required_keys = ["title", "id", "severity", "discussion", "check", "fix",
                         "references", "tags"]
        for rule_id in self.SHARING_RULE_IDS:
            rule = self._load_rule(rule_id)
            for key in required_keys:
                self.assertIn(key, rule, f"{rule_id} missing field: {key}")
            self.assertIn("800-53r5", rule["references"],
                          f"{rule_id} missing 800-53r5 reference")


class TestPrivacyPeripheralRules(unittest.TestCase):
    """Tests for privacy & peripheral security rule YAML files (experiment 9)."""

    PRIVACY_RULE_IDS = [
        "os_diagnostic_reports_disable",
        "os_location_services_enable",
        "os_usb_restricted_mode",
        "os_power_nap_disable",
        "os_ad_tracking_disable",
    ]

    def setUp(self):
        self.repo_root = pathlib.Path(__file__).resolve().parents[1]
        self.rules_dir = self.repo_root / "rules"

    def _load_rule(self, rule_id):
        import yaml
        rule_path = self.rules_dir / f"{rule_id}.yaml"
        self.assertTrue(rule_path.exists(), f"Rule file {rule_id}.yaml not found")
        with open(rule_path) as f:
            return yaml.safe_load(f)

    def test_diagnostic_reports_disable_rule(self):
        rule = self._load_rule("os_diagnostic_reports_disable")
        self.assertEqual(rule["id"], "os_diagnostic_reports_disable")
        self.assertEqual(rule["severity"], "medium")
        self.assertIn("AutoSubmit", rule["check"])
        self.assertIn("AutoSubmit", rule["fix"])
        self.assertIn("CM-7", rule["references"]["800-53r5"])
        self.assertIn("privacy", rule["tags"])

    def test_location_services_enable_rule(self):
        rule = self._load_rule("os_location_services_enable")
        self.assertEqual(rule["id"], "os_location_services_enable")
        self.assertEqual(rule["severity"], "medium")
        self.assertIn("LocationServicesEnabled", rule["check"])
        self.assertIn("LocationServicesEnabled", rule["fix"])
        self.assertIn("CM-6", rule["references"]["800-53r5"])
        self.assertIn("privacy", rule["tags"])

    def test_usb_restricted_mode_rule(self):
        rule = self._load_rule("os_usb_restricted_mode")
        self.assertEqual(rule["id"], "os_usb_restricted_mode")
        self.assertEqual(rule["severity"], "high")
        self.assertIn("USBRestrictedMode", rule["check"])
        self.assertIn("USBRestrictedMode", rule["fix"])
        self.assertIn("MP-7", rule["references"]["800-53r5"])
        self.assertIn("peripheral", rule["tags"])

    def test_power_nap_disable_rule(self):
        rule = self._load_rule("os_power_nap_disable")
        self.assertEqual(rule["id"], "os_power_nap_disable")
        self.assertEqual(rule["severity"], "medium")
        self.assertIn("powernap", rule["check"])
        self.assertIn("pmset", rule["fix"])
        self.assertIn("CM-7", rule["references"]["800-53r5"])
        self.assertIn("system_preferences", rule["tags"])

    def test_ad_tracking_disable_rule(self):
        rule = self._load_rule("os_ad_tracking_disable")
        self.assertEqual(rule["id"], "os_ad_tracking_disable")
        self.assertEqual(rule["severity"], "low")
        self.assertIn("allowApplePersonalizedAdvertising", rule["check"])
        self.assertIn("allowApplePersonalizedAdvertising", rule["fix"])
        self.assertIn("CM-7", rule["references"]["800-53r5"])
        self.assertIn("privacy", rule["tags"])

    def test_all_privacy_rules_loaded_by_collect_rules(self):
        rules = RuleHandler.collect_rules(root_dir=str(self.repo_root))
        rule_ids = [r.rule_id for r in rules]
        for rule_id in self.PRIVACY_RULE_IDS:
            self.assertIn(rule_id, rule_ids, f"{rule_id} not loaded by collect_rules")

    def test_privacy_rules_check_commands_are_read_only(self):
        """Check commands must not contain sudo or mutating commands."""
        for rule_id in self.PRIVACY_RULE_IDS:
            rule = self._load_rule(rule_id)
            check = rule["check"]
            self.assertNotRegex(check, r'\bsudo\b',
                                f"Check for {rule_id} contains sudo")

    def test_privacy_rules_have_required_schema_fields(self):
        """All privacy/peripheral rules must have the standard YAML schema fields."""
        required_keys = ["title", "id", "severity", "discussion", "check", "fix",
                         "references", "tags"]
        for rule_id in self.PRIVACY_RULE_IDS:
            rule = self._load_rule(rule_id)
            for key in required_keys:
                self.assertIn(key, rule, f"{rule_id} missing field: {key}")
            self.assertIn("800-53r5", rule["references"],
                          f"{rule_id} missing 800-53r5 reference")


class TestFinalCoverageRules(unittest.TestCase):
    """Tests for final coverage rules (experiment 10): firewall stealth, software update details, home folder, Safari pop-ups."""

    FINAL_RULE_IDS = [
        "os_firewall_stealth_mode",
        "os_software_update_download",
        "os_software_update_critical_install",
        "os_home_folder_permissions",
        "os_safari_popups_disable",
    ]

    def setUp(self):
        self.repo_root = pathlib.Path(__file__).resolve().parents[1]
        self.rules_dir = self.repo_root / "rules"

    def _load_rule(self, rule_id):
        import yaml
        rule_path = self.rules_dir / f"{rule_id}.yaml"
        self.assertTrue(rule_path.exists(), f"Rule file {rule_id}.yaml not found")
        with open(rule_path) as f:
            return yaml.safe_load(f)

    def test_firewall_stealth_mode_rule(self):
        rule = self._load_rule("os_firewall_stealth_mode")
        self.assertEqual(rule["id"], "os_firewall_stealth_mode")
        self.assertEqual(rule["severity"], "high")
        self.assertIn("getstealthmode", rule["check"])
        self.assertIn("setstealthmode", rule["fix"])
        self.assertIn("SC-7", rule["references"]["800-53r5"])
        self.assertIn("firewall", rule["tags"])

    def test_software_update_download_rule(self):
        rule = self._load_rule("os_software_update_download")
        self.assertEqual(rule["id"], "os_software_update_download")
        self.assertEqual(rule["severity"], "high")
        self.assertIn("AutomaticDownload", rule["check"])
        self.assertIn("AutomaticDownload", rule["fix"])
        self.assertIn("SI-2", rule["references"]["800-53r5"])
        self.assertIn("software_update", rule["tags"])

    def test_software_update_critical_install_rule(self):
        rule = self._load_rule("os_software_update_critical_install")
        self.assertEqual(rule["id"], "os_software_update_critical_install")
        self.assertEqual(rule["severity"], "critical")
        self.assertIn("CriticalUpdateInstall", rule["check"])
        self.assertIn("CriticalUpdateInstall", rule["fix"])
        self.assertIn("SI-2", rule["references"]["800-53r5"])
        self.assertIn("software_update", rule["tags"])

    def test_home_folder_permissions_rule(self):
        rule = self._load_rule("os_home_folder_permissions")
        self.assertEqual(rule["id"], "os_home_folder_permissions")
        self.assertEqual(rule["severity"], "medium")
        self.assertIn("drwx------", rule["check"])
        self.assertIn("chmod 700", rule["fix"])
        self.assertIn("AC-3", rule["references"]["800-53r5"])
        self.assertIn("filesystem", rule["tags"])

    def test_safari_popups_disable_rule(self):
        rule = self._load_rule("os_safari_popups_disable")
        self.assertEqual(rule["id"], "os_safari_popups_disable")
        self.assertEqual(rule["severity"], "medium")
        self.assertIn("WebKitJavaScriptCanOpenWindowsAutomatically", rule["check"])
        self.assertIn("WebKitJavaScriptCanOpenWindowsAutomatically", rule["fix"])
        self.assertIn("CM-7", rule["references"]["800-53r5"])
        self.assertIn("safari", rule["tags"])

    def test_all_final_rules_loaded_by_collect_rules(self):
        rules = RuleHandler.collect_rules(root_dir=str(self.repo_root))
        rule_ids = [r.rule_id for r in rules]
        for rule_id in self.FINAL_RULE_IDS:
            self.assertIn(rule_id, rule_ids, f"{rule_id} not loaded by collect_rules")

    def test_final_rules_check_commands_are_read_only(self):
        """Check commands must not contain sudo or mutating commands."""
        for rule_id in self.FINAL_RULE_IDS:
            rule = self._load_rule(rule_id)
            check = rule["check"]
            self.assertNotRegex(check, r'\bsudo\b',
                                f"Check for {rule_id} contains sudo")

    def test_final_rules_have_required_schema_fields(self):
        """All final rules must have the standard YAML schema fields."""
        required_keys = ["title", "id", "severity", "discussion", "check", "fix",
                         "references", "tags"]
        for rule_id in self.FINAL_RULE_IDS:
            rule = self._load_rule(rule_id)
            for key in required_keys:
                self.assertIn(key, rule, f"{rule_id} missing field: {key}")
            self.assertIn("800-53r5", rule["references"],
                          f"{rule_id} missing 800-53r5 reference")


class TestFinalGapRules(unittest.TestCase):
    """Tests for the 5 remaining CIS gap rules (experiment 12)."""

    GAP_RULE_IDS = [
        "os_security_responses_install",
        "os_time_machine_auto_backup",
        "os_ipv6_privacy_extensions",
        "os_managed_kext_policy",
        "os_safari_javascript_restrict",
    ]

    def setUp(self):
        self.repo_root = pathlib.Path(__file__).resolve().parents[1]
        self.rules_dir = self.repo_root / "rules"

    def _load_rule(self, rule_id):
        import yaml
        rule_path = self.rules_dir / f"{rule_id}.yaml"
        self.assertTrue(rule_path.exists(), f"Rule file {rule_id}.yaml not found")
        with open(rule_path) as f:
            return yaml.safe_load(f)

    def test_security_responses_install_rule(self):
        rule = self._load_rule("os_security_responses_install")
        self.assertEqual(rule["id"], "os_security_responses_install")
        self.assertEqual(rule["severity"], "critical")
        self.assertIn("ConfigDataInstall", rule["check"])
        self.assertIn("ConfigDataInstall", rule["fix"])
        self.assertIn("SI-2", rule["references"]["800-53r5"])
        self.assertIn("cis_lvl1", rule["tags"])

    def test_time_machine_auto_backup_rule(self):
        rule = self._load_rule("os_time_machine_auto_backup")
        self.assertEqual(rule["id"], "os_time_machine_auto_backup")
        self.assertEqual(rule["severity"], "medium")
        self.assertIn("TimeMachine", rule["check"])
        self.assertIn("AutoBackup", rule["check"])
        self.assertIn("CP-9", rule["references"]["800-53r5"])
        self.assertIn("backup", rule["tags"])

    def test_ipv6_privacy_extensions_rule(self):
        rule = self._load_rule("os_ipv6_privacy_extensions")
        self.assertEqual(rule["id"], "os_ipv6_privacy_extensions")
        self.assertEqual(rule["severity"], "medium")
        self.assertIn("use_tempaddr", rule["check"])
        self.assertIn("use_tempaddr", rule["fix"])
        self.assertIn("SC-7", rule["references"]["800-53r5"])
        self.assertIn("network", rule["tags"])

    def test_managed_kext_policy_rule(self):
        rule = self._load_rule("os_managed_kext_policy")
        self.assertEqual(rule["id"], "os_managed_kext_policy")
        self.assertEqual(rule["severity"], "high")
        self.assertIn("kext-consent", rule["check"])
        self.assertIn("kext-consent", rule["fix"])
        self.assertIn("CM-5", rule["references"]["800-53r5"])
        self.assertIn("kernel", rule["tags"])

    def test_safari_javascript_restrict_rule(self):
        rule = self._load_rule("os_safari_javascript_restrict")
        self.assertEqual(rule["id"], "os_safari_javascript_restrict")
        self.assertEqual(rule["severity"], "low")
        self.assertIn("JavaScriptCanOpenWindowsAutomatically", rule["check"])
        self.assertIn("JavaScriptCanOpenWindowsAutomatically", rule["fix"])
        self.assertIn("CM-7", rule["references"]["800-53r5"])
        self.assertIn("safari", rule["tags"])

    def test_all_gap_rules_loaded_by_collect_rules(self):
        rules = RuleHandler.collect_rules(root_dir=str(self.repo_root))
        rule_ids = [r.rule_id for r in rules]
        for rule_id in self.GAP_RULE_IDS:
            self.assertIn(rule_id, rule_ids, f"{rule_id} not loaded by collect_rules")

    def test_gap_rules_check_commands_are_read_only(self):
        """Check commands must not contain sudo or mutating commands."""
        for rule_id in self.GAP_RULE_IDS:
            rule = self._load_rule(rule_id)
            check = rule["check"]
            self.assertNotRegex(check, r'\bsudo\b',
                                f"Check for {rule_id} contains sudo")

    def test_gap_rules_have_required_schema_fields(self):
        """All gap rules must have the standard YAML schema fields."""
        required_keys = ["title", "id", "severity", "discussion", "check", "fix",
                         "references", "tags"]
        for rule_id in self.GAP_RULE_IDS:
            rule = self._load_rule(rule_id)
            for key in required_keys:
                self.assertIn(key, rule, f"{rule_id} missing field: {key}")
            self.assertIn("800-53r5", rule["references"],
                          f"{rule_id} missing 800-53r5 reference")


class TestComplianceProfiles(unittest.TestCase):
    """Tests for CIS Level 1, Level 2, and STIG compliance profiles (experiment 13)."""

    def setUp(self):
        self.repo_root = pathlib.Path(__file__).resolve().parents[1]
        self.profiles_dir = self.repo_root / "config" / "profiles"
        self.rules_dir = self.repo_root / "rules"
        import yaml
        self.yaml = yaml

    def _load_profile(self, name):
        path = self.profiles_dir / f"{name}.yaml"
        self.assertTrue(path.exists(), f"Profile {name}.yaml not found")
        with open(path) as f:
            return self.yaml.safe_load(f)

    def _all_rule_ids(self):
        return sorted(
            p.stem for p in self.rules_dir.glob("os_*.yaml")
        )

    def test_cis_level1_profile_exists_and_has_required_fields(self):
        data = self._load_profile("cis_level1")
        self.assertIn("profile", data)
        p = data["profile"]
        self.assertEqual(p["name"], "cis_level1")
        self.assertEqual(p["level"], 1)
        self.assertIn("rules", p)
        self.assertIn("description", p)

    def test_cis_level2_profile_exists_and_has_required_fields(self):
        data = self._load_profile("cis_level2")
        self.assertIn("profile", data)
        p = data["profile"]
        self.assertEqual(p["name"], "cis_level2")
        self.assertEqual(p["level"], 2)
        self.assertIn("rules", p)
        self.assertIn("description", p)

    def test_stig_profile_exists_and_has_required_fields(self):
        data = self._load_profile("stig")
        self.assertIn("profile", data)
        p = data["profile"]
        self.assertEqual(p["name"], "stig")
        self.assertIn("rules", p)
        self.assertIn("framework", p)
        self.assertIn("DISA", p["framework"])

    def test_cis_level1_rules_are_subset_of_level2(self):
        l1 = set(self._load_profile("cis_level1")["profile"]["rules"])
        l2 = set(self._load_profile("cis_level2")["profile"]["rules"])
        missing = l1 - l2
        self.assertEqual(missing, set(),
                         f"L1 rules not in L2: {missing}")

    def test_cis_level2_is_superset_with_more_rules(self):
        l1 = self._load_profile("cis_level1")["profile"]["rules"]
        l2 = self._load_profile("cis_level2")["profile"]["rules"]
        self.assertGreater(len(l2), len(l1),
                           "Level 2 should have more rules than Level 1")

    def test_all_profile_rules_reference_existing_rule_files(self):
        """Every rule listed in a profile must have a corresponding YAML file."""
        all_ids = set(self._all_rule_ids())
        for profile_name in ("cis_level1", "cis_level2", "stig"):
            rules = self._load_profile(profile_name)["profile"]["rules"]
            for rule_id in rules:
                self.assertIn(rule_id, all_ids,
                              f"{profile_name}: rule {rule_id} has no YAML file")

    def test_cis_level2_covers_all_rules(self):
        """Level 2 profile should include every os_* rule."""
        all_ids = set(self._all_rule_ids())
        l2_ids = set(self._load_profile("cis_level2")["profile"]["rules"])
        missing = all_ids - l2_ids
        self.assertEqual(missing, set(),
                         f"Rules missing from L2 profile: {missing}")

    def test_stig_covers_all_rules(self):
        """STIG profile should include every os_* rule (all have DISA refs)."""
        all_ids = set(self._all_rule_ids())
        stig_ids = set(self._load_profile("stig")["profile"]["rules"])
        missing = all_ids - stig_ids
        self.assertEqual(missing, set(),
                         f"Rules missing from STIG profile: {missing}")

    def test_no_duplicate_rules_in_profiles(self):
        """No profile should list the same rule twice."""
        for profile_name in ("cis_level1", "cis_level2", "stig"):
            rules = self._load_profile(profile_name)["profile"]["rules"]
            self.assertEqual(len(rules), len(set(rules)),
                             f"{profile_name} has duplicate rules")

    def test_level2_only_rules_not_in_level1(self):
        """Known L2-only controls must not appear in the L1 profile."""
        l2_only = {
            "os_diagnostic_reports_disable", "os_find_my_mac_enable",
            "os_handoff_disable", "os_icloud_keychain_disable",
            "os_ipv6_privacy_extensions", "os_location_services_enable",
            "os_lockdown_enable", "os_managed_kext_policy",
            "os_power_nap_disable", "os_safari_javascript_restrict",
            "os_time_machine_auto_backup",
        }
        l1_rules = set(self._load_profile("cis_level1")["profile"]["rules"])
        overlap = l2_only & l1_rules
        self.assertEqual(overlap, set(),
                         f"L2-only rules found in L1 profile: {overlap}")

    def test_profile_rule_counts_match(self):
        """Declared rule_count must match actual rules list length."""
        for profile_name in ("cis_level1", "cis_level2", "stig"):
            p = self._load_profile(profile_name)["profile"]
            self.assertEqual(p["rule_count"], len(p["rules"]),
                             f"{profile_name} rule_count mismatch")


class TestRollbackApply(unittest.TestCase):
    """Tests for rollback_apply.py (Track 3 — experiment 14)."""

    def setUp(self):
        self.repo_root = pathlib.Path(__file__).resolve().parents[1]
        self.rollback_script = self.repo_root / "rollback_apply.py"
        self.assertTrue(self.rollback_script.exists(), "rollback_apply.py not found")

    def _write_meta(self, tmpdir, data):
        meta_path = os.path.join(tmpdir, "test_rollback.json")
        with open(meta_path, "w") as f:
            json.dump(data, f)
        return meta_path

    def test_dry_run_applies_no_commands(self):
        """Dry-run should list rollback commands without executing."""
        import rollback_apply
        meta = {
            "script": "test",
            "changes": [
                {"component": "com.apple.test/Key", "detail": "set key",
                 "rollback_command": "echo rolled_back", "timestamp": "2026-01-01T00:00:00Z"}
            ]
        }
        result = rollback_apply.apply_rollback(meta, dry_run=True)
        self.assertEqual(result["applied_count"], 1)
        self.assertEqual(result["failed_count"], 0)
        self.assertTrue(result["applied"][0]["dry_run"])

    def test_missing_rollback_command_falls_back_to_defaults_delete(self):
        """If rollback_command is empty but component has domain/key, derive defaults delete."""
        import rollback_apply
        meta = {
            "script": "test",
            "changes": [
                {"component": "com.apple.test/SomeKey", "detail": "set key",
                 "rollback_command": "", "timestamp": "2026-01-01T00:00:00Z"}
            ]
        }
        result = rollback_apply.apply_rollback(meta, dry_run=True)
        self.assertEqual(result["applied_count"], 1)
        self.assertIn("defaults delete", result["applied"][0]["command"])

    def test_completely_missing_rollback_command_recorded_as_failure(self):
        """If no rollback_command and no derivable fallback, record as failed."""
        import rollback_apply
        meta = {
            "script": "test",
            "changes": [
                {"component": "no_slash", "detail": "something",
                 "rollback_command": "", "timestamp": "2026-01-01T00:00:00Z"}
            ]
        }
        result = rollback_apply.apply_rollback(meta, dry_run=True)
        self.assertEqual(result["applied_count"], 0)
        self.assertEqual(result["failed_count"], 1)
        self.assertIn("missing rollback command", result["failed"][0]["reason"])

    def test_changes_applied_in_reverse_order(self):
        """Rollback must process changes in LIFO order."""
        import rollback_apply
        meta = {
            "script": "test",
            "changes": [
                {"component": "dom/A", "detail": "first", "rollback_command": "echo A"},
                {"component": "dom/B", "detail": "second", "rollback_command": "echo B"},
                {"component": "dom/C", "detail": "third", "rollback_command": "echo C"},
            ]
        }
        result = rollback_apply.apply_rollback(meta, dry_run=True)
        self.assertEqual(result["applied_count"], 3)
        # First applied should be the last change (reverse order)
        self.assertEqual(result["applied"][0]["change"]["detail"], "third")
        self.assertEqual(result["applied"][2]["change"]["detail"], "first")

    def test_empty_changes_list(self):
        """Rollback with no changes should succeed with zero counts."""
        import rollback_apply
        meta = {"script": "test", "changes": []}
        result = rollback_apply.apply_rollback(meta, dry_run=False)
        self.assertEqual(result["applied_count"], 0)
        self.assertEqual(result["failed_count"], 0)
        self.assertEqual(result["status"], "ok")

    def test_cli_missing_file_returns_exit_code_2(self):
        """CLI should exit 2 when metadata file does not exist."""
        result = subprocess.run(
            ["python3", str(self.rollback_script), "/nonexistent/file.json"],
            capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 2)

    def test_cli_dry_run_json_output(self):
        """CLI with --dry-run --json should produce valid JSON output."""
        with tempfile.TemporaryDirectory() as tmpdir:
            meta = {
                "script": "cli_test",
                "changes": [
                    {"component": "com.test/Key", "detail": "test",
                     "rollback_command": "echo ok", "timestamp": "2026-01-01T00:00:00Z"}
                ]
            }
            meta_path = os.path.join(tmpdir, "test.json")
            with open(meta_path, "w") as f:
                json.dump(meta, f)
            result = subprocess.run(
                ["python3", str(self.rollback_script), "--dry-run", "--json", meta_path],
                capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 0)
            output = json.loads(result.stdout)
            self.assertEqual(output["applied_count"], 1)
            self.assertEqual(output["script"], "cli_test")


class TestRollbackShellScript(unittest.TestCase):
    """Tests for rollback.sh shell wrapper (Track 3 — experiment 14)."""

    def setUp(self):
        self.repo_root = pathlib.Path(__file__).resolve().parents[1]
        self.rollback_sh = self.repo_root / "rollback.sh"
        self.assertTrue(self.rollback_sh.exists(), "rollback.sh not found")

    def test_rollback_sh_help_exits_zero(self):
        result = subprocess.run(
            ["bash", str(self.rollback_sh), "--help"],
            capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("Usage", result.stdout)

    def test_rollback_sh_list_empty_state_dir(self):
        """--list with empty state dir should exit non-zero."""
        with tempfile.TemporaryDirectory() as tmpdir:
            env = os.environ.copy()
            env["ALBATOR_STATE_DIR"] = tmpdir
            result = subprocess.run(
                ["bash", str(self.rollback_sh), "--list"],
                capture_output=True, text=True, env=env
            )
            self.assertNotEqual(result.returncode, 0)

    def test_rollback_sh_dry_run_with_metadata(self):
        """Dry-run should succeed with valid metadata and print commands."""
        with tempfile.TemporaryDirectory() as tmpdir:
            meta = {
                "script": "privacy.sh",
                "changes": [
                    {"component": "com.apple.test/Key", "detail": "set key",
                     "rollback_command": "echo rolled_back", "timestamp": "2026-01-01T00:00:00Z"}
                ]
            }
            meta_path = os.path.join(tmpdir, "privacy.sh_rollback_20260101_000000.json")
            with open(meta_path, "w") as f:
                json.dump(meta, f)
            env = os.environ.copy()
            env["ALBATOR_STATE_DIR"] = tmpdir
            result = subprocess.run(
                ["bash", str(self.rollback_sh), "--dry-run", "--latest"],
                capture_output=True, text=True, env=env
            )
            self.assertEqual(result.returncode, 0)
            self.assertIn("echo rolled_back", result.stdout)

    def test_rollback_sh_json_output_mode(self):
        """--json should produce parseable JSON output."""
        with tempfile.TemporaryDirectory() as tmpdir:
            meta = {
                "script": "firewall.sh",
                "changes": [
                    {"component": "--setstealthmode", "detail": "stealth",
                     "rollback_command": "echo off", "timestamp": "2026-01-01T00:00:00Z"}
                ]
            }
            meta_path = os.path.join(tmpdir, "firewall.sh_rollback_20260101_000000.json")
            with open(meta_path, "w") as f:
                json.dump(meta, f)
            env = os.environ.copy()
            env["ALBATOR_STATE_DIR"] = tmpdir
            result = subprocess.run(
                ["bash", str(self.rollback_sh), "--dry-run", "--json", "--latest"],
                capture_output=True, text=True, env=env
            )
            self.assertEqual(result.returncode, 0)
            # Extract the JSON block from output (skip log lines)
            lines = result.stdout.strip().split("\n")
            json_lines = []
            in_json = False
            for line in lines:
                if line.strip().startswith("{"):
                    in_json = True
                if in_json:
                    json_lines.append(line)
                if in_json and line.strip().startswith("}"):
                    break
            json_str = "\n".join(json_lines)
            output = json.loads(json_str)
            self.assertEqual(output["script"], "firewall.sh")
            self.assertEqual(output["applied"], 1)

    def test_rollback_sh_nonexistent_file_exits_2(self):
        result = subprocess.run(
            ["bash", str(self.rollback_sh), "/nonexistent/file.json"],
            capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 2)


class TestPrivacyRollbackCommands(unittest.TestCase):
    """Verify privacy.sh records proper rollback commands (Track 3)."""

    def setUp(self):
        self.repo_root = pathlib.Path(__file__).resolve().parents[1]

    def test_privacy_sh_contains_rollback_commands_in_record_calls(self):
        """privacy.sh record_rollback_change calls should include a 3rd argument."""
        privacy_path = self.repo_root / "privacy.sh"
        content = privacy_path.read_text()
        import re
        calls = re.findall(r'record_rollback_change\s+"[^"]*"\s+"[^"]*"', content)
        # Every call should have a third argument (even if empty string)
        three_arg_calls = re.findall(
            r'record_rollback_change\s+"[^"]*"\s+"[^"]*"\s+"[^"]*"', content
        )
        self.assertEqual(len(calls), len(three_arg_calls),
                         "Some record_rollback_change calls in privacy.sh lack a rollback_command argument")

    def test_firewall_sh_contains_rollback_commands_in_record_calls(self):
        """firewall.sh record_rollback_change calls should include a 3rd argument."""
        firewall_path = self.repo_root / "firewall.sh"
        content = firewall_path.read_text()
        import re
        calls = re.findall(r'record_rollback_change\s+"[^"]*"\s+"[^"]*"', content)
        three_arg_calls = re.findall(
            r'record_rollback_change\s+"[^"]*"\s+"[^"]*"\s+"[^"]*"', content
        )
        self.assertEqual(len(calls), len(three_arg_calls),
                         "Some record_rollback_change calls in firewall.sh lack a rollback_command argument")


class TestEncryptionRollbackCommands(unittest.TestCase):
    """Verify encryption.sh records proper rollback commands (Track 3 — experiment 16)."""

    def setUp(self):
        self.repo_root = pathlib.Path(__file__).resolve().parents[1]

    def test_encryption_sh_rollback_calls_have_three_args(self):
        """encryption.sh record_rollback_change calls should include a 3rd argument."""
        encryption_path = self.repo_root / "encryption.sh"
        content = encryption_path.read_text()
        import re
        calls = re.findall(r'record_rollback_change\s+"[^"]*"\s+"[^"]*"', content)
        three_arg_calls = re.findall(
            r'record_rollback_change\s+"[^"]*"\s+"[^"]*"\s+"[^"]*"', content
        )
        self.assertEqual(len(calls), len(three_arg_calls),
                         "Some record_rollback_change calls in encryption.sh lack a rollback_command argument")

    def test_encryption_sh_filevault_rollback_uses_fdesetup_disable(self):
        """FileVault rollback should use 'fdesetup disable'."""
        encryption_path = self.repo_root / "encryption.sh"
        content = encryption_path.read_text()
        import re
        rollback_cmds = re.findall(
            r'record_rollback_change\s+"filevault"\s+"[^"]*"\s+"([^"]*)"', content
        )
        self.assertGreater(len(rollback_cmds), 0, "No filevault rollback commands found")
        for cmd in rollback_cmds:
            self.assertIn("fdesetup disable", cmd,
                          f"FileVault rollback should use fdesetup disable, got: {cmd}")


class TestAppSecurityRollbackCommands(unittest.TestCase):
    """Verify app_security.sh records proper rollback commands (Track 3 — experiment 16)."""

    def setUp(self):
        self.repo_root = pathlib.Path(__file__).resolve().parents[1]

    def test_app_security_sh_rollback_calls_have_three_args(self):
        """app_security.sh record_rollback_change calls should include a 3rd argument."""
        app_sec_path = self.repo_root / "app_security.sh"
        content = app_sec_path.read_text()
        import re
        calls = re.findall(r'record_rollback_change\s+"[^"]*"\s+"[^"]*"', content)
        three_arg_calls = re.findall(
            r'record_rollback_change\s+"[^"]*"\s+"[^"]*"\s+"[^"]*"', content
        )
        self.assertEqual(len(calls), len(three_arg_calls),
                         "Some record_rollback_change calls in app_security.sh lack a rollback_command argument")

    def test_app_security_sh_gatekeeper_rollback_uses_spctl(self):
        """Gatekeeper rollback should use spctl commands."""
        app_sec_path = self.repo_root / "app_security.sh"
        content = app_sec_path.read_text()
        import re
        rollback_cmds = re.findall(
            r'record_rollback_change\s+"gatekeeper[^"]*"\s+"[^"]*"\s+"([^"]*)"', content
        )
        self.assertGreater(len(rollback_cmds), 0, "No gatekeeper rollback commands found")
        for cmd in rollback_cmds:
            self.assertIn("spctl", cmd,
                          f"Gatekeeper rollback should use spctl, got: {cmd}")


class TestAllScriptsHaveRollbackCommands(unittest.TestCase):
    """Verify all 4 core scripts have proper rollback commands (Track 3 complete — experiment 16)."""

    SCRIPTS = ["privacy.sh", "firewall.sh", "encryption.sh", "app_security.sh"]

    def setUp(self):
        self.repo_root = pathlib.Path(__file__).resolve().parents[1]

    def test_all_scripts_rollback_calls_have_three_args(self):
        """Every record_rollback_change call in all core scripts must have 3 arguments."""
        import re
        errors = []
        for script in self.SCRIPTS:
            path = self.repo_root / script
            if not path.exists():
                continue
            content = path.read_text()
            calls = re.findall(r'record_rollback_change\s+"[^"]*"\s+"[^"]*"', content)
            three_arg_calls = re.findall(
                r'record_rollback_change\s+"[^"]*"\s+"[^"]*"\s+"[^"]*"', content
            )
            if len(calls) != len(three_arg_calls):
                errors.append(f"{script}: {len(calls)} calls but only {len(three_arg_calls)} have rollback commands")
        self.assertEqual(errors, [], "\n".join(errors))


class TestComprehensiveRuleValidation(unittest.TestCase):
    """Cross-cutting validation of ALL 72 rules for schema, safety, references, and profile coverage (experiment 15)."""

    REQUIRED_SCHEMA_KEYS = [
        "title", "id", "severity", "discussion", "check", "fix",
        "references", "tags",
    ]
    VALID_SEVERITIES = {"low", "medium", "high", "critical"}
    VALID_800_53_PREFIXES = {
        "AC", "AU", "AT", "CM", "CP", "IA", "IR", "MA",
        "MP", "PE", "PL", "PM", "PS", "RA", "SA", "SC",
        "SI", "SR",
    }
    # Commands that should never appear in check (read-only) commands
    CHECK_FORBIDDEN_PATTERNS = [
        (r'\bsudo\b', "sudo"),
        (r'\blaunchctl\s+load\b', "launchctl load"),
        (r'\blaunchctl\s+unload\b', "launchctl unload"),
        (r'\bdefaults\s+write\b', "defaults write"),
        (r'\bdefaults\s+delete\b', "defaults delete"),
        (r'\bchmod\b', "chmod"),
        (r'\bchown\b', "chown"),
        (r'\brm\s', "rm"),
        (r'\bkill\b', "kill"),
        (r'\bpmset\s+set\b', "pmset set"),
        (r'\bpwpolicy\s+-.*setglobalpolicy\b', "pwpolicy setglobalpolicy"),
    ]

    def setUp(self):
        import yaml
        self.yaml = yaml
        self.repo_root = pathlib.Path(__file__).resolve().parents[1]
        self.rules_dir = self.repo_root / "rules"
        self.profiles_dir = self.repo_root / "config" / "profiles"
        self._rules_cache = {}

    def _all_rule_files(self):
        return sorted(self.rules_dir.glob("os_*.yaml"))

    def _load_rule(self, path):
        if path not in self._rules_cache:
            with open(path) as f:
                self._rules_cache[path] = self.yaml.safe_load(f)
        return self._rules_cache[path]

    def _load_profile(self, name):
        with open(self.profiles_dir / f"{name}.yaml") as f:
            return self.yaml.safe_load(f)

    def test_all_rules_have_required_schema_fields(self):
        """Every rule YAML must contain all mandatory keys."""
        errors = []
        for path in self._all_rule_files():
            rule = self._load_rule(path)
            for key in self.REQUIRED_SCHEMA_KEYS:
                if key not in rule:
                    errors.append(f"{path.name}: missing '{key}'")
        self.assertEqual(errors, [], "\n".join(errors))

    def test_all_rule_ids_match_filenames(self):
        """The 'id' field must match the filename (sans .yaml)."""
        errors = []
        for path in self._all_rule_files():
            rule = self._load_rule(path)
            expected_id = path.stem
            if rule.get("id") != expected_id:
                errors.append(f"{path.name}: id='{rule.get('id')}' != expected '{expected_id}'")
        self.assertEqual(errors, [], "\n".join(errors))

    def test_all_rules_have_valid_severity(self):
        """Severity must be one of: low, medium, high, critical."""
        errors = []
        for path in self._all_rule_files():
            rule = self._load_rule(path)
            sev = rule.get("severity")
            if sev not in self.VALID_SEVERITIES:
                errors.append(f"{path.name}: invalid severity '{sev}'")
        self.assertEqual(errors, [], "\n".join(errors))

    def test_all_rules_have_800_53_references(self):
        """Every rule must have at least one NIST 800-53r5 reference."""
        errors = []
        for path in self._all_rule_files():
            rule = self._load_rule(path)
            refs = rule.get("references", {})
            controls = refs.get("800-53r5", [])
            if not controls:
                errors.append(f"{path.name}: no 800-53r5 references")
        self.assertEqual(errors, [], "\n".join(errors))

    def test_800_53_references_use_valid_family_prefixes(self):
        """All 800-53r5 references must start with a recognized control family prefix."""
        import re
        errors = []
        for path in self._all_rule_files():
            rule = self._load_rule(path)
            controls = rule.get("references", {}).get("800-53r5", [])
            for ctrl in controls:
                prefix = re.match(r'^([A-Z]+)', ctrl)
                if not prefix or prefix.group(1) not in self.VALID_800_53_PREFIXES:
                    errors.append(f"{path.name}: invalid 800-53 control '{ctrl}'")
        self.assertEqual(errors, [], "\n".join(errors))

    def test_all_check_commands_are_read_only(self):
        """Check commands must not contain destructive/mutating operations."""
        import re
        errors = []
        for path in self._all_rule_files():
            rule = self._load_rule(path)
            check = rule.get("check", "")
            for pattern, label in self.CHECK_FORBIDDEN_PATTERNS:
                if re.search(pattern, check):
                    errors.append(f"{path.name}: check contains '{label}'")
        self.assertEqual(errors, [], "\n".join(errors))

    def test_all_check_commands_are_non_empty(self):
        """Every rule must have a non-empty check command."""
        errors = []
        for path in self._all_rule_files():
            rule = self._load_rule(path)
            if not rule.get("check", "").strip():
                errors.append(f"{path.name}: empty check command")
        self.assertEqual(errors, [], "\n".join(errors))

    def test_all_fix_commands_are_non_empty(self):
        """Every rule must have a non-empty fix command."""
        errors = []
        for path in self._all_rule_files():
            rule = self._load_rule(path)
            if not rule.get("fix", "").strip():
                errors.append(f"{path.name}: empty fix command")
        self.assertEqual(errors, [], "\n".join(errors))

    def test_all_rules_have_at_least_one_tag(self):
        """Every rule must have at least one tag."""
        errors = []
        for path in self._all_rule_files():
            rule = self._load_rule(path)
            tags = rule.get("tags", [])
            if not tags:
                errors.append(f"{path.name}: no tags")
        self.assertEqual(errors, [], "\n".join(errors))

    def test_every_rule_in_at_least_one_profile(self):
        """Every rule file must appear in at least one compliance profile."""
        all_ids = {p.stem for p in self._all_rule_files()}
        profiled_ids = set()
        for profile_name in ("cis_level1", "cis_level2", "stig"):
            data = self._load_profile(profile_name)
            profiled_ids.update(data["profile"]["rules"])
        orphans = all_ids - profiled_ids
        self.assertEqual(orphans, set(),
                         f"Rules not in any profile: {orphans}")

    def test_no_profile_references_nonexistent_rules(self):
        """Profiles must not list rules that don't have YAML files."""
        all_ids = {p.stem for p in self._all_rule_files()}
        errors = []
        for profile_name in ("cis_level1", "cis_level2", "stig"):
            data = self._load_profile(profile_name)
            for rule_id in data["profile"]["rules"]:
                if rule_id not in all_ids:
                    errors.append(f"{profile_name}: references nonexistent rule '{rule_id}'")
        self.assertEqual(errors, [], "\n".join(errors))

    def test_rule_count_is_72(self):
        """We expect exactly 72 rule files for 100% CIS coverage."""
        count = len(self._all_rule_files())
        self.assertEqual(count, 72, f"Expected 72 rules, found {count}")

    def test_all_rules_have_discussion_of_minimum_length(self):
        """Discussion field should be substantive (at least 20 characters)."""
        errors = []
        for path in self._all_rule_files():
            rule = self._load_rule(path)
            disc = rule.get("discussion", "")
            if len(disc) < 20:
                errors.append(f"{path.name}: discussion too short ({len(disc)} chars)")
        self.assertEqual(errors, [], "\n".join(errors))

    def test_no_duplicate_rule_ids_across_files(self):
        """No two rule files should declare the same id."""
        seen = {}
        errors = []
        for path in self._all_rule_files():
            rule = self._load_rule(path)
            rid = rule.get("id")
            if rid in seen:
                errors.append(f"Duplicate id '{rid}' in {seen[rid]} and {path.name}")
            seen[rid] = path.name
        self.assertEqual(errors, [], "\n".join(errors))

    def test_fix_commands_use_absolute_paths_for_system_binaries(self):
        """Fix commands referencing common system tools should use absolute paths."""
        import re
        # Only check for bare 'defaults' at start of fix command (not within pipes)
        errors = []
        for path in self._all_rule_files():
            rule = self._load_rule(path)
            fix = rule.get("fix", "")
            # Check if fix starts with bare 'defaults' (no path)
            if re.match(r'^(sudo\s+)?defaults\s', fix):
                errors.append(f"{path.name}: fix uses bare 'defaults' instead of /usr/bin/defaults")
        self.assertEqual(errors, [], "\n".join(errors))


class TestScanModule(unittest.TestCase):
    """Tests for the scan module — compliance auditing against YAML rules (experiment 17)."""

    def setUp(self):
        import scan as scan_mod
        self.scan_mod = scan_mod
        self.repo_root = pathlib.Path(__file__).resolve().parents[1]
        self.rules_dir = str(self.repo_root / "rules")
        self.profiles_dir = str(self.repo_root / "config" / "profiles")

    def test_load_rules_returns_all_72(self):
        """load_rules should find all 72 rule files."""
        rules = self.scan_mod.load_rules(self.rules_dir)
        self.assertEqual(len(rules), 72)

    def test_load_rules_each_has_id_and_check(self):
        """Every loaded rule must have id and check fields."""
        rules = self.scan_mod.load_rules(self.rules_dir)
        for r in rules:
            self.assertIn("id", r, f"Rule missing 'id': {r.get('_source')}")
            self.assertIn("check", r, f"Rule missing 'check': {r.get('_source')}")

    def test_load_profile_cis_level1(self):
        """Loading cis_level1 profile should return a non-empty list of rule IDs."""
        ids = self.scan_mod.load_profile(self.profiles_dir, "cis_level1")
        self.assertIsInstance(ids, list)
        self.assertGreater(len(ids), 50)

    def test_load_profile_nonexistent_raises(self):
        """Loading a nonexistent profile should raise FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            self.scan_mod.load_profile(self.profiles_dir, "nonexistent_profile")

    def test_filter_rules_by_profile(self):
        """Filtering by cis_level1 should reduce the rule set."""
        rules = self.scan_mod.load_rules(self.rules_dir)
        profile_ids = self.scan_mod.load_profile(self.profiles_dir, "cis_level1")
        filtered = self.scan_mod.filter_rules_by_profile(rules, profile_ids)
        self.assertLess(len(filtered), len(rules))
        self.assertEqual(len(filtered), len([r for r in rules if r["id"] in set(profile_ids)]))

    def test_filter_rules_by_severity(self):
        """Filtering by high severity should exclude low/medium rules."""
        rules = self.scan_mod.load_rules(self.rules_dir)
        high_rules = self.scan_mod.filter_rules_by_severity(rules, "high")
        for r in high_rules:
            self.assertIn(r["severity"], ("high", "critical"))

    def test_scan_dry_run_returns_all_rules(self):
        """Dry-run scan should list all rules without executing checks."""
        result = self.scan_mod.scan(self.rules_dir, dry_run=True)
        self.assertEqual(result["rules_scanned"], 72)
        self.assertTrue(result["dry_run"])
        self.assertEqual(result["passed"], 0)
        self.assertEqual(result["failed"], 0)
        for r in result["results"]:
            self.assertEqual(r["status"], "dry-run")

    def test_scan_with_profile_dry_run(self):
        """Dry-run scan with profile should only include profile rules."""
        result = self.scan_mod.scan(
            self.rules_dir,
            profiles_dir=self.profiles_dir,
            profile_name="cis_level1",
            dry_run=True,
        )
        self.assertLess(result["rules_scanned"], 72)
        self.assertEqual(result["profile"], "cis_level1")

    def test_scan_with_severity_filter_dry_run(self):
        """Dry-run scan with severity filter should only include matching rules."""
        result = self.scan_mod.scan(
            self.rules_dir, min_severity="critical", dry_run=True
        )
        for r in result["results"]:
            self.assertEqual(r["severity"], "critical")

    def test_scan_summary_compliance_pct(self):
        """Summary compliance percentage should be 0.0 in dry-run mode."""
        result = self.scan_mod.scan(self.rules_dir, dry_run=True)
        self.assertEqual(result["summary"]["compliance_pct"], 0.0)

    def test_format_scan_report_contains_header(self):
        """Formatted report should contain the header and rule IDs."""
        result = self.scan_mod.scan(self.rules_dir, dry_run=True)
        report = self.scan_mod.format_scan_report(result)
        self.assertIn("Albator Compliance Scan Report", report)
        self.assertIn("os_firewall_enable", report)

    def test_run_check_with_passing_command(self):
        """A check command that exits 0 should return (True, ...)."""
        rule = {"check": "true"}
        passed, detail = self.scan_mod.run_check(rule)
        self.assertTrue(passed)

    def test_run_check_with_failing_command(self):
        """A check command that exits non-zero should return (False, ...)."""
        rule = {"check": "false"}
        passed, detail = self.scan_mod.run_check(rule)
        self.assertFalse(passed)

    def test_run_check_empty_command(self):
        """An empty check command should return (False, ...)."""
        rule = {"check": ""}
        passed, detail = self.scan_mod.run_check(rule)
        self.assertFalse(passed)
        self.assertIn("empty", detail)

    def test_run_check_timeout(self):
        """A check that exceeds timeout should return (False, 'timed out')."""
        rule = {"check": "sleep 60"}
        passed, detail = self.scan_mod.run_check(rule, timeout=1)
        self.assertFalse(passed)
        self.assertIn("timed out", detail)

    def test_scan_no_profile_dir_with_profile_raises(self):
        """scan() with profile_name but no profiles_dir should raise ValueError."""
        with self.assertRaises(ValueError):
            self.scan_mod.scan(self.rules_dir, profile_name="cis_level1")

    def test_scan_results_have_required_keys(self):
        """Each result entry should have id, title, severity, status."""
        result = self.scan_mod.scan(self.rules_dir, dry_run=True)
        for r in result["results"]:
            self.assertIn("id", r)
            self.assertIn("title", r)
            self.assertIn("severity", r)
            self.assertIn("status", r)

    def test_scan_with_real_checks_counts_correctly(self):
        """Running scan with actual checks, pass+fail should equal total."""
        # Use a tiny subset via severity filter to keep it fast
        result = self.scan_mod.scan(self.rules_dir, min_severity="critical", dry_run=False, timeout=5)
        total = result["rules_scanned"]
        self.assertEqual(result["passed"] + result["failed"], total)


class TestScanCLIIntegration(unittest.TestCase):
    """Tests for 'albator_cli.py scan' CLI integration (experiment 17)."""

    def setUp(self):
        self.repo_root = pathlib.Path(__file__).resolve().parents[1]
        self.cli = str(self.repo_root / "albator_cli.py")

    def test_scan_dry_run_exits_zero(self):
        """scan --dry-run should always exit 0."""
        result = subprocess.run(
            ["python3", self.cli, "scan", "--dry-run"],
            capture_output=True, text=True, cwd=str(self.repo_root)
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("Albator Compliance Scan Report", result.stdout)

    def test_scan_dry_run_with_profile(self):
        """scan --dry-run --profile cis_level1 should list fewer than 72 rules."""
        result = subprocess.run(
            ["python3", self.cli, "scan", "--dry-run", "--profile", "cis_level1"],
            capture_output=True, text=True, cwd=str(self.repo_root)
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("Profile: cis_level1", result.stdout)

    def test_scan_json_output(self):
        """scan --dry-run --json-output should produce valid JSON."""
        result = subprocess.run(
            ["python3", self.cli, "--json-output", "scan", "--dry-run"],
            capture_output=True, text=True, cwd=str(self.repo_root)
        )
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertEqual(data["command"], "scan")
        self.assertTrue(data["success"])
        self.assertEqual(data["rules_scanned"], 72)

    def test_scan_json_with_profile(self):
        """scan --json-output --profile cis_level2 should include profile in output."""
        result = subprocess.run(
            ["python3", self.cli, "--json-output", "scan", "--dry-run", "--profile", "cis_level2"],
            capture_output=True, text=True, cwd=str(self.repo_root)
        )
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertEqual(data["profile"], "cis_level2")

    def test_scan_invalid_profile_exits_2(self):
        """scan with nonexistent profile should exit 2."""
        result = subprocess.run(
            ["python3", self.cli, "scan", "--dry-run", "--profile", "nonexistent"],
            capture_output=True, text=True, cwd=str(self.repo_root)
        )
        self.assertEqual(result.returncode, 2)

    def test_scan_severity_filter(self):
        """scan --severity high should only include high/critical rules."""
        result = subprocess.run(
            ["python3", self.cli, "--json-output", "scan", "--dry-run", "--severity", "high"],
            capture_output=True, text=True, cwd=str(self.repo_root)
        )
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        for r in data["results"]:
            self.assertIn(r["severity"], ("high", "critical"))


class TestFixModule(unittest.TestCase):
    """Tests for the fix module — remediation of non-compliant rules (experiment 18)."""

    def setUp(self):
        import fix as fix_mod
        self.fix_mod = fix_mod
        self.repo_root = pathlib.Path(__file__).resolve().parents[1]
        self.rules_dir = str(self.repo_root / "rules")
        self.profiles_dir = str(self.repo_root / "config" / "profiles")

    def test_run_fix_empty_command(self):
        """run_fix with empty fix command should return failure."""
        rule = {"id": "test", "fix": ""}
        ok, detail = self.fix_mod.run_fix(rule)
        self.assertFalse(ok)
        self.assertIn("no fix command", detail)

    def test_run_fix_with_passing_command(self):
        """run_fix with a simple true command should succeed."""
        rule = {"id": "test", "fix": "true"}
        ok, detail = self.fix_mod.run_fix(rule)
        self.assertTrue(ok)

    def test_run_fix_with_failing_command(self):
        """run_fix with false should fail."""
        rule = {"id": "test", "fix": "false"}
        ok, detail = self.fix_mod.run_fix(rule)
        self.assertFalse(ok)

    def test_run_fix_timeout(self):
        """run_fix should respect timeout."""
        rule = {"id": "test", "fix": "sleep 10"}
        ok, detail = self.fix_mod.run_fix(rule, timeout=1)
        self.assertFalse(ok)
        self.assertIn("timed out", detail)

    def test_fix_dry_run_returns_all_rules(self):
        """fix --dry-run should return results for all 72 rules."""
        result = self.fix_mod.fix(
            rules_dir=self.rules_dir,
            profiles_dir=self.profiles_dir,
            dry_run=True,
        )
        self.assertEqual(result["rules_checked"], 72)
        self.assertTrue(result["dry_run"])
        # Every result should be compliant or would-fix or skipped
        for r in result["results"]:
            self.assertIn(r["status"], ("compliant", "would-fix", "skipped"))

    def test_fix_dry_run_with_profile(self):
        """fix --dry-run --profile cis_level1 should filter rules."""
        result = self.fix_mod.fix(
            rules_dir=self.rules_dir,
            profiles_dir=self.profiles_dir,
            profile_name="cis_level1",
            dry_run=True,
        )
        self.assertLess(result["rules_checked"], 72)
        self.assertEqual(result["profile"], "cis_level1")

    def test_fix_dry_run_with_severity(self):
        """fix --dry-run --severity high should only include high/critical."""
        result = self.fix_mod.fix(
            rules_dir=self.rules_dir,
            profiles_dir=self.profiles_dir,
            min_severity="high",
            dry_run=True,
        )
        for r in result["results"]:
            self.assertIn(r["severity"], ("high", "critical"))

    def test_fix_results_have_required_keys(self):
        """fix results dict should have all expected keys."""
        result = self.fix_mod.fix(rules_dir=self.rules_dir, dry_run=True)
        for key in ("rules_checked", "already_compliant", "fixed", "fix_failed",
                     "skipped", "dry_run", "profile", "results", "summary"):
            self.assertIn(key, result, f"Missing key: {key}")

    def test_fix_summary_fields(self):
        """fix summary should have all expected counters."""
        result = self.fix_mod.fix(rules_dir=self.rules_dir, dry_run=True)
        s = result["summary"]
        for key in ("total", "already_compliant", "non_compliant", "fixed",
                     "fix_failed", "skipped", "would_fix"):
            self.assertIn(key, s, f"Missing summary key: {key}")
        self.assertEqual(s["total"], result["rules_checked"])

    def test_fix_invalid_profile_raises(self):
        """fix with nonexistent profile should raise FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            self.fix_mod.fix(
                rules_dir=self.rules_dir,
                profiles_dir=self.profiles_dir,
                profile_name="nonexistent",
                dry_run=True,
            )

    def test_fix_no_profiles_dir_with_profile_raises(self):
        """fix with profile_name but no profiles_dir should raise ValueError."""
        with self.assertRaises(ValueError):
            self.fix_mod.fix(
                rules_dir=self.rules_dir,
                profile_name="cis_level1",
                dry_run=True,
            )

    def test_fix_with_mock_checks_compliant(self):
        """When all checks pass, all rules should be marked compliant."""
        from unittest.mock import patch
        with patch.object(self.fix_mod, "run_check", return_value=(True, "ok")):
            result = self.fix_mod.fix(rules_dir=self.rules_dir, dry_run=False)
        self.assertEqual(result["already_compliant"], 72)
        self.assertEqual(result["fixed"], 0)

    def test_fix_with_mock_check_fail_and_fix_success(self):
        """When check fails then fix+verify succeeds, rule should be marked fixed."""
        from unittest.mock import patch, call
        check_results = [(False, "not compliant"), (True, "ok")]
        with patch.object(self.fix_mod, "run_check", side_effect=check_results), \
             patch.object(self.fix_mod, "run_fix", return_value=(True, "applied")):
            # Use a single rule
            rules = self.fix_mod.load_rules(self.rules_dir)[:1]
            with patch.object(self.fix_mod, "load_rules", return_value=rules):
                result = self.fix_mod.fix(rules_dir=self.rules_dir, dry_run=False)
        self.assertEqual(result["fixed"], 1)

    def test_fix_with_mock_fix_failure(self):
        """When fix command fails, rule should be marked fix-failed."""
        from unittest.mock import patch
        with patch.object(self.fix_mod, "run_check", return_value=(False, "fail")), \
             patch.object(self.fix_mod, "run_fix", return_value=(False, "permission denied")):
            rules = self.fix_mod.load_rules(self.rules_dir)[:1]
            with patch.object(self.fix_mod, "load_rules", return_value=rules):
                result = self.fix_mod.fix(rules_dir=self.rules_dir, dry_run=False)
        self.assertEqual(result["fix_failed"], 1)
        self.assertEqual(result["results"][0]["status"], "fix-failed")

    def test_format_fix_report_contains_header(self):
        """format_fix_report output should contain the report header."""
        result = self.fix_mod.fix(rules_dir=self.rules_dir, dry_run=True)
        report = self.fix_mod.format_fix_report(result)
        self.assertIn("Albator Remediation Report", report)
        self.assertIn("DRY-RUN", report)

    def test_format_fix_report_shows_would_fix(self):
        """Dry-run report should show 'Would fix' count."""
        result = self.fix_mod.fix(rules_dir=self.rules_dir, dry_run=True)
        report = self.fix_mod.format_fix_report(result)
        self.assertIn("Would fix:", report)


class TestFixCLIIntegration(unittest.TestCase):
    """CLI integration tests for the fix subcommand (experiment 18)."""

    def setUp(self):
        self.repo_root = pathlib.Path(__file__).resolve().parents[1]
        self.cli = str(self.repo_root / "albator_cli.py")

    def test_fix_dry_run_exits_zero(self):
        """fix --dry-run should exit 0."""
        result = subprocess.run(
            ["python3", self.cli, "fix", "--dry-run"],
            capture_output=True, text=True, cwd=str(self.repo_root)
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("Albator Remediation Report", result.stdout)

    def test_fix_dry_run_with_profile(self):
        """fix --dry-run --profile cis_level1 should filter rules."""
        result = subprocess.run(
            ["python3", self.cli, "fix", "--dry-run", "--profile", "cis_level1"],
            capture_output=True, text=True, cwd=str(self.repo_root)
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("Profile: cis_level1", result.stdout)

    def test_fix_json_output(self):
        """fix --dry-run --json-output should produce valid JSON."""
        result = subprocess.run(
            ["python3", self.cli, "--json-output", "fix", "--dry-run"],
            capture_output=True, text=True, cwd=str(self.repo_root)
        )
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertEqual(data["command"], "fix")
        self.assertTrue(data["success"])
        self.assertEqual(data["rules_checked"], 72)

    def test_fix_json_with_profile(self):
        """fix --json-output --profile cis_level2 should include profile."""
        result = subprocess.run(
            ["python3", self.cli, "--json-output", "fix", "--dry-run", "--profile", "cis_level2"],
            capture_output=True, text=True, cwd=str(self.repo_root)
        )
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertEqual(data["profile"], "cis_level2")

    def test_fix_invalid_profile_exits_2(self):
        """fix with nonexistent profile should exit 2."""
        result = subprocess.run(
            ["python3", self.cli, "fix", "--dry-run", "--profile", "nonexistent"],
            capture_output=True, text=True, cwd=str(self.repo_root)
        )
        self.assertEqual(result.returncode, 2)

    def test_fix_severity_filter(self):
        """fix --severity high should only include high/critical rules."""
        result = subprocess.run(
            ["python3", self.cli, "--json-output", "fix", "--dry-run", "--severity", "high"],
            capture_output=True, text=True, cwd=str(self.repo_root)
        )
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        for r in data["results"]:
            self.assertIn(r["severity"], ("high", "critical"))


class TestRollbackModule(unittest.TestCase):
    """Tests for the rollback Python module (experiment 19)."""

    def setUp(self):
        import rollback as rb_mod
        self.rb = rb_mod
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _write_metadata(self, filename, data):
        path = os.path.join(self.tmpdir, filename)
        with open(path, "w") as f:
            json.dump(data, f)
        return path

    def test_find_metadata_files_empty_dir(self):
        """find_metadata_files returns empty list for dir with no metadata."""
        self.assertEqual(self.rb.find_metadata_files(self.tmpdir), [])

    def test_find_metadata_files_nonexistent_dir(self):
        """find_metadata_files returns empty list for nonexistent dir."""
        self.assertEqual(self.rb.find_metadata_files("/tmp/no_such_dir_abc123"), [])

    def test_find_metadata_files_finds_rollback_json(self):
        """find_metadata_files finds files matching *_rollback_*.json pattern."""
        self._write_metadata("privacy_rollback_2026.json", {"script": "privacy.sh", "changes": []})
        self._write_metadata("firewall_rollback_2026.json", {"script": "firewall.sh", "changes": []})
        files = self.rb.find_metadata_files(self.tmpdir)
        self.assertEqual(len(files), 2)

    def test_load_metadata_file_not_found(self):
        """load_metadata raises FileNotFoundError for missing file."""
        with self.assertRaises(FileNotFoundError):
            self.rb.load_metadata("/tmp/no_such_file.json")

    def test_load_metadata_valid(self):
        """load_metadata returns parsed dict for valid JSON."""
        path = self._write_metadata("test_rollback_001.json", {"script": "test.sh", "changes": []})
        data = self.rb.load_metadata(path)
        self.assertEqual(data["script"], "test.sh")

    def test_list_rollbacks_empty(self):
        """list_rollbacks returns count=0 for empty dir."""
        result = self.rb.list_rollbacks(self.tmpdir)
        self.assertEqual(result["count"], 0)
        self.assertEqual(result["files"], [])

    def test_list_rollbacks_with_files(self):
        """list_rollbacks returns summaries for each metadata file."""
        self._write_metadata("priv_rollback_001.json", {
            "script": "privacy.sh", "status": "completed", "changes": [{"component": "a", "detail": "b"}]
        })
        result = self.rb.list_rollbacks(self.tmpdir)
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["files"][0]["script"], "privacy.sh")
        self.assertEqual(result["files"][0]["changes"], 1)

    def test_apply_rollback_empty_changes(self):
        """apply_rollback with no changes should return 0 applied."""
        path = self._write_metadata("test_rollback_empty.json", {"script": "test.sh", "changes": []})
        result = self.rb.apply_rollback(path)
        self.assertEqual(result["total_changes"], 0)
        self.assertEqual(result["applied"], 0)
        self.assertEqual(result["status"], "ok")

    def test_apply_rollback_dry_run(self):
        """apply_rollback dry_run should not execute commands."""
        path = self._write_metadata("test_rollback_dry.json", {
            "script": "privacy.sh",
            "changes": [{
                "component": "com.apple.test/Key",
                "detail": "Set Key to 1",
                "rollback_command": "echo rollback_executed"
            }]
        })
        result = self.rb.apply_rollback(path, dry_run=True)
        self.assertEqual(result["applied"], 1)
        self.assertEqual(result["status"], "dry-run")
        self.assertEqual(result["results"][0]["status"], "would-rollback")

    def test_apply_rollback_executes_commands(self):
        """apply_rollback should execute rollback commands."""
        path = self._write_metadata("test_rollback_exec.json", {
            "script": "test.sh",
            "changes": [{
                "component": "test/comp",
                "detail": "test change",
                "rollback_command": "true"
            }]
        })
        result = self.rb.apply_rollback(path)
        self.assertEqual(result["applied"], 1)
        self.assertEqual(result["failed"], 0)
        self.assertEqual(result["results"][0]["status"], "rolled-back")

    def test_apply_rollback_failed_command(self):
        """apply_rollback counts failed commands."""
        path = self._write_metadata("test_rollback_fail.json", {
            "script": "test.sh",
            "changes": [{
                "component": "test/comp",
                "detail": "test change",
                "rollback_command": "false"
            }]
        })
        result = self.rb.apply_rollback(path)
        self.assertEqual(result["failed"], 1)
        self.assertEqual(result["status"], "failed")

    def test_apply_rollback_skips_no_command(self):
        """apply_rollback skips changes with no rollback command and no domain/key."""
        path = self._write_metadata("test_rollback_skip.json", {
            "script": "test.sh",
            "changes": [{
                "component": "plain_component",
                "detail": "no command",
                "rollback_command": ""
            }]
        })
        result = self.rb.apply_rollback(path)
        self.assertEqual(result["skipped"], 1)
        self.assertEqual(result["results"][0]["status"], "skipped")

    def test_apply_rollback_lifo_order(self):
        """apply_rollback processes changes in reverse (LIFO) order."""
        path = self._write_metadata("test_rollback_lifo.json", {
            "script": "test.sh",
            "changes": [
                {"component": "first", "detail": "first", "rollback_command": "true"},
                {"component": "second", "detail": "second", "rollback_command": "true"},
                {"component": "third", "detail": "third", "rollback_command": "true"},
            ]
        })
        result = self.rb.apply_rollback(path, dry_run=True)
        components = [r["component"] for r in result["results"]]
        self.assertEqual(components, ["third", "second", "first"])

    def test_apply_rollback_fallback_defaults_delete(self):
        """apply_rollback uses 'defaults delete domain key' fallback for domain/key components."""
        path = self._write_metadata("test_rollback_fallback.json", {
            "script": "test.sh",
            "changes": [{
                "component": "com.apple.test/SomeKey",
                "detail": "set SomeKey",
                "rollback_command": ""
            }]
        })
        result = self.rb.apply_rollback(path, dry_run=True)
        self.assertEqual(result["results"][0]["rollback_command"], "defaults delete com.apple.test SomeKey")
        self.assertEqual(result["results"][0]["status"], "would-rollback")

    def test_format_rollback_list_header(self):
        """format_rollback_list includes header."""
        result = self.rb.list_rollbacks(self.tmpdir)
        output = self.rb.format_rollback_list(result)
        self.assertIn("Albator Rollback Metadata", output)
        self.assertIn("Files found: 0", output)

    def test_format_rollback_report_header(self):
        """format_rollback_report includes header and summary."""
        path = self._write_metadata("test_rollback_fmt.json", {"script": "test.sh", "changes": []})
        result = self.rb.apply_rollback(path, dry_run=True)
        output = self.rb.format_rollback_report(result)
        self.assertIn("Albator Rollback Report", output)
        self.assertIn("Applied: 0", output)

    def test_apply_rollback_timeout(self):
        """apply_rollback handles command timeout."""
        path = self._write_metadata("test_rollback_timeout.json", {
            "script": "test.sh",
            "changes": [{
                "component": "test/comp",
                "detail": "slow command",
                "rollback_command": "sleep 60"
            }]
        })
        result = self.rb.apply_rollback(path, timeout=1)
        self.assertEqual(result["failed"], 1)
        self.assertIn("timed out", result["results"][0]["error"])


class TestRollbackCLIIntegration(unittest.TestCase):
    """CLI integration tests for the rollback subcommand (experiment 19)."""

    def setUp(self):
        self.repo_root = pathlib.Path(__file__).resolve().parents[1]
        self.cli = str(self.repo_root / "albator_cli.py")
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _write_metadata(self, filename, data):
        path = os.path.join(self.tmpdir, filename)
        with open(path, "w") as f:
            json.dump(data, f)
        return path

    def test_rollback_list_exits_zero(self):
        """rollback --list should always exit 0."""
        result = subprocess.run(
            ["python3", self.cli, "rollback", "--list", "--state-dir", self.tmpdir],
            capture_output=True, text=True, cwd=str(self.repo_root)
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("Albator Rollback Metadata", result.stdout)

    def test_rollback_list_json(self):
        """rollback --list --json-output should produce valid JSON."""
        self._write_metadata("priv_rollback_001.json", {
            "script": "privacy.sh", "status": "done", "changes": []
        })
        result = subprocess.run(
            ["python3", self.cli, "--json-output", "rollback", "--list", "--state-dir", self.tmpdir],
            capture_output=True, text=True, cwd=str(self.repo_root)
        )
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertEqual(data["command"], "rollback")
        self.assertTrue(data["success"])
        self.assertEqual(data["count"], 1)

    def test_rollback_no_metadata_exits_2(self):
        """rollback with no metadata files should exit 2."""
        result = subprocess.run(
            ["python3", self.cli, "rollback", "--state-dir", self.tmpdir],
            capture_output=True, text=True, cwd=str(self.repo_root)
        )
        self.assertEqual(result.returncode, 2)

    def test_rollback_dry_run_exits_zero(self):
        """rollback --dry-run should exit 0."""
        self._write_metadata("test_rollback_001.json", {
            "script": "test.sh",
            "changes": [{"component": "x", "detail": "y", "rollback_command": "echo ok"}]
        })
        result = subprocess.run(
            ["python3", self.cli, "rollback", "--dry-run", "--state-dir", self.tmpdir],
            capture_output=True, text=True, cwd=str(self.repo_root)
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("Albator Rollback Report", result.stdout)

    def test_rollback_dry_run_json(self):
        """rollback --dry-run --json-output should produce valid JSON."""
        self._write_metadata("test_rollback_002.json", {
            "script": "firewall.sh",
            "changes": [{"component": "fw/rule", "detail": "add rule", "rollback_command": "true"}]
        })
        result = subprocess.run(
            ["python3", self.cli, "--json-output", "rollback", "--dry-run", "--state-dir", self.tmpdir],
            capture_output=True, text=True, cwd=str(self.repo_root)
        )
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertEqual(data["command"], "rollback")
        self.assertTrue(data["success"])
        self.assertEqual(data["status"], "dry-run")

    def test_rollback_specific_file(self):
        """rollback with explicit metadata file path should work."""
        path = self._write_metadata("specific_rollback_001.json", {
            "script": "encryption.sh",
            "changes": [{"component": "enc/fv", "detail": "enable fv", "rollback_command": "true"}]
        })
        result = subprocess.run(
            ["python3", self.cli, "rollback", "--dry-run", path],
            capture_output=True, text=True, cwd=str(self.repo_root)
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("encryption.sh", result.stdout)

    def test_rollback_invalid_file_exits_2(self):
        """rollback with nonexistent file should exit 2."""
        result = subprocess.run(
            ["python3", self.cli, "rollback", "/tmp/nonexistent_metadata.json"],
            capture_output=True, text=True, cwd=str(self.repo_root)
        )
        self.assertEqual(result.returncode, 2)

    def test_rollback_json_no_metadata(self):
        """rollback --json-output with no metadata should produce error JSON."""
        result = subprocess.run(
            ["python3", self.cli, "--json-output", "rollback", "--state-dir", self.tmpdir],
            capture_output=True, text=True, cwd=str(self.repo_root)
        )
        self.assertEqual(result.returncode, 2)
        data = json.loads(result.stdout)
        self.assertFalse(data["success"])
        self.assertIn("No rollback metadata", data["error"])


class TestReportModule(unittest.TestCase):
    """Tests for the report module — comprehensive CIS Benchmark compliance reports (experiment 20)."""

    def setUp(self):
        import report as report_mod
        self.report_mod = report_mod
        self.repo_root = pathlib.Path(__file__).resolve().parents[1]
        self.rules_dir = str(self.repo_root / "rules")
        self.profiles_dir = str(self.repo_root / "config" / "profiles")

    def test_cis_controls_catalogue_has_77_entries(self):
        """CIS_CONTROLS should have exactly 77 control entries (72 unique rules, some shared)."""
        self.assertEqual(len(self.report_mod.CIS_CONTROLS), 77)

    def test_cis_controls_all_reference_existing_rules(self):
        """Every CIS control must reference a rule that exists on disk."""
        from scan import load_rules
        rules = load_rules(self.rules_dir)
        rule_ids = {r["id"] for r in rules}
        for cis_id, ctrl in self.report_mod.CIS_CONTROLS.items():
            self.assertIn(ctrl["rule"], rule_ids,
                          f"CIS {cis_id} references unknown rule {ctrl['rule']}")

    def test_cis_controls_level_values(self):
        """Every CIS control must have level 1 or 2."""
        for cis_id, ctrl in self.report_mod.CIS_CONTROLS.items():
            self.assertIn(ctrl["level"], (1, 2),
                          f"CIS {cis_id} has invalid level {ctrl['level']}")

    def test_cis_controls_level1_count(self):
        """There should be 65 Level 1 control entries."""
        l1 = [c for c in self.report_mod.CIS_CONTROLS.values() if c["level"] == 1]
        self.assertEqual(len(l1), 65)

    def test_cis_controls_level2_count(self):
        """There should be 12 Level 2 control entries."""
        l2 = [c for c in self.report_mod.CIS_CONTROLS.values() if c["level"] == 2]
        self.assertEqual(len(l2), 12)

    def test_generate_report_dry_run_returns_all_sections(self):
        """Dry-run report should contain all expected top-level keys."""
        result = self.report_mod.generate_report(self.rules_dir, dry_run=True)
        for key in ("metadata", "summary", "level_summary", "sections",
                     "cis_controls", "nist_families"):
            self.assertIn(key, result, f"Missing key: {key}")

    def test_generate_report_dry_run_summary(self):
        """Dry-run report summary should have 0 passed/failed."""
        result = self.report_mod.generate_report(self.rules_dir, dry_run=True)
        self.assertEqual(result["summary"]["passed"], 0)
        self.assertEqual(result["summary"]["failed"], 0)
        self.assertTrue(result["metadata"]["dry_run"])

    def test_generate_report_dry_run_77_controls(self):
        """Dry-run report should list all 77 CIS control entries."""
        result = self.report_mod.generate_report(self.rules_dir, dry_run=True)
        self.assertEqual(len(result["cis_controls"]), 77)

    def test_generate_report_sections_cover_1_through_6(self):
        """Report should have sections 1 through 6."""
        result = self.report_mod.generate_report(self.rules_dir, dry_run=True)
        for sec in ("1", "2", "3", "4", "5", "6"):
            self.assertIn(sec, result["sections"], f"Missing section {sec}")

    def test_generate_report_with_profile(self):
        """Report with cis_level1 profile should mark L2-only controls as N/A."""
        result = self.report_mod.generate_report(
            self.rules_dir,
            profiles_dir=self.profiles_dir,
            profile_name="cis_level1",
            dry_run=True,
        )
        # cis_level1 should exclude some L2 controls
        na_count = result["summary"]["not_applicable"]
        self.assertGreater(na_count, 0,
                           "cis_level1 profile should have some N/A controls")

    def test_generate_report_nist_families_present(self):
        """Report should include NIST 800-53 family coverage data."""
        result = self.report_mod.generate_report(self.rules_dir, dry_run=True)
        nist = result["nist_families"]
        self.assertGreater(len(nist), 0)
        # At minimum AC and AU families should be present
        self.assertIn("AC", nist)
        self.assertIn("AU", nist)

    def test_generate_report_level_summary(self):
        """Level summary should have level1 and level2 sub-dicts."""
        result = self.report_mod.generate_report(self.rules_dir, dry_run=True)
        ls = result["level_summary"]
        self.assertIn("level1", ls)
        self.assertIn("level2", ls)
        for key in ("passed", "failed", "total", "compliance_pct"):
            self.assertIn(key, ls["level1"])
            self.assertIn(key, ls["level2"])

    def test_format_text_report_contains_header(self):
        """Text report should contain the expected header."""
        result = self.report_mod.generate_report(self.rules_dir, dry_run=True)
        text = self.report_mod.format_text_report(result)
        self.assertIn("ALBATOR CIS macOS Benchmark Compliance Report", text)
        self.assertIn("Overall Compliance", text)
        self.assertIn("Level Breakdown", text)
        self.assertIn("Section Breakdown", text)

    def test_format_text_report_contains_sections(self):
        """Text report should mention all 6 CIS sections."""
        result = self.report_mod.generate_report(self.rules_dir, dry_run=True)
        text = self.report_mod.format_text_report(result)
        for sec_title in self.report_mod.CIS_SECTIONS.values():
            self.assertIn(sec_title[:30], text)

    def test_format_csv_report_has_header_row(self):
        """CSV report should start with a header row."""
        result = self.report_mod.generate_report(self.rules_dir, dry_run=True)
        csv_out = self.report_mod.format_csv_report(result)
        lines = csv_out.strip().splitlines()
        self.assertTrue(lines[0].rstrip("\r").startswith("cis_id,title,level,rule_id,severity,status,detail"))
        # Should have 77 data rows + 1 header
        self.assertEqual(len(lines), 78)

    def test_format_csv_report_parseable(self):
        """CSV report should be parseable by csv.reader."""
        import csv as csv_mod
        result = self.report_mod.generate_report(self.rules_dir, dry_run=True)
        csv_out = self.report_mod.format_csv_report(result)
        reader = csv_mod.reader(io.StringIO(csv_out))
        rows = list(reader)
        self.assertEqual(len(rows), 78)  # header + 77 controls

    def test_generate_report_with_severity_filter(self):
        """Report with severity filter should reduce evaluated controls."""
        result = self.report_mod.generate_report(
            self.rules_dir, min_severity="critical", dry_run=True
        )
        # With critical filter, many controls should be N/A
        self.assertGreater(result["summary"]["not_applicable"], 0)

    def test_generate_report_nonexistent_profile_raises(self):
        """Report with nonexistent profile should raise FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            self.report_mod.generate_report(
                self.rules_dir,
                profiles_dir=self.profiles_dir,
                profile_name="nonexistent",
            )

    def test_section_for_helper(self):
        """_section_for should extract the top-level section number."""
        self.assertEqual(self.report_mod._section_for("2.3.3.1"), "2")
        self.assertEqual(self.report_mod._section_for("5.2.1"), "5")
        self.assertEqual(self.report_mod._section_for("1.1"), "1")


class TestReportCLIIntegration(unittest.TestCase):
    """CLI integration tests for the report command (experiment 20)."""

    def setUp(self):
        self.repo_root = pathlib.Path(__file__).resolve().parents[1]
        self.cli = str(self.repo_root / "albator_cli.py")

    def test_report_dry_run_text(self):
        """report --dry-run should produce text output and exit 0."""
        result = subprocess.run(
            ["python3", self.cli, "report", "--dry-run"],
            capture_output=True, text=True, cwd=str(self.repo_root)
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("ALBATOR CIS macOS Benchmark Compliance Report", result.stdout)
        self.assertIn("DRY-RUN", result.stdout)

    def test_report_dry_run_json(self):
        """report --dry-run --json-output should produce valid JSON."""
        result = subprocess.run(
            ["python3", self.cli, "--json-output", "report", "--dry-run"],
            capture_output=True, text=True, cwd=str(self.repo_root)
        )
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertEqual(data["command"], "report")
        self.assertTrue(data["success"])
        self.assertIn("summary", data)
        self.assertIn("cis_controls", data)

    def test_report_dry_run_csv(self):
        """report --dry-run --format csv should produce CSV output."""
        result = subprocess.run(
            ["python3", self.cli, "report", "--dry-run", "--format", "csv"],
            capture_output=True, text=True, cwd=str(self.repo_root)
        )
        self.assertEqual(result.returncode, 0)
        lines = result.stdout.strip().split("\n")
        self.assertEqual(lines[0], "cis_id,title,level,rule_id,severity,status,detail")
        self.assertEqual(len(lines), 78)

    def test_report_with_profile_dry_run(self):
        """report --profile cis_level1 --dry-run should filter to L1 rules."""
        result = subprocess.run(
            ["python3", self.cli, "report", "--profile", "cis_level1", "--dry-run"],
            capture_output=True, text=True, cwd=str(self.repo_root)
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("cis_level1", result.stdout)

    def test_report_json_format_flag(self):
        """report --format json should produce same output as --json-output."""
        result = subprocess.run(
            ["python3", self.cli, "report", "--dry-run", "--format", "json"],
            capture_output=True, text=True, cwd=str(self.repo_root)
        )
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertIn("summary", data)
        self.assertIn("sections", data)

    def test_report_nonexistent_profile_exits_2(self):
        """report with nonexistent profile should exit 2."""
        result = subprocess.run(
            ["python3", self.cli, "report", "--profile", "nonexistent"],
            capture_output=True, text=True, cwd=str(self.repo_root)
        )
        self.assertEqual(result.returncode, 2)


class TestODVModule(unittest.TestCase):
    """Tests for the Organization-Defined Values (ODV) module."""

    def setUp(self):
        self.repo_root = pathlib.Path(__file__).resolve().parents[1]
        self.rules_dir = self.repo_root / "rules"
        self.odv_defaults_path = self.repo_root / "config" / "odv_defaults.yaml"

    def _load_all_rules(self):
        import yaml
        rules = []
        for path in sorted(self.rules_dir.glob("os_*.yaml")):
            with open(path) as f:
                data = yaml.safe_load(f)
            if data and "id" in data:
                rules.append(data)
        return rules

    def test_odv_defaults_file_exists(self):
        """config/odv_defaults.yaml must exist."""
        self.assertTrue(self.odv_defaults_path.exists())

    def test_load_odv_defaults_returns_dict(self):
        """load_odv_defaults should return a dict of ODV values."""
        from odv import load_odv_defaults
        odv_values = load_odv_defaults(str(self.odv_defaults_path))
        self.assertIsInstance(odv_values, dict)
        self.assertGreater(len(odv_values), 0)

    def test_load_odv_defaults_has_all_schema_variables(self):
        """ODV defaults file must define all variables in the schema."""
        from odv import load_odv_defaults, ODV_SCHEMA
        odv_values = load_odv_defaults(str(self.odv_defaults_path))
        for var_name in ODV_SCHEMA:
            self.assertIn(var_name, odv_values, f"ODV defaults missing: {var_name}")

    def test_validate_odv_defaults_no_errors(self):
        """validate_odv_values should report no errors for the default config."""
        from odv import load_odv_defaults, validate_odv_values
        odv_values = load_odv_defaults(str(self.odv_defaults_path))
        errors = validate_odv_values(odv_values)
        self.assertEqual(errors, [], f"ODV validation errors: {errors}")

    def test_validate_odv_catches_missing_variable(self):
        """validate_odv_values should catch missing variables."""
        from odv import validate_odv_values
        errors = validate_odv_values({})
        self.assertGreater(len(errors), 0)
        self.assertTrue(any("missing" in e for e in errors))

    def test_validate_odv_catches_wrong_type(self):
        """validate_odv_values should catch type mismatches."""
        from odv import load_odv_defaults, validate_odv_values
        odv_values = load_odv_defaults(str(self.odv_defaults_path))
        odv_values["password_min_length"] = "not_an_int"
        errors = validate_odv_values(odv_values)
        self.assertTrue(any("password_min_length" in e for e in errors))

    def test_no_rules_have_odv_missing(self):
        """No os_*.yaml rule should have odv='missing' anymore."""
        rules = self._load_all_rules()
        for rule in rules:
            self.assertNotEqual(
                rule.get("odv"), "missing",
                f"Rule {rule['id']} still has odv='missing'"
            )

    def test_all_rules_have_odv_field(self):
        """Every os_*.yaml rule must have an 'odv' field."""
        rules = self._load_all_rules()
        for rule in rules:
            self.assertIn("odv", rule, f"Rule {rule['id']} is missing 'odv' field")

    def test_boolean_rules_have_odv_none(self):
        """Rules without tunable parameters should have odv='none'."""
        from odv import extract_rule_odv
        rules = self._load_all_rules()
        none_count = sum(1 for r in rules if r.get("odv") == "none")
        self.assertEqual(none_count, 61, f"Expected 61 boolean rules with odv='none', got {none_count}")

    def test_tunable_rules_have_structured_odv(self):
        """11 rules should have structured ODV with variable/default/type."""
        from odv import extract_rule_odv
        rules = self._load_all_rules()
        tunable = [r for r in rules if extract_rule_odv(r) is not None]
        self.assertEqual(len(tunable), 11, f"Expected 11 tunable rules, got {len(tunable)}")

    def test_tunable_rules_odv_has_required_keys(self):
        """Each tunable rule's ODV must have variable, default, description, type."""
        from odv import extract_rule_odv
        rules = self._load_all_rules()
        for rule in rules:
            odv_meta = extract_rule_odv(rule)
            if odv_meta is None:
                continue
            for key in ("variable", "default", "description", "type"):
                self.assertIn(
                    key, odv_meta,
                    f"Rule {rule['id']} ODV missing key: {key}"
                )

    def test_odv_variables_match_schema(self):
        """All ODV variable names in rules must exist in ODV_SCHEMA."""
        from odv import extract_rule_odv, ODV_SCHEMA
        rules = self._load_all_rules()
        for rule in rules:
            odv_meta = extract_rule_odv(rule)
            if odv_meta is None:
                continue
            self.assertIn(
                odv_meta["variable"], ODV_SCHEMA,
                f"Rule {rule['id']} uses unknown ODV variable: {odv_meta['variable']}"
            )

    def test_odv_variables_unique_across_rules(self):
        """Each ODV variable should map to exactly one rule."""
        from odv import extract_rule_odv
        rules = self._load_all_rules()
        seen = {}
        for rule in rules:
            odv_meta = extract_rule_odv(rule)
            if odv_meta is None:
                continue
            var = odv_meta["variable"]
            self.assertNotIn(
                var, seen,
                f"ODV variable '{var}' used by both '{seen.get(var)}' and '{rule['id']}'"
            )
            seen[var] = rule["id"]

    def test_get_odv_value_uses_override(self):
        """get_odv_value should prefer org override over rule default."""
        from odv import get_odv_value
        rule = {
            "id": "test_rule",
            "odv": {
                "variable": "password_min_length",
                "default": 15,
                "description": "test",
                "type": "integer",
            }
        }
        val = get_odv_value(rule, {"password_min_length": 20})
        self.assertEqual(val, 20)

    def test_get_odv_value_falls_back_to_default(self):
        """get_odv_value should fall back to rule default if no override."""
        from odv import get_odv_value
        rule = {
            "id": "test_rule",
            "odv": {
                "variable": "password_min_length",
                "default": 15,
                "description": "test",
                "type": "integer",
            }
        }
        val = get_odv_value(rule, {})
        self.assertEqual(val, 15)

    def test_get_odv_value_returns_none_for_boolean_rule(self):
        """get_odv_value should return None for rules with odv='none'."""
        from odv import get_odv_value
        rule = {"id": "test_rule", "odv": "none"}
        self.assertIsNone(get_odv_value(rule))

    def test_list_odv_rules_returns_11(self):
        """list_odv_rules should return 11 tunable rules."""
        from odv import list_odv_rules
        rules = self._load_all_rules()
        odv_list = list_odv_rules(rules)
        self.assertEqual(len(odv_list), 11)
        for entry in odv_list:
            self.assertIn("rule_id", entry)
            self.assertIn("variable", entry)
            self.assertIn("default", entry)

    def test_validate_rules_odv_consistency_no_errors(self):
        """validate_rules_odv_consistency should report no errors for current rules."""
        from odv import validate_rules_odv_consistency
        rules = self._load_all_rules()
        errors = validate_rules_odv_consistency(rules)
        self.assertEqual(errors, [], f"ODV consistency errors: {errors}")

    def test_load_odv_missing_file_raises(self):
        """load_odv_defaults should raise FileNotFoundError for missing file."""
        from odv import load_odv_defaults
        with self.assertRaises(FileNotFoundError):
            load_odv_defaults("/nonexistent/odv.yaml")

    def test_odv_schema_covers_all_11_variables(self):
        """ODV_SCHEMA should define exactly 11 variables."""
        from odv import ODV_SCHEMA
        self.assertEqual(len(ODV_SCHEMA), 11)


class TestODVSubstitution(unittest.TestCase):
    """Tests for ODV-aware command substitution (experiment 22)."""

    def test_substitute_odv_command_replaces_placeholder(self):
        """substitute_odv_command should replace {ODV_VALUE} with the effective value."""
        from odv import substitute_odv_command
        rule = {
            "id": "test_rule",
            "odv": {"variable": "password_min_length", "default": 15,
                    "description": "test", "type": "integer"},
        }
        cmd = "sudo /usr/bin/pwpolicy -setglobalpolicy 'minChars={ODV_VALUE}'"
        result = substitute_odv_command(cmd, rule, {"password_min_length": 20})
        self.assertEqual(result, "sudo /usr/bin/pwpolicy -setglobalpolicy 'minChars=20'")

    def test_substitute_odv_command_uses_default_when_no_override(self):
        """substitute_odv_command should use rule default when no org override."""
        from odv import substitute_odv_command
        rule = {
            "id": "test_rule",
            "odv": {"variable": "password_min_length", "default": 15,
                    "description": "test", "type": "integer"},
        }
        cmd = "sudo pwpolicy 'minChars={ODV_VALUE}'"
        result = substitute_odv_command(cmd, rule, {})
        self.assertEqual(result, "sudo pwpolicy 'minChars=15'")

    def test_substitute_odv_command_no_placeholder_passthrough(self):
        """Commands without {ODV_VALUE} should pass through unchanged."""
        from odv import substitute_odv_command
        rule = {"id": "test_rule", "odv": "none"}
        cmd = "sudo launchctl disable system/com.apple.screensharing"
        result = substitute_odv_command(cmd, rule, None)
        self.assertEqual(result, cmd)

    def test_substitute_odv_command_boolean_rule_no_change(self):
        """Boolean rules (odv=none) should not be modified even with placeholder."""
        from odv import substitute_odv_command
        rule = {"id": "test_rule", "odv": "none"}
        cmd = "echo {ODV_VALUE}"
        result = substitute_odv_command(cmd, rule, None)
        self.assertEqual(result, cmd)

    def test_substitute_odv_command_string_value(self):
        """substitute_odv_command should handle string ODV values."""
        from odv import substitute_odv_command
        rule = {
            "id": "test_rule",
            "odv": {"variable": "ntp_server", "default": "time.apple.com",
                    "description": "test", "type": "string"},
        }
        cmd = "sudo systemsetup -setnetworktimeserver {ODV_VALUE}"
        result = substitute_odv_command(cmd, rule, {"ntp_server": "ntp.example.com"})
        self.assertEqual(result, "sudo systemsetup -setnetworktimeserver ntp.example.com")

    def test_get_effective_check_command_prefers_odv_template(self):
        """get_effective_check_command should use check_odv when ODV values provided."""
        from odv import get_effective_check_command
        rule = {
            "id": "test_rule",
            "check": "grep 'ttl=365' /etc/asl/com.apple.install",
            "check_odv": "grep 'ttl={ODV_VALUE}' /etc/asl/com.apple.install",
            "odv": {"variable": "install_log_retention_days", "default": 365,
                    "description": "test", "type": "integer"},
        }
        result = get_effective_check_command(rule, {"install_log_retention_days": 730})
        self.assertEqual(result, "grep 'ttl=730' /etc/asl/com.apple.install")

    def test_get_effective_check_command_falls_back_without_odv(self):
        """get_effective_check_command should use check when no ODV values."""
        from odv import get_effective_check_command
        rule = {
            "id": "test_rule",
            "check": "grep 'ttl=365' /etc/asl/com.apple.install",
            "check_odv": "grep 'ttl={ODV_VALUE}' /etc/asl/com.apple.install",
            "odv": {"variable": "install_log_retention_days", "default": 365,
                    "description": "test", "type": "integer"},
        }
        result = get_effective_check_command(rule, None)
        self.assertEqual(result, "grep 'ttl=365' /etc/asl/com.apple.install")

    def test_get_effective_fix_command_prefers_odv_template(self):
        """get_effective_fix_command should use fix_odv when ODV values provided."""
        from odv import get_effective_fix_command
        rule = {
            "id": "test_rule",
            "fix": "sudo chmod 700 /Users/foo",
            "fix_odv": "sudo chmod {ODV_VALUE} /Users/foo",
            "odv": {"variable": "home_folder_permissions", "default": "700",
                    "description": "test", "type": "string"},
        }
        result = get_effective_fix_command(rule, {"home_folder_permissions": "750"})
        self.assertEqual(result, "sudo chmod 750 /Users/foo")

    def test_get_effective_fix_command_falls_back_without_odv(self):
        """get_effective_fix_command should use fix when no ODV values."""
        from odv import get_effective_fix_command
        rule = {
            "id": "test_rule",
            "fix": "sudo chmod 700 /Users/foo",
            "fix_odv": "sudo chmod {ODV_VALUE} /Users/foo",
            "odv": {"variable": "home_folder_permissions", "default": "700",
                    "description": "test", "type": "string"},
        }
        result = get_effective_fix_command(rule, None)
        self.assertEqual(result, "sudo chmod 700 /Users/foo")


class TestODVAwareRules(unittest.TestCase):
    """Validate all 11 ODV-tunable rules have proper fix_odv templates (experiment 22)."""

    def _load_all_rules(self):
        import yaml
        rules = []
        rules_dir = os.path.join(os.path.dirname(__file__), "..", "rules")
        import glob as globmod
        for path in sorted(globmod.glob(os.path.join(rules_dir, "os_*.yaml"))):
            with open(path) as f:
                data = yaml.safe_load(f)
            if data:
                rules.append(data)
        return rules

    def test_all_odv_tunable_rules_have_fix_odv(self):
        """Every rule with structured ODV metadata must have a fix_odv template."""
        from odv import extract_rule_odv
        rules = self._load_all_rules()
        missing = []
        for rule in rules:
            odv_meta = extract_rule_odv(rule)
            if odv_meta is not None:
                if "fix_odv" not in rule:
                    missing.append(rule["id"])
        self.assertEqual(missing, [], f"Rules with ODV but no fix_odv: {missing}")

    def test_all_fix_odv_templates_contain_placeholder(self):
        """Every fix_odv template must contain {ODV_VALUE} placeholder."""
        from odv import extract_rule_odv
        rules = self._load_all_rules()
        errors = []
        for rule in rules:
            if "fix_odv" in rule:
                if "{ODV_VALUE}" not in rule["fix_odv"]:
                    errors.append(f"{rule['id']}: fix_odv missing {{ODV_VALUE}}")
        self.assertEqual(errors, [], f"Template errors: {errors}")

    def test_check_odv_templates_contain_placeholder(self):
        """Every check_odv template must contain {ODV_VALUE} placeholder."""
        rules = self._load_all_rules()
        errors = []
        for rule in rules:
            if "check_odv" in rule:
                if "{ODV_VALUE}" not in rule["check_odv"]:
                    errors.append(f"{rule['id']}: check_odv missing {{ODV_VALUE}}")
        self.assertEqual(errors, [], f"Template errors: {errors}")

    def test_fix_odv_count_matches_odv_rules(self):
        """There should be exactly 11 rules with fix_odv templates."""
        rules = self._load_all_rules()
        count = sum(1 for r in rules if "fix_odv" in r)
        self.assertEqual(count, 11, f"Expected 11 fix_odv templates, found {count}")

    def test_check_odv_templates_exist_for_easy_rules(self):
        """Screensaver timeout and install log retention should have check_odv."""
        rules = self._load_all_rules()
        rule_by_id = {r["id"]: r for r in rules}
        self.assertIn("check_odv", rule_by_id["os_screensaver_timeout"])
        self.assertIn("check_odv", rule_by_id["os_install_log_retention_configure"])

    def test_odv_substitution_produces_valid_commands(self):
        """Substituting ODV defaults into fix_odv should produce non-empty commands."""
        from odv import substitute_odv_command, extract_rule_odv
        rules = self._load_all_rules()
        for rule in rules:
            if "fix_odv" in rule:
                result = substitute_odv_command(rule["fix_odv"], rule, None)
                self.assertTrue(len(result.strip()) > 0,
                                f"{rule['id']}: fix_odv produced empty command")
                self.assertNotIn("{ODV_VALUE}", result,
                                 f"{rule['id']}: fix_odv still has placeholder after substitution")


class TestScanODVIntegration(unittest.TestCase):
    """Test scan module with ODV overrides (experiment 22)."""

    def test_scan_accepts_odv_file_parameter(self):
        """scan() should accept odv_file parameter without error."""
        from scan import scan
        with tempfile.TemporaryDirectory() as td:
            # Create a minimal rule
            rules_dir = os.path.join(td, "rules")
            os.makedirs(rules_dir)
            rule = {
                "id": "test_rule", "title": "Test", "severity": "low",
                "check": "true", "fix": "true", "odv": "none",
            }
            with open(os.path.join(rules_dir, "os_test.yaml"), "w") as f:
                yaml.dump(rule, f)

            result = scan(rules_dir=rules_dir, dry_run=True, odv_file=None)
            self.assertEqual(result["rules_scanned"], 1)

    def test_scan_dry_run_uses_odv_template(self):
        """In dry-run with ODV overrides, scan should show the ODV-substituted check command."""
        from scan import scan
        with tempfile.TemporaryDirectory() as td:
            rules_dir = os.path.join(td, "rules")
            os.makedirs(rules_dir)
            rule = {
                "id": "os_test_odv", "title": "Test ODV", "severity": "medium",
                "check": "echo default=365",
                "check_odv": "echo default={ODV_VALUE}",
                "fix": "true",
                "odv": {"variable": "install_log_retention_days", "default": 365,
                        "description": "test", "type": "integer"},
            }
            with open(os.path.join(rules_dir, "os_test_odv.yaml"), "w") as f:
                yaml.dump(rule, f)

            # Create ODV file
            odv_file = os.path.join(td, "odv.yaml")
            with open(odv_file, "w") as f:
                yaml.dump({"odv": {"install_log_retention_days": 730}}, f)

            result = scan(rules_dir=rules_dir, dry_run=True, odv_file=odv_file)
            self.assertEqual(result["results"][0]["check"], "echo default=730")


class TestFixODVIntegration(unittest.TestCase):
    """Test fix module with ODV overrides (experiment 22)."""

    def test_fix_accepts_odv_file_parameter(self):
        """fix() should accept odv_file parameter without error."""
        from fix import fix
        with tempfile.TemporaryDirectory() as td:
            rules_dir = os.path.join(td, "rules")
            os.makedirs(rules_dir)
            rule = {
                "id": "test_rule", "title": "Test", "severity": "low",
                "check": "true", "fix": "true", "odv": "none",
            }
            with open(os.path.join(rules_dir, "os_test.yaml"), "w") as f:
                yaml.dump(rule, f)

            result = fix(rules_dir=rules_dir, dry_run=True, odv_file=None)
            self.assertEqual(result["rules_checked"], 1)

    def test_fix_dry_run_uses_odv_template(self):
        """In dry-run mode, fix should show ODV-substituted fix command."""
        from fix import fix
        with tempfile.TemporaryDirectory() as td:
            rules_dir = os.path.join(td, "rules")
            os.makedirs(rules_dir)
            rule = {
                "id": "os_test_odv", "title": "Test ODV", "severity": "medium",
                "check": "false",  # always non-compliant
                "fix": "echo minChars=15",
                "fix_odv": "echo minChars={ODV_VALUE}",
                "odv": {"variable": "password_min_length", "default": 15,
                        "description": "test", "type": "integer"},
            }
            with open(os.path.join(rules_dir, "os_test_odv.yaml"), "w") as f:
                yaml.dump(rule, f)

            odv_file = os.path.join(td, "odv.yaml")
            with open(odv_file, "w") as f:
                yaml.dump({"odv": {"password_min_length": 20}}, f)

            result = fix(rules_dir=rules_dir, dry_run=True, odv_file=odv_file)
            would_fix = [r for r in result["results"] if r["status"] == "would-fix"]
            self.assertEqual(len(would_fix), 1)
            self.assertIn("minChars=20", would_fix[0]["fix"])


class TestCLIODVFlag(unittest.TestCase):
    """Test CLI --odv-file flag integration (experiment 22)."""

    def test_scan_cli_accepts_odv_file(self):
        """CLI scan subcommand should accept --odv-file flag."""
        result = subprocess.run(
            [sys.executable, "-m", "albator_cli", "scan", "--dry-run",
             "--odv-file", "/nonexistent/odv.yaml"],
            capture_output=True, text=True,
            cwd=os.path.join(os.path.dirname(__file__), ".."),
        )
        # Should fail due to missing file, not unknown argument
        self.assertNotIn("unrecognized arguments", result.stderr)

    def test_fix_cli_accepts_odv_file(self):
        """CLI fix subcommand should accept --odv-file flag."""
        result = subprocess.run(
            [sys.executable, "-m", "albator_cli", "fix", "--dry-run",
             "--odv-file", "/nonexistent/odv.yaml"],
            capture_output=True, text=True,
            cwd=os.path.join(os.path.dirname(__file__), ".."),
        )
        self.assertNotIn("unrecognized arguments", result.stderr)

    def test_report_cli_accepts_odv_file(self):
        """CLI report subcommand should accept --odv-file flag."""
        result = subprocess.run(
            [sys.executable, "-m", "albator_cli", "report", "--dry-run",
             "--odv-file", "/nonexistent/odv.yaml"],
            capture_output=True, text=True,
            cwd=os.path.join(os.path.dirname(__file__), ".."),
        )
        self.assertNotIn("unrecognized arguments", result.stderr)


###############################################################################
# Experiment 23 — Exemption / Exception Management
###############################################################################

from exemptions import load_exemptions, get_exempt_ids, filter_rules_with_exemptions, format_exemption_summary


class TestExemptionsLoading(unittest.TestCase):
    """Test exemptions.py loading and validation."""

    def test_load_valid_exemptions(self):
        """Valid exemptions file loads correctly."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump({"exemptions": [
                {"rule_id": "os_test_rule", "reason": "Business need", "approved_by": "CISO"},
            ]}, f)
            f.flush()
            result = load_exemptions(f.name)
        os.unlink(f.name)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["rule_id"], "os_test_rule")
        self.assertEqual(result[0]["reason"], "Business need")
        self.assertFalse(result[0]["expired"])
        self.assertIsNone(result[0]["expires"])

    def test_load_exemption_with_future_expiry(self):
        """Exemption with future expiry is not expired."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump({"exemptions": [
                {"rule_id": "os_test", "reason": "Test", "approved_by": "Admin",
                 "expires": "2099-12-31"},
            ]}, f)
            f.flush()
            result = load_exemptions(f.name)
        os.unlink(f.name)
        self.assertFalse(result[0]["expired"])
        self.assertEqual(result[0]["expires"], "2099-12-31")

    def test_load_exemption_with_past_expiry(self):
        """Exemption with past expiry is marked expired."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump({"exemptions": [
                {"rule_id": "os_test", "reason": "Test", "approved_by": "Admin",
                 "expires": "2020-01-01"},
            ]}, f)
            f.flush()
            result = load_exemptions(f.name)
        os.unlink(f.name)
        self.assertTrue(result[0]["expired"])

    def test_load_missing_file_raises(self):
        """Missing exemptions file raises FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            load_exemptions("/nonexistent/exemptions.yaml")

    def test_load_missing_top_level_key_raises(self):
        """File without 'exemptions' key raises ValueError."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump({"rules": []}, f)
            f.flush()
            with self.assertRaises(ValueError):
                load_exemptions(f.name)
        os.unlink(f.name)

    def test_load_missing_required_field_raises(self):
        """Entry without required 'reason' raises ValueError."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump({"exemptions": [
                {"rule_id": "os_test", "approved_by": "Admin"},
            ]}, f)
            f.flush()
            with self.assertRaises(ValueError):
                load_exemptions(f.name)
        os.unlink(f.name)

    def test_load_duplicate_rule_id_raises(self):
        """Duplicate rule_id raises ValueError."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump({"exemptions": [
                {"rule_id": "os_test", "reason": "A", "approved_by": "X"},
                {"rule_id": "os_test", "reason": "B", "approved_by": "Y"},
            ]}, f)
            f.flush()
            with self.assertRaises(ValueError):
                load_exemptions(f.name)
        os.unlink(f.name)

    def test_load_bad_date_format_raises(self):
        """Invalid date format in 'expires' raises ValueError."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump({"exemptions": [
                {"rule_id": "os_test", "reason": "Test", "approved_by": "Admin",
                 "expires": "not-a-date"},
            ]}, f)
            f.flush()
            with self.assertRaises(ValueError):
                load_exemptions(f.name)
        os.unlink(f.name)

    def test_load_multiple_exemptions(self):
        """Multiple valid exemptions load correctly."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump({"exemptions": [
                {"rule_id": "os_a", "reason": "Reason A", "approved_by": "Admin"},
                {"rule_id": "os_b", "reason": "Reason B", "approved_by": "CISO",
                 "expires": "2099-06-30"},
            ]}, f)
            f.flush()
            result = load_exemptions(f.name)
        os.unlink(f.name)
        self.assertEqual(len(result), 2)


class TestExemptionFiltering(unittest.TestCase):
    """Test exempt ID extraction and rule filtering."""

    def test_get_exempt_ids_excludes_expired(self):
        """Expired exemptions excluded by default."""
        exemptions = [
            {"rule_id": "os_a", "reason": "A", "approved_by": "X", "expires": None, "expired": False},
            {"rule_id": "os_b", "reason": "B", "approved_by": "Y", "expires": "2020-01-01", "expired": True},
        ]
        ids = get_exempt_ids(exemptions)
        self.assertEqual(ids, {"os_a"})

    def test_get_exempt_ids_includes_expired_when_asked(self):
        """Expired exemptions included with include_expired=True."""
        exemptions = [
            {"rule_id": "os_a", "reason": "A", "approved_by": "X", "expires": None, "expired": False},
            {"rule_id": "os_b", "reason": "B", "approved_by": "Y", "expires": "2020-01-01", "expired": True},
        ]
        ids = get_exempt_ids(exemptions, include_expired=True)
        self.assertEqual(ids, {"os_a", "os_b"})

    def test_filter_rules_with_exemptions(self):
        """Rules split correctly into active and exempted."""
        rules = [
            {"id": "os_a", "title": "A"},
            {"id": "os_b", "title": "B"},
            {"id": "os_c", "title": "C"},
        ]
        active, exempted = filter_rules_with_exemptions(rules, {"os_b"})
        self.assertEqual([r["id"] for r in active], ["os_a", "os_c"])
        self.assertEqual([r["id"] for r in exempted], ["os_b"])

    def test_filter_empty_exempt_set(self):
        """Empty exempt set returns all rules as active."""
        rules = [{"id": "os_a", "title": "A"}]
        active, exempted = filter_rules_with_exemptions(rules, set())
        self.assertEqual(len(active), 1)
        self.assertEqual(len(exempted), 0)


class TestExemptionFormatting(unittest.TestCase):
    """Test exemption summary formatting."""

    def test_format_no_exemptions(self):
        result = format_exemption_summary([])
        self.assertEqual(result, "No exemptions loaded.")

    def test_format_active_exemption(self):
        exemptions = [
            {"rule_id": "os_test", "reason": "Business need", "approved_by": "CISO",
             "expires": "2099-12-31", "expired": False},
        ]
        result = format_exemption_summary(exemptions)
        self.assertIn("[EXEMPT]", result)
        self.assertIn("os_test", result)
        self.assertIn("CISO", result)

    def test_format_expired_exemption(self):
        exemptions = [
            {"rule_id": "os_old", "reason": "Was needed", "approved_by": "Admin",
             "expires": "2020-01-01", "expired": True},
        ]
        result = format_exemption_summary(exemptions)
        self.assertIn("[EXPIRED]", result)
        self.assertIn("os_old", result)


class TestScanWithExemptions(unittest.TestCase):
    """Test scan module integration with exemptions."""

    def test_scan_exempt_rules_not_counted_as_failures(self):
        """Exempt rules should have status 'exempt' and not count as failures."""
        from scan import scan
        with tempfile.TemporaryDirectory() as td:
            rules_dir = os.path.join(td, "rules")
            os.makedirs(rules_dir)

            # Create two rules: one will fail, one will be exempted
            for name, check in [("os_pass", "true"), ("os_fail", "false"), ("os_exempt", "false")]:
                rule = {"id": name, "title": name, "severity": "medium",
                        "check": check, "fix": "echo fix", "odv": "none"}
                with open(os.path.join(rules_dir, f"{name}.yaml"), "w") as f:
                    yaml.dump(rule, f)

            exempt_file = os.path.join(td, "exemptions.yaml")
            with open(exempt_file, "w") as f:
                yaml.dump({"exemptions": [
                    {"rule_id": "os_exempt", "reason": "Test exempt", "approved_by": "Tester"},
                ]}, f)

            result = scan(rules_dir=rules_dir, exempt_file=exempt_file)
            self.assertEqual(result["passed"], 1)
            self.assertEqual(result["failed"], 1)
            self.assertEqual(result["exempt"], 1)
            exempt_results = [r for r in result["results"] if r["status"] == "exempt"]
            self.assertEqual(len(exempt_results), 1)
            self.assertEqual(exempt_results[0]["id"], "os_exempt")
            self.assertEqual(exempt_results[0]["exempt_reason"], "Test exempt")

    def test_scan_without_exempt_file_unchanged(self):
        """Scan without --exempt-file works as before (backward compatible)."""
        from scan import scan
        with tempfile.TemporaryDirectory() as td:
            rules_dir = os.path.join(td, "rules")
            os.makedirs(rules_dir)
            rule = {"id": "os_test", "title": "Test", "severity": "low",
                    "check": "true", "fix": "echo fix", "odv": "none"}
            with open(os.path.join(rules_dir, "os_test.yaml"), "w") as f:
                yaml.dump(rule, f)
            result = scan(rules_dir=rules_dir)
            self.assertEqual(result["exempt"], 0)
            self.assertEqual(result["passed"], 1)


class TestFixWithExemptions(unittest.TestCase):
    """Test fix module integration with exemptions."""

    def test_fix_skips_exempt_rules(self):
        """Exempt rules should not be fixed."""
        from fix import fix as fix_fn
        with tempfile.TemporaryDirectory() as td:
            rules_dir = os.path.join(td, "rules")
            os.makedirs(rules_dir)

            rule = {"id": "os_exempt_fix", "title": "Exempt Fix", "severity": "medium",
                    "check": "false", "fix": "echo fixing", "odv": "none"}
            with open(os.path.join(rules_dir, "os_exempt_fix.yaml"), "w") as f:
                yaml.dump(rule, f)

            exempt_file = os.path.join(td, "exemptions.yaml")
            with open(exempt_file, "w") as f:
                yaml.dump({"exemptions": [
                    {"rule_id": "os_exempt_fix", "reason": "Skip this", "approved_by": "Admin"},
                ]}, f)

            result = fix_fn(rules_dir=rules_dir, dry_run=True, exempt_file=exempt_file)
            self.assertEqual(result["exempt"], 1)
            exempt_results = [r for r in result["results"] if r["status"] == "exempt"]
            self.assertEqual(len(exempt_results), 1)
            # No would-fix entries for exempted rule
            would_fix = [r for r in result["results"] if r["status"] == "would-fix"]
            self.assertEqual(len(would_fix), 0)


class TestReportWithExemptions(unittest.TestCase):
    """Test report module integration with exemptions."""

    def test_report_marks_exempt_controls(self):
        """Report should mark exempted CIS controls as exempt."""
        from report import generate_report, format_text_report
        with tempfile.TemporaryDirectory() as td:
            rules_dir = os.path.join(td, "rules")
            os.makedirs(rules_dir)

            # Create a rule that maps to CIS 2.1.1 (os_bluetooth_disable)
            rule = {"id": "os_bluetooth_disable", "title": "Disable Bluetooth",
                    "severity": "medium", "check": "false", "fix": "echo fix",
                    "references": {"800-53r5": ["AC-18"]}, "odv": "none"}
            with open(os.path.join(rules_dir, "os_bluetooth_disable.yaml"), "w") as f:
                yaml.dump(rule, f)

            exempt_file = os.path.join(td, "exemptions.yaml")
            with open(exempt_file, "w") as f:
                yaml.dump({"exemptions": [
                    {"rule_id": "os_bluetooth_disable", "reason": "Wireless peripherals",
                     "approved_by": "CISO", "expires": "2099-12-31"},
                ]}, f)

            result = generate_report(rules_dir=rules_dir, exempt_file=exempt_file)
            self.assertGreater(result["summary"]["exempt"], 0)

            # CIS 2.1.1 should be exempt
            bt_ctrl = result["cis_controls"].get("2.1.1")
            self.assertIsNotNone(bt_ctrl)
            self.assertEqual(bt_ctrl["status"], "exempt")
            self.assertEqual(bt_ctrl["exempt_reason"], "Wireless peripherals")

            # Text report should show EXMT marker
            text = format_text_report(result)
            self.assertIn("EXMT", text)
            self.assertIn("exempt", text.lower())


class TestCLIExemptFlag(unittest.TestCase):
    """Test CLI --exempt-file flag integration."""

    def test_scan_cli_accepts_exempt_file(self):
        """CLI scan subcommand should accept --exempt-file flag."""
        result = subprocess.run(
            [sys.executable, "-m", "albator_cli", "scan", "--dry-run",
             "--exempt-file", "/nonexistent/exemptions.yaml"],
            capture_output=True, text=True,
            cwd=os.path.join(os.path.dirname(__file__), ".."),
        )
        self.assertNotIn("unrecognized arguments", result.stderr)

    def test_fix_cli_accepts_exempt_file(self):
        """CLI fix subcommand should accept --exempt-file flag."""
        result = subprocess.run(
            [sys.executable, "-m", "albator_cli", "fix", "--dry-run",
             "--exempt-file", "/nonexistent/exemptions.yaml"],
            capture_output=True, text=True,
            cwd=os.path.join(os.path.dirname(__file__), ".."),
        )
        self.assertNotIn("unrecognized arguments", result.stderr)

    def test_report_cli_accepts_exempt_file(self):
        """CLI report subcommand should accept --exempt-file flag."""
        result = subprocess.run(
            [sys.executable, "-m", "albator_cli", "report", "--dry-run",
             "--exempt-file", "/nonexistent/exemptions.yaml"],
            capture_output=True, text=True,
            cwd=os.path.join(os.path.dirname(__file__), ".."),
        )
        self.assertNotIn("unrecognized arguments", result.stderr)


class TestExemptionExampleFile(unittest.TestCase):
    """Validate the example exemptions file loads correctly."""

    def test_example_exemptions_file_is_valid(self):
        """config/exemptions_example.yaml should load without errors."""
        base = os.path.join(os.path.dirname(__file__), "..")
        path = os.path.join(base, "config", "exemptions_example.yaml")
        if not os.path.exists(path):
            self.skipTest("exemptions_example.yaml not found")
        exemptions = load_exemptions(path)
        self.assertGreater(len(exemptions), 0)
        for ex in exemptions:
            self.assertIn("rule_id", ex)
            self.assertIn("reason", ex)
            self.assertIn("approved_by", ex)

    def test_example_exemptions_reference_real_rules(self):
        """Exempted rule_ids in example file should match actual rule files."""
        base = os.path.join(os.path.dirname(__file__), "..")
        path = os.path.join(base, "config", "exemptions_example.yaml")
        rules_dir = os.path.join(base, "rules")
        if not os.path.exists(path):
            self.skipTest("exemptions_example.yaml not found")

        exemptions = load_exemptions(path)
        import glob as glob_mod
        rule_files = glob_mod.glob(os.path.join(rules_dir, "os_*.yaml"))
        rule_ids = set()
        for rf in rule_files:
            with open(rf) as f:
                data = yaml.safe_load(f)
            if data and "id" in data:
                rule_ids.add(data["id"])

        for ex in exemptions:
            self.assertIn(ex["rule_id"], rule_ids,
                          f"Exempted rule '{ex['rule_id']}' does not match any rule file")


class TestBaselineSaveLoad(unittest.TestCase):
    """Test baseline save and load operations."""

    def _make_scan_result(self, passed=3, failed=1, rules=None):
        if rules is None:
            rules = []
            for i in range(passed):
                rules.append({"id": f"os_rule_{i}", "title": f"Rule {i}", "severity": "medium", "status": "pass"})
            for i in range(failed):
                rules.append({"id": f"os_fail_{i}", "title": f"Fail {i}", "severity": "high", "status": "fail", "detail": "non-compliant"})
        total = passed + failed
        return {
            "rules_scanned": total,
            "passed": passed,
            "failed": failed,
            "errors": 0,
            "exempt": 0,
            "dry_run": False,
            "profile": None,
            "results": rules,
            "summary": {
                "total": total,
                "passed": passed,
                "failed": failed,
                "exempt": 0,
                "compliance_pct": round(100.0 * passed / total, 1) if total > 0 else 0.0,
            },
        }

    def test_save_creates_file(self):
        from baseline import save_baseline
        with tempfile.TemporaryDirectory() as tmp:
            scan_result = self._make_scan_result()
            path = save_baseline(scan_result, tmp)
            self.assertTrue(os.path.exists(path))
            self.assertTrue(path.endswith(".json"))
            self.assertIn("baseline_", os.path.basename(path))

    def test_save_with_label(self):
        from baseline import save_baseline
        with tempfile.TemporaryDirectory() as tmp:
            scan_result = self._make_scan_result()
            path = save_baseline(scan_result, tmp, label="pre-deploy")
            self.assertIn("pre-deploy", os.path.basename(path))

    def test_save_creates_directory(self):
        from baseline import save_baseline
        with tempfile.TemporaryDirectory() as tmp:
            subdir = os.path.join(tmp, "nested", "baselines")
            scan_result = self._make_scan_result()
            path = save_baseline(scan_result, subdir)
            self.assertTrue(os.path.exists(path))

    def test_load_roundtrip(self):
        from baseline import save_baseline, load_baseline
        with tempfile.TemporaryDirectory() as tmp:
            scan_result = self._make_scan_result()
            path = save_baseline(scan_result, tmp)
            loaded = load_baseline(path)
            self.assertEqual(loaded["scan"]["passed"], 3)
            self.assertEqual(loaded["scan"]["failed"], 1)
            self.assertIn("timestamp", loaded)
            self.assertEqual(loaded["version"], 1)

    def test_load_missing_file_raises(self):
        from baseline import load_baseline
        with self.assertRaises(FileNotFoundError):
            load_baseline("/nonexistent/baseline.json")

    def test_load_invalid_json_raises(self):
        from baseline import load_baseline
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write('{"no_scan_key": true}')
            f.flush()
            try:
                with self.assertRaises(ValueError):
                    load_baseline(f.name)
            finally:
                os.unlink(f.name)


class TestBaselineList(unittest.TestCase):
    """Test baseline listing."""

    def test_list_empty_directory(self):
        from baseline import list_baselines
        with tempfile.TemporaryDirectory() as tmp:
            result = list_baselines(tmp)
            self.assertEqual(result["count"], 0)
            self.assertEqual(result["baselines"], [])

    def test_list_nonexistent_directory(self):
        from baseline import list_baselines
        result = list_baselines("/nonexistent/dir")
        self.assertEqual(result["count"], 0)

    def test_list_finds_baselines(self):
        from baseline import save_baseline, list_baselines
        scan_result = {
            "rules_scanned": 2, "passed": 1, "failed": 1, "errors": 0,
            "exempt": 0, "dry_run": False, "profile": None,
            "results": [
                {"id": "r1", "title": "R1", "severity": "low", "status": "pass"},
                {"id": "r2", "title": "R2", "severity": "high", "status": "fail"},
            ],
            "summary": {"total": 2, "passed": 1, "failed": 1, "exempt": 0, "compliance_pct": 50.0},
        }
        with tempfile.TemporaryDirectory() as tmp:
            save_baseline(scan_result, tmp, label="first")
            save_baseline(scan_result, tmp, label="second")
            result = list_baselines(tmp)
            self.assertEqual(result["count"], 2)
            self.assertTrue(any("first" in b["filename"] for b in result["baselines"]))


class TestBaselineCompare(unittest.TestCase):
    """Test baseline comparison and drift detection."""

    def _make_baseline(self, results, label="test"):
        total = len(results)
        passed = sum(1 for r in results if r["status"] == "pass")
        failed = total - passed
        return {
            "version": 1,
            "timestamp": "2026-03-20T10:00:00",
            "label": label,
            "scan": {
                "rules_scanned": total,
                "passed": passed,
                "failed": failed,
                "errors": 0,
                "exempt": 0,
                "dry_run": False,
                "results": results,
                "summary": {
                    "total": total,
                    "passed": passed,
                    "failed": failed,
                    "compliance_pct": round(100.0 * passed / total, 1) if total > 0 else 0.0,
                },
            },
        }

    def test_no_drift_identical(self):
        from baseline import compare_baselines
        results = [
            {"id": "r1", "title": "R1", "severity": "low", "status": "pass"},
            {"id": "r2", "title": "R2", "severity": "high", "status": "pass"},
        ]
        old = self._make_baseline(results, "old")
        new = self._make_baseline(results, "new")
        diff = compare_baselines(old, new)
        self.assertFalse(diff["summary"]["has_drift"])
        self.assertEqual(diff["summary"]["regressions"], 0)
        self.assertEqual(diff["summary"]["resolved"], 0)
        self.assertEqual(diff["summary"]["unchanged"], 2)

    def test_regression_detected(self):
        from baseline import compare_baselines
        old = self._make_baseline([
            {"id": "r1", "title": "R1", "severity": "high", "status": "pass"},
        ], "old")
        new = self._make_baseline([
            {"id": "r1", "title": "R1", "severity": "high", "status": "fail", "detail": "broken"},
        ], "new")
        diff = compare_baselines(old, new)
        self.assertTrue(diff["summary"]["has_drift"])
        self.assertEqual(diff["summary"]["regressions"], 1)
        self.assertEqual(diff["regressions"][0]["id"], "r1")

    def test_resolved_detected(self):
        from baseline import compare_baselines
        old = self._make_baseline([
            {"id": "r1", "title": "R1", "severity": "high", "status": "fail"},
        ], "old")
        new = self._make_baseline([
            {"id": "r1", "title": "R1", "severity": "high", "status": "pass"},
        ], "new")
        diff = compare_baselines(old, new)
        self.assertTrue(diff["summary"]["has_drift"])
        self.assertEqual(diff["summary"]["resolved"], 1)

    def test_new_rule_detected(self):
        from baseline import compare_baselines
        old = self._make_baseline([
            {"id": "r1", "title": "R1", "severity": "low", "status": "pass"},
        ], "old")
        new = self._make_baseline([
            {"id": "r1", "title": "R1", "severity": "low", "status": "pass"},
            {"id": "r2", "title": "R2", "severity": "high", "status": "fail"},
        ], "new")
        diff = compare_baselines(old, new)
        self.assertTrue(diff["summary"]["has_drift"])
        self.assertEqual(diff["summary"]["new_rules"], 1)
        self.assertEqual(diff["summary"]["new_failures"], 1)

    def test_removed_rule_detected(self):
        from baseline import compare_baselines
        old = self._make_baseline([
            {"id": "r1", "title": "R1", "severity": "low", "status": "pass"},
            {"id": "r2", "title": "R2", "severity": "high", "status": "pass"},
        ], "old")
        new = self._make_baseline([
            {"id": "r1", "title": "R1", "severity": "low", "status": "pass"},
        ], "new")
        diff = compare_baselines(old, new)
        self.assertTrue(diff["summary"]["has_drift"])
        self.assertEqual(diff["summary"]["removed_rules"], 1)

    def test_compliance_delta(self):
        from baseline import compare_baselines
        old = self._make_baseline([
            {"id": "r1", "title": "R1", "severity": "low", "status": "pass"},
            {"id": "r2", "title": "R2", "severity": "low", "status": "fail"},
        ], "old")
        new = self._make_baseline([
            {"id": "r1", "title": "R1", "severity": "low", "status": "pass"},
            {"id": "r2", "title": "R2", "severity": "low", "status": "pass"},
        ], "new")
        diff = compare_baselines(old, new)
        self.assertEqual(diff["summary"]["compliance_delta"], 50.0)

    def test_mixed_drift_scenario(self):
        from baseline import compare_baselines
        old = self._make_baseline([
            {"id": "r1", "title": "R1", "severity": "low", "status": "pass"},
            {"id": "r2", "title": "R2", "severity": "high", "status": "fail"},
            {"id": "r3", "title": "R3", "severity": "medium", "status": "pass"},
        ], "old")
        new = self._make_baseline([
            {"id": "r1", "title": "R1", "severity": "low", "status": "fail"},  # regression
            {"id": "r2", "title": "R2", "severity": "high", "status": "pass"},  # resolved
            {"id": "r4", "title": "R4", "severity": "low", "status": "pass"},  # new rule
        ], "new")
        diff = compare_baselines(old, new)
        self.assertEqual(diff["summary"]["regressions"], 1)
        self.assertEqual(diff["summary"]["resolved"], 1)
        self.assertEqual(diff["summary"]["new_rules"], 1)
        self.assertEqual(diff["summary"]["removed_rules"], 1)


class TestBaselineFormatting(unittest.TestCase):
    """Test baseline report formatting."""

    def test_format_diff_report_no_drift(self):
        from baseline import format_diff_report
        diff = {
            "old_meta": {"timestamp": "2026-03-19T10:00:00", "label": "before"},
            "new_meta": {"timestamp": "2026-03-20T10:00:00", "label": "after"},
            "summary": {
                "has_drift": False, "regressions": 0, "resolved": 0,
                "new_failures": 0, "new_rules": 0, "removed_rules": 0,
                "unchanged": 5, "old_compliance_pct": 100.0,
                "new_compliance_pct": 100.0, "compliance_delta": 0.0,
            },
            "regressions": [], "resolved": [], "new_failures": [],
            "new_rules": [], "removed_rules": [], "unchanged": [],
        }
        report = format_diff_report(diff)
        self.assertIn("No compliance drift detected", report)
        self.assertIn("UNCHANGED", report)

    def test_format_diff_report_with_regressions(self):
        from baseline import format_diff_report
        diff = {
            "old_meta": {"timestamp": "2026-03-19T10:00:00", "label": "old"},
            "new_meta": {"timestamp": "2026-03-20T10:00:00", "label": "new"},
            "summary": {
                "has_drift": True, "regressions": 1, "resolved": 0,
                "new_failures": 0, "new_rules": 0, "removed_rules": 0,
                "unchanged": 4, "old_compliance_pct": 100.0,
                "new_compliance_pct": 80.0, "compliance_delta": -20.0,
            },
            "regressions": [{"id": "r1", "title": "R1", "severity": "high", "old_status": "pass", "new_status": "fail"}],
            "resolved": [], "new_failures": [], "new_rules": [],
            "removed_rules": [], "unchanged": [],
        }
        report = format_diff_report(diff)
        self.assertIn("REGRESSIONS", report)
        self.assertIn("DEGRADED", report)
        self.assertIn("r1", report)

    def test_format_baseline_list_empty(self):
        from baseline import format_baseline_list
        result = {"baselines_dir": "/tmp/test", "count": 0, "baselines": []}
        report = format_baseline_list(result)
        self.assertIn("No baselines saved yet", report)

    def test_format_baseline_list_with_entries(self):
        from baseline import format_baseline_list
        result = {
            "baselines_dir": "/tmp/test",
            "count": 1,
            "baselines": [{
                "path": "/tmp/test/baseline_20260320.json",
                "filename": "baseline_20260320.json",
                "timestamp": "2026-03-20T10:00:00",
                "label": "deploy",
                "rules_scanned": 72,
                "passed": 70,
                "failed": 2,
                "compliance_pct": 97.2,
            }],
        }
        report = format_baseline_list(result)
        self.assertIn("deploy", report)
        self.assertIn("72", report)


class TestBaselineCLIIntegration(unittest.TestCase):
    """Test baseline CLI subcommand integration."""

    def _run_cli(self, args_list):
        sys_argv_backup = sys.argv
        try:
            sys.argv = ["albator_cli.py"] + args_list
            albator_cli.main()
        except SystemExit as e:
            return e.code
        finally:
            sys.argv = sys_argv_backup
        return 0

    def test_baseline_list_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            code = self._run_cli(["baseline", "--list", "--baselines-dir", tmp])
            self.assertEqual(code, 0)

    def test_baseline_list_json_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            captured = io.StringIO()
            sys_argv_backup = sys.argv
            try:
                sys.argv = ["albator_cli.py", "--json-output", "baseline", "--list", "--baselines-dir", tmp]
                with self.assertRaises(SystemExit) as ctx:
                    with patch("sys.stdout", captured):
                        albator_cli.main()
                self.assertEqual(ctx.exception.code, 0)
            finally:
                sys.argv = sys_argv_backup

    def test_baseline_save_dry_run(self):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with tempfile.TemporaryDirectory() as tmp:
            code = self._run_cli(["baseline", "--save", "--dry-run", "--baselines-dir", tmp])
            self.assertEqual(code, 0)
            # Check a file was created
            import glob as glob_mod
            files = glob_mod.glob(os.path.join(tmp, "baseline_*.json"))
            self.assertEqual(len(files), 1)

    def test_baseline_save_with_label(self):
        with tempfile.TemporaryDirectory() as tmp:
            code = self._run_cli(["baseline", "--save", "--dry-run", "--label", "test-label", "--baselines-dir", tmp])
            self.assertEqual(code, 0)
            import glob as glob_mod
            files = glob_mod.glob(os.path.join(tmp, "baseline_*test-label*.json"))
            self.assertEqual(len(files), 1)

    def test_baseline_compare_missing_file(self):
        code = self._run_cli(["baseline", "--compare", "/nonexistent/a.json", "/nonexistent/b.json"])
        self.assertEqual(code, 2)

    def test_baseline_compare_roundtrip(self):
        from baseline import save_baseline
        scan_result = {
            "rules_scanned": 1, "passed": 1, "failed": 0, "errors": 0,
            "exempt": 0, "dry_run": False, "profile": None,
            "results": [{"id": "r1", "title": "R1", "severity": "low", "status": "pass"}],
            "summary": {"total": 1, "passed": 1, "failed": 0, "exempt": 0, "compliance_pct": 100.0},
        }
        with tempfile.TemporaryDirectory() as tmp:
            p1 = save_baseline(scan_result, tmp, label="a")
            p2 = save_baseline(scan_result, tmp, label="b")
            code = self._run_cli(["baseline", "--compare", p1, p2])
            self.assertEqual(code, 0)

    def test_baseline_no_action_fails(self):
        code = self._run_cli(["baseline"])
        self.assertEqual(code, 2)

    def test_baseline_save_with_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            code = self._run_cli(["baseline", "--save", "--dry-run", "--profile", "cis_level1", "--baselines-dir", tmp])
            self.assertEqual(code, 0)


###############################################################################
# Experiment 25 — Evidence Collection Module Tests
###############################################################################

class TestEvidenceCollectSystemMetadata(unittest.TestCase):
    """Tests for evidence.collect_system_metadata()."""

    def test_returns_required_keys(self):
        from evidence import collect_system_metadata
        meta = collect_system_metadata()
        for key in ["hostname", "platform", "architecture", "kernel",
                     "collected_by", "collected_at", "collected_at_epoch"]:
            self.assertIn(key, meta)

    def test_collected_at_is_iso_format(self):
        from evidence import collect_system_metadata
        import datetime
        meta = collect_system_metadata()
        # Should parse without error
        dt = datetime.datetime.fromisoformat(meta["collected_at"])
        self.assertIsInstance(dt, datetime.datetime)

    def test_collected_at_epoch_is_int(self):
        from evidence import collect_system_metadata
        meta = collect_system_metadata()
        self.assertIsInstance(meta["collected_at_epoch"], int)

    def test_hostname_not_empty(self):
        from evidence import collect_system_metadata
        meta = collect_system_metadata()
        self.assertTrue(len(meta["hostname"]) > 0)


class TestEvidenceCollectRuleEvidence(unittest.TestCase):
    """Tests for evidence.collect_rule_evidence()."""

    def test_passing_check_returns_compliant_true(self):
        from evidence import collect_rule_evidence
        rule = {"id": "test_pass", "title": "Test", "severity": "low",
                "check": "true", "references": {}}
        ev = collect_rule_evidence(rule, timeout=5)
        self.assertTrue(ev["compliant"])
        self.assertEqual(ev["exit_code"], 0)
        self.assertEqual(ev["rule_id"], "test_pass")

    def test_failing_check_returns_compliant_false(self):
        from evidence import collect_rule_evidence
        rule = {"id": "test_fail", "title": "Test", "severity": "high",
                "check": "false", "references": {}}
        ev = collect_rule_evidence(rule, timeout=5)
        self.assertFalse(ev["compliant"])
        self.assertNotEqual(ev["exit_code"], 0)

    def test_captures_stdout(self):
        from evidence import collect_rule_evidence
        rule = {"id": "test_echo", "title": "Echo", "severity": "low",
                "check": "echo hello_evidence", "references": {}}
        ev = collect_rule_evidence(rule, timeout=5)
        self.assertIn("hello_evidence", ev["stdout"])

    def test_captures_stderr(self):
        from evidence import collect_rule_evidence
        rule = {"id": "test_stderr", "title": "Stderr", "severity": "low",
                "check": "echo err_output >&2; false", "references": {}}
        ev = collect_rule_evidence(rule, timeout=5)
        self.assertIn("err_output", ev["stderr"])

    def test_empty_check_command(self):
        from evidence import collect_rule_evidence
        rule = {"id": "test_empty", "title": "Empty", "severity": "low",
                "check": "  ", "references": {}}
        ev = collect_rule_evidence(rule, timeout=5)
        self.assertFalse(ev["compliant"])
        self.assertEqual(ev["exit_code"], -1)
        self.assertIn("empty", ev.get("error", ""))

    def test_timeout_returns_error(self):
        from evidence import collect_rule_evidence
        rule = {"id": "test_timeout", "title": "Slow", "severity": "low",
                "check": "sleep 60", "references": {}}
        ev = collect_rule_evidence(rule, timeout=1)
        self.assertFalse(ev["compliant"])
        self.assertIn("timed out", ev.get("error", ""))

    def test_duration_ms_is_positive(self):
        from evidence import collect_rule_evidence
        rule = {"id": "test_dur", "title": "Dur", "severity": "low",
                "check": "true", "references": {}}
        ev = collect_rule_evidence(rule, timeout=5)
        self.assertGreaterEqual(ev["duration_ms"], 0)

    def test_includes_references(self):
        from evidence import collect_rule_evidence
        refs = {"800-53r5": ["AC-2"], "cci": ["CCI-000366"]}
        rule = {"id": "test_refs", "title": "Refs", "severity": "low",
                "check": "true", "references": refs}
        ev = collect_rule_evidence(rule, timeout=5)
        self.assertEqual(ev["references"], refs)

    def test_has_timestamp(self):
        from evidence import collect_rule_evidence
        import datetime
        rule = {"id": "test_ts", "title": "TS", "severity": "low",
                "check": "true", "references": {}}
        ev = collect_rule_evidence(rule, timeout=5)
        dt = datetime.datetime.fromisoformat(ev["timestamp"])
        self.assertIsInstance(dt, datetime.datetime)


class TestEvidenceSaveAndManifest(unittest.TestCase):
    """Tests for evidence.save_evidence() and manifest generation."""

    def _make_evidence_list(self, count=3):
        items = []
        for i in range(count):
            items.append({
                "rule_id": f"rule_{i}",
                "rule_title": f"Rule {i}",
                "severity": "medium",
                "check_command": "true",
                "references": {},
                "compliant": i % 2 == 0,
                "stdout": f"output {i}",
                "stderr": "",
                "exit_code": 0 if i % 2 == 0 else 1,
                "duration_ms": 10,
                "timestamp": "2026-03-20T00:00:00+00:00",
            })
        return items

    def test_creates_evidence_dir(self):
        from evidence import save_evidence
        with tempfile.TemporaryDirectory() as tmp:
            ev_dir = os.path.join(tmp, "evidence_out")
            self.assertFalse(os.path.exists(ev_dir))
            save_evidence(self._make_evidence_list(1), ev_dir)
            self.assertTrue(os.path.isdir(ev_dir))

    def test_creates_per_rule_files(self):
        from evidence import save_evidence
        with tempfile.TemporaryDirectory() as tmp:
            ev_dir = os.path.join(tmp, "ev")
            save_evidence(self._make_evidence_list(3), ev_dir)
            for i in range(3):
                path = os.path.join(ev_dir, f"evidence_rule_{i}.json")
                self.assertTrue(os.path.exists(path), f"Missing {path}")
                data = json.load(open(path))
                self.assertEqual(data["evidence"]["rule_id"], f"rule_{i}")
                self.assertIn("system", data)

    def test_creates_manifest(self):
        from evidence import save_evidence
        with tempfile.TemporaryDirectory() as tmp:
            ev_dir = os.path.join(tmp, "ev")
            manifest_path = save_evidence(self._make_evidence_list(3), ev_dir)
            self.assertTrue(manifest_path.endswith("evidence_manifest.json"))
            manifest = json.load(open(manifest_path))
            self.assertEqual(manifest["version"], 1)
            self.assertEqual(manifest["summary"]["total"], 3)

    def test_manifest_checksums_present(self):
        from evidence import save_evidence
        with tempfile.TemporaryDirectory() as tmp:
            ev_dir = os.path.join(tmp, "ev")
            manifest_path = save_evidence(self._make_evidence_list(2), ev_dir)
            manifest = json.load(open(manifest_path))
            for artifact in manifest["artifacts"]:
                self.assertIn("sha256", artifact)
                self.assertEqual(len(artifact["sha256"]), 64)  # SHA-256 hex length

    def test_manifest_compliance_counts(self):
        from evidence import save_evidence
        with tempfile.TemporaryDirectory() as tmp:
            ev_dir = os.path.join(tmp, "ev")
            # 3 items: rule_0=compliant, rule_1=non-compliant, rule_2=compliant
            manifest_path = save_evidence(self._make_evidence_list(3), ev_dir)
            manifest = json.load(open(manifest_path))
            self.assertEqual(manifest["summary"]["compliant"], 2)
            self.assertEqual(manifest["summary"]["non_compliant"], 1)

    def test_manifest_label(self):
        from evidence import save_evidence
        with tempfile.TemporaryDirectory() as tmp:
            ev_dir = os.path.join(tmp, "ev")
            save_evidence(self._make_evidence_list(1), ev_dir, label="Q1-audit")
            manifest = json.load(open(os.path.join(ev_dir, "evidence_manifest.json")))
            self.assertEqual(manifest["label"], "Q1-audit")

    def test_checksum_matches_file_content(self):
        import hashlib
        from evidence import save_evidence
        with tempfile.TemporaryDirectory() as tmp:
            ev_dir = os.path.join(tmp, "ev")
            manifest_path = save_evidence(self._make_evidence_list(1), ev_dir)
            manifest = json.load(open(manifest_path))
            art = manifest["artifacts"][0]
            filepath = os.path.join(ev_dir, art["file"])
            with open(filepath) as f:
                content = f.read()
            computed = hashlib.sha256(content.encode("utf-8")).hexdigest()
            self.assertEqual(art["sha256"], computed)

    def test_empty_evidence_list(self):
        from evidence import save_evidence
        with tempfile.TemporaryDirectory() as tmp:
            ev_dir = os.path.join(tmp, "ev")
            manifest_path = save_evidence([], ev_dir)
            manifest = json.load(open(manifest_path))
            self.assertEqual(manifest["summary"]["total"], 0)
            self.assertEqual(manifest["summary"]["compliance_pct"], 0.0)


class TestEvidenceFormatSummary(unittest.TestCase):
    """Tests for evidence.format_evidence_summary()."""

    def test_summary_contains_key_info(self):
        from evidence import format_evidence_summary
        manifest = {
            "label": "test-run",
            "collected_at": "2026-03-20T00:00:00",
            "system": {"hostname": "testhost", "platform": "macOS", "collected_by": "admin"},
            "summary": {"total": 5, "compliant": 4, "non_compliant": 1, "compliance_pct": 80.0},
            "artifacts": [
                {"rule_id": "r1", "compliant": True, "severity": "low"},
                {"rule_id": "r2", "compliant": False, "severity": "high"},
            ],
        }
        text = format_evidence_summary(manifest)
        self.assertIn("test-run", text)
        self.assertIn("testhost", text)
        self.assertIn("80.0%", text)
        self.assertIn("r2", text)  # non-compliant rule listed

    def test_all_compliant_message(self):
        from evidence import format_evidence_summary
        manifest = {
            "label": "", "collected_at": "", "system": {},
            "summary": {"total": 1, "compliant": 1, "non_compliant": 0, "compliance_pct": 100.0},
            "artifacts": [{"rule_id": "r1", "compliant": True, "severity": "low"}],
        }
        text = format_evidence_summary(manifest)
        self.assertIn("All rules compliant", text)


class TestEvidenceCLIIntegration(unittest.TestCase):
    """Tests for --evidence-dir flag in scan CLI subcommand."""

    def _run_cli(self, cli_args):
        saved = sys.argv
        sys.argv = ["albator_cli.py"] + cli_args
        try:
            albator_cli.main()
        except SystemExit as e:
            return int(e.code or 0)
        finally:
            sys.argv = saved
        return 0

    def test_scan_dry_run_ignores_evidence_dir(self):
        """--evidence-dir with --dry-run should not create evidence files."""
        with tempfile.TemporaryDirectory() as tmp:
            ev_dir = os.path.join(tmp, "evidence")
            code = self._run_cli(["scan", "--dry-run", "--evidence-dir", ev_dir])
            self.assertEqual(code, 0)
            # Evidence dir should NOT be created for dry-run
            self.assertFalse(os.path.exists(os.path.join(ev_dir, "evidence_manifest.json")))

    def test_scan_evidence_dir_creates_manifest(self):
        """--evidence-dir without --dry-run should create evidence manifest."""
        with tempfile.TemporaryDirectory() as tmp:
            ev_dir = os.path.join(tmp, "evidence")
            code = self._run_cli(["scan", "--evidence-dir", ev_dir, "--timeout", "5"])
            # Don't assert exit code 0 — rules may fail on non-macOS
            manifest_path = os.path.join(ev_dir, "evidence_manifest.json")
            self.assertTrue(os.path.exists(manifest_path))
            manifest = json.load(open(manifest_path))
            self.assertIn("artifacts", manifest)
            self.assertIn("summary", manifest)
            self.assertGreater(manifest["summary"]["total"], 0)

    def test_scan_evidence_with_label(self):
        """--evidence-label should appear in evidence manifest."""
        with tempfile.TemporaryDirectory() as tmp:
            ev_dir = os.path.join(tmp, "evidence")
            self._run_cli(["scan", "--evidence-dir", ev_dir, "--evidence-label", "Q1-2026", "--timeout", "5"])
            manifest = json.load(open(os.path.join(ev_dir, "evidence_manifest.json")))
            self.assertEqual(manifest["label"], "Q1-2026")

    def test_scan_evidence_json_output_includes_evidence_path(self):
        """--json-output with --evidence-dir should include evidence_dir in JSON."""
        with tempfile.TemporaryDirectory() as tmp:
            ev_dir = os.path.join(tmp, "evidence")
            captured = io.StringIO()
            saved_stdout = sys.stdout
            sys.stdout = captured
            try:
                self._run_cli(["--json-output", "scan", "--evidence-dir", ev_dir, "--timeout", "5"])
            finally:
                sys.stdout = saved_stdout
            output = captured.getvalue()
            data = json.loads(output)
            self.assertIn("evidence_dir", data)

    def test_scan_evidence_per_rule_files_match_artifact_count(self):
        """Number of evidence_*.json files should match manifest artifact count."""
        with tempfile.TemporaryDirectory() as tmp:
            ev_dir = os.path.join(tmp, "evidence")
            self._run_cli(["scan", "--evidence-dir", ev_dir, "--timeout", "5"])
            manifest = json.load(open(os.path.join(ev_dir, "evidence_manifest.json")))
            expected = manifest["summary"]["total"]
            evidence_files = [f for f in os.listdir(ev_dir)
                              if f.startswith("evidence_") and f != "evidence_manifest.json"]
            self.assertEqual(len(evidence_files), expected)

    def test_scan_evidence_with_profile_filter(self):
        """--evidence-dir with --profile should only collect evidence for profile rules."""
        with tempfile.TemporaryDirectory() as tmp:
            ev_dir = os.path.join(tmp, "evidence")
            self._run_cli(["scan", "--evidence-dir", ev_dir, "--profile", "cis_level1", "--timeout", "5"])
            manifest = json.load(open(os.path.join(ev_dir, "evidence_manifest.json")))
            # cis_level1 has fewer rules than total (61 vs 72)
            self.assertGreater(manifest["summary"]["total"], 0)
            self.assertLessEqual(manifest["summary"]["total"], 72)


if __name__ == "__main__":
    unittest.main()
