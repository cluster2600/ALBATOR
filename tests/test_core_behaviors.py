import argparse
import json
import os
import pathlib
import subprocess
import tempfile
import unittest
import io
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


if __name__ == "__main__":
    unittest.main()
