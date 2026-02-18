import argparse
import os
import pathlib
import subprocess
import tempfile
import unittest
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


if __name__ == "__main__":
    unittest.main()
