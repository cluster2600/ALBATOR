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


if __name__ == "__main__":
    unittest.main()
