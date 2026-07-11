import argparse
import importlib.util
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("configure-rules.py")
SPEC = importlib.util.spec_from_file_location("configure_rules", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
import sys
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class RuleConfigurationTests(unittest.TestCase):
    def arguments(self, **overrides):
        values = {
            "group_name": "browser_navigation,phishing_detection",
            "preferred_start": 100300,
            "navigation_level": 5,
            "classification_base_level": 0,
            "phishtank_level": 10,
            "ml_level": 9,
            "error_level": 5,
            "negative_level": 0,
        }
        values.update({role: None for role in MODULE.RULE_ROLES})
        values.update(overrides)
        return argparse.Namespace(**values)

    def test_ignores_commented_rule_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            rules = home / "etc" / "rules"
            rules.mkdir(parents=True)
            (rules / "local_rules.xml").write_text(
                '<group name="x,"><!-- <rule id="100300" level="3"></rule> -->'
                '<rule id="100301" level="3"></rule></group>',
                encoding="utf-8",
            )
            used, _ = MODULE.scan_used_ids(home)
        self.assertNotIn(100300, used)
        self.assertIn(100301, used)

    def test_prefers_contiguous_range_from_100300(self):
        allocated = MODULE.allocate_ids(self.arguments(), set(), {})
        self.assertEqual(list(allocated.values()), list(range(100300, 100306)))

    def test_moves_to_next_free_contiguous_range(self):
        allocated = MODULE.allocate_ids(self.arguments(), {100302}, {100302: Path("rules.xml")})
        self.assertEqual(list(allocated.values()), list(range(100303, 100309)))

    def test_preserves_original_severity_defaults(self):
        args = self.arguments()
        policy = MODULE.make_policy(args, MODULE.allocate_ids(args, set(), {}))
        xml = MODULE.generate_xml(policy)
        self.assertIn('<rule id="100300" level="5">', xml)
        self.assertIn('<rule id="100302" level="10">', xml)
        self.assertIn('<rule id="100303" level="9">', xml)
        self.assertIn('<rule id="100305" level="0">', xml)

    def test_rejects_explicit_collision(self):
        args = self.arguments(navigation_rule_id=100300)
        with self.assertRaisesRegex(ValueError, "conflicts"):
            MODULE.allocate_ids(args, {100300}, {100300: Path("local_rules.xml")})

    def test_accepts_comma_separated_wazuh_groups(self):
        args = self.arguments(group_name="browser_navigation,phishing")
        allocated = MODULE.allocate_ids(args, set(), {})
        policy = MODULE.make_policy(args, allocated)
        root = ET.fromstring(MODULE.generate_xml(policy))
        self.assertEqual(root.attrib["name"], "browser_navigation,phishing,")

    def test_reuses_installed_policy_without_overriding_cli_options(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            manifest = home / "etc" / "edge-phishing-rule-policy.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_text(
                '{"group_name":"installed_group","navigation_rule_id":100302,'
                '"navigation_level":5,"classification_base_rule_id":100310,'
                '"classification_base_level":0,"phishtank_rule_id":100311,'
                '"phishtank_level":10,"ml_rule_id":100312,"ml_level":9,'
                '"error_rule_id":100313,"error_level":5,'
                '"negative_rule_id":100314,"negative_level":0}',
                encoding="utf-8",
            )
            args = self.arguments(group_name="cli_group")
            MODULE.apply_installed_policy_defaults(args, home, ["--group-name", "cli_group"])
        self.assertEqual(args.group_name, "cli_group")
        self.assertEqual(args.navigation_rule_id, 100302)
        self.assertEqual(args.phishtank_rule_id, 100311)


if __name__ == "__main__":
    unittest.main()
