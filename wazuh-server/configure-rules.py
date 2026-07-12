#!/usr/bin/env python3
"""Generate or install configurable Wazuh Edge phishing pipeline rules."""

from __future__ import annotations

import argparse
import grp
import html
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, fields
from pathlib import Path


CUSTOM_MIN = 100000
CUSTOM_MAX = 120000
GROUP_RE = re.compile(r"^[A-Za-z0-9_.-]+(?:,[A-Za-z0-9_.-]+)*,?$")
RULE_RE = re.compile(r'<rule\s+id=["\'](\d+)["\']')
COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
MANAGED_FILES = {
    "edge_navigation_rules.xml",
    "edge_phishing_classification_rules.xml",
    "edge_phishing_pipeline_rules.xml",
}


@dataclass
class Policy:
    group_name: str = "browser_navigation,phishing_detection"
    reputation_provider: str = "phishtank"
    navigation_rule_id: int = 0
    navigation_level: int = 5
    classification_base_rule_id: int = 0
    classification_base_level: int = 0
    phishtank_rule_id: int = 0
    phishtank_level: int = 10
    ml_rule_id: int = 0
    ml_level: int = 9
    review_rule_id: int = 0
    review_level: int = 7
    error_rule_id: int = 0
    error_level: int = 5
    negative_rule_id: int = 0
    negative_level: int = 0


RULE_ROLES = [
    "navigation_rule_id",
    "classification_base_rule_id",
    "phishtank_rule_id",
    "ml_rule_id",
    "error_rule_id",
    "negative_rule_id",
    "review_rule_id",
]


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    result.add_argument("--wizard", action="store_true", help="prompt for group, IDs, and levels")
    result.add_argument("--install", action="store_true", help="install, validate, and restart Wazuh")
    result.add_argument("--wazuh-home", default="/var/ossec")
    result.add_argument("--output", type=Path, help="write generated XML here")
    result.add_argument(
        "--group-name", default="browser_navigation,phishing_detection",
        help="comma-separated Wazuh group names",
    )
    result.add_argument("--preferred-start", type=int, default=100300, help="first ID considered for automatic allocation")
    result.add_argument(
        "--reputation-provider", choices=("phishtank", "google-webrisk"), default="phishtank",
        help="the one reputation provider whose confirmed-phishing rule is enabled",
    )
    for role in RULE_ROLES:
        result.add_argument(
            "--" + role.replace("_", "-"), type=int,
            help="explicit custom rule ID; omitted IDs are allocated automatically",
        )
    result.add_argument(
        "--reputation-rule-id", dest="phishtank_rule_id", type=int, default=argparse.SUPPRESS,
        help="provider-neutral alias for --phishtank-rule-id",
    )
    result.add_argument("--navigation-level", type=int, default=5, help="Edge URL-observed alert level")
    result.add_argument("--classification-base-level", type=int, default=0, help="classification parent level")
    result.add_argument("--phishtank-level", type=int, default=10, help="verified PhishTank alert level")
    result.add_argument(
        "--reputation-level", dest="phishtank_level", type=int, default=argparse.SUPPRESS,
        help="provider-neutral alias for --phishtank-level",
    )
    result.add_argument("--ml-level", type=int, default=9, help="ML-suspicious alert level")
    result.add_argument("--review-level", type=int, default=7, help="ML review-band alert level")
    result.add_argument("--error-level", type=int, default=5, help="classifier failure alert level")
    result.add_argument("--negative-level", type=int, default=0, help="negative/unknown result level")
    result.add_argument("-v", "--verbose", action="store_true")
    return result


def scan_used_ids(home: Path) -> tuple[set[int], dict[int, Path]]:
    used: set[int] = set()
    locations: dict[int, Path] = {}
    for directory in (home / "etc" / "rules", home / "ruleset" / "rules"):
        if not directory.is_dir():
            continue
        for path in directory.glob("*.xml"):
            if path.name in MANAGED_FILES:
                continue
            try:
                content = COMMENT_RE.sub("", path.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue
            for match in RULE_RE.finditer(content):
                rule_id = int(match.group(1))
                used.add(rule_id)
                locations.setdefault(rule_id, path)
    return used, locations


def apply_installed_policy_defaults(
    args: argparse.Namespace, home: Path, command_line: list[str]
) -> None:
    manifest = home / "etc" / "edge-phishing-rule-policy.json"
    if not manifest.exists() or "--preferred-start" in command_line:
        return
    try:
        installed = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"installed rule policy cannot be read: {manifest}") from exc
    if not isinstance(installed, dict):
        raise ValueError(f"installed rule policy is not an object: {manifest}")
    aliases = {
        "phishtank_rule_id": {"--phishtank-rule-id", "--reputation-rule-id"},
        "phishtank_level": {"--phishtank-level", "--reputation-level"},
    }
    for field in fields(Policy):
        options = aliases.get(field.name, {"--" + field.name.replace("_", "-")})
        if not options.intersection(command_line) and field.name in installed:
            setattr(args, field.name, installed[field.name])


def validate_rule_id(rule_id: int) -> None:
    if not CUSTOM_MIN <= rule_id <= CUSTOM_MAX:
        raise ValueError(f"rule ID {rule_id} is outside {CUSTOM_MIN}-{CUSTOM_MAX}")


def allocate_ids(args: argparse.Namespace, used: set[int], locations: dict[int, Path]) -> dict[str, int]:
    explicit = {role: getattr(args, role) for role in RULE_ROLES if getattr(args, role) is not None}
    for role, rule_id in explicit.items():
        validate_rule_id(rule_id)
        if rule_id in used:
            raise ValueError(f"{role}={rule_id} conflicts with {locations[rule_id]}")
    if len(set(explicit.values())) != len(explicit):
        raise ValueError("explicit rule IDs must be distinct")

    result = dict(explicit)
    reserved = used | set(explicit.values())
    missing = [role for role in RULE_ROLES if role not in result]
    if missing:
        validate_rule_id(args.preferred_start)

    if len(missing) == len(RULE_ROLES):
        start = args.preferred_start
        while start + len(RULE_ROLES) - 1 <= CUSTOM_MAX:
            candidate = set(range(start, start + len(RULE_ROLES)))
            if not candidate & reserved:
                return dict(zip(RULE_ROLES, range(start, start + len(RULE_ROLES))))
            start += 1
        raise ValueError("no free contiguous custom-rule range was found")

    candidate = args.preferred_start
    for role in missing:
        while candidate in reserved and candidate <= CUSTOM_MAX:
            candidate += 1
        validate_rule_id(candidate)
        result[role] = candidate
        reserved.add(candidate)
        candidate += 1
    return result


def prompt(label: str, default: str, validator=None) -> str:
    while True:
        value = input(f"{label} [{default}]: ").strip() or default
        try:
            if validator:
                validator(value)
            return value
        except ValueError as exc:
            print(f"Invalid value: {exc}")


def run_wizard(args: argparse.Namespace, allocated: dict[str, int]) -> None:
    def group_validator(value: str) -> None:
        if not GROUP_RE.fullmatch(value):
            raise ValueError("use comma-separated names containing letters, digits, _, ., or -")

    def id_validator(value: str) -> None:
        validate_rule_id(int(value))

    def level_validator(value: str) -> None:
        if not 0 <= int(value) <= 16:
            raise ValueError("level must be between 0 and 16")

    args.group_name = prompt("Wazuh group/block name", args.group_name, group_validator)
    labels = {
        "navigation": "URL observed",
        "classification_base": "Classification base",
        "phishtank": "Verified reputation result",
        "ml": "ML suspicious result",
        "review": "ML review-band result",
        "error": "Classification error",
        "negative": "Negative/unknown result",
    }
    for prefix, label in labels.items():
        role = f"{prefix}_rule_id"
        setattr(args, role, int(prompt(f"{label} rule ID", str(allocated[role]), id_validator)))
        level_name = f"{prefix}_level"
        setattr(args, level_name, int(prompt(f"{label} alert level", str(getattr(args, level_name)), level_validator)))


def make_policy(args: argparse.Namespace, allocated: dict[str, int]) -> Policy:
    if not GROUP_RE.fullmatch(args.group_name):
        raise ValueError("group name must be a comma-separated Wazuh name list")
    values = {field.name: getattr(args, field.name, field.default) for field in fields(Policy)}
    values["reputation_provider"] = values["reputation_provider"].replace("-", "_")
    values.update(allocated)
    policy = Policy(**values)
    ids = [getattr(policy, role) for role in RULE_ROLES]
    if len(set(ids)) != len(ids):
        raise ValueError("all rule IDs must be distinct")
    for rule_id in ids:
        validate_rule_id(rule_id)
    for name, value in values.items():
        if name.endswith("_level") and not 0 <= value <= 16:
            raise ValueError(f"{name} must be between 0 and 16")
    return policy


def generate_xml(policy: Policy) -> str:
    group = policy.group_name.rstrip(",") + ","
    group_xml = html.escape(group, quote=True)
    if policy.reputation_provider == "google_webrisk":
        reputation_source = "google_webrisk"
        reputation_description = (
            "A URL opened by a user on $(classification.url_host) was identified as "
            "$(classification.threat_types) by Google Web Risk."
        )
        reputation_group = "google_web_risk"
    else:
        reputation_source = "phishtank"
        reputation_description = (
            "A URL opened by a user on $(classification.url_host) was verified as phishing by PhishTank."
        )
        reputation_group = "phishtank"
    return f'''<group name="{group_xml}">
  <rule id="{policy.navigation_rule_id}" level="{policy.navigation_level}">
    <if_sid>86600</if_sid>
    <field name="schema_version" type="pcre2">^1$</field>
    <field name="event_type" type="pcre2">^browser_navigation$</field>
    <field name="source" type="pcre2">^edge_extension$</field>
    <field name="browser" type="pcre2">^edge$</field>
    <url type="pcre2">^https?://</url>
    <description>URL was opened in Microsoft Edge: $(url_host) [event_id=$(event_id)]</description>
    <mitre><id>T1566.002</id></mitre>
    <group>browser_navigation,pilot_transport,</group>
  </rule>

  <rule id="{policy.classification_base_rule_id}" level="{policy.classification_base_level}">
    <decoded_as>json</decoded_as>
    <field name="integration" type="pcre2">^edge-phishing-classifier$</field>
    <description>Edge phishing classification result.</description>
  </rule>

  <rule id="{policy.phishtank_rule_id}" level="{policy.phishtank_level}">
    <if_sid>{policy.classification_base_rule_id}</if_sid>
    <field name="classification.status" type="pcre2">^malicious$</field>
    <field name="classification.source" type="pcre2">^{reputation_source}$</field>
    <description>{reputation_description}</description>
    <mitre><id>T1566.002</id></mitre>
    <group>phishing,confirmed_phishing,{reputation_group},</group>
  </rule>

  <rule id="{policy.ml_rule_id}" level="{policy.ml_level}">
    <if_sid>{policy.classification_base_rule_id}</if_sid>
    <field name="classification.status" type="pcre2">^suspicious$</field>
    <field name="classification.source" type="pcre2">^ml$</field>
    <description>ML detected a suspicious URL on $(classification.url_host) with score $(classification.score) [model=$(classification.model_kind), calibrated=$(classification.calibrated)].</description>
    <mitre><id>T1566.002</id></mitre>
    <group>phishing,ml_detection,</group>
  </rule>

  <rule id="{policy.review_rule_id}" level="{policy.review_level}">
    <if_sid>{policy.classification_base_rule_id}</if_sid>
    <field name="classification.status" type="pcre2">^review$</field>
    <field name="classification.source" type="pcre2">^ml$</field>
    <description>ML marked a URL on $(classification.url_host) for review with score $(classification.score) [review_threshold=$(classification.review_threshold), suspicious_threshold=$(classification.threshold)].</description>
    <mitre><id>T1566.002</id></mitre>
    <group>phishing,ml_review,</group>
  </rule>

  <rule id="{policy.error_rule_id}" level="{policy.error_level}">
    <if_sid>{policy.classification_base_rule_id}</if_sid>
    <field name="classification.status" type="pcre2">^error$</field>
    <description>URL classification failed: $(classification.error)</description>
    <group>phishing_detection_error,</group>
  </rule>

  <rule id="{policy.negative_rule_id}" level="{policy.negative_level}">
    <if_sid>{policy.classification_base_rule_id}</if_sid>
    <field name="classification.status" type="pcre2">^(not_found|listed_inactive|unlikely)$</field>
    <description>URL was not classified as phishing: $(classification.url_host)</description>
  </rule>
</group>
'''


def update_classifier_config(path: Path, navigation_rule_id: int) -> None:
    if not path.exists():
        return
    config = json.loads(path.read_text(encoding="utf-8"))
    config["navigation_rule_id"] = str(navigation_rule_id)
    path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")


def update_integration_rule_id(path: Path, navigation_rule_id: int) -> None:
    if not path.exists():
        return
    text = path.read_text(encoding="utf-8")
    begin = "<!-- BEGIN EDGE PHISHING CLASSIFIER -->"
    end = "<!-- END EDGE PHISHING CLASSIFIER -->"
    if begin not in text or end not in text:
        return
    start, finish = text.index(begin), text.index(end, text.index(begin))
    block = text[start:finish]
    updated = re.sub(r"<rule_id>\d+</rule_id>", f"<rule_id>{navigation_rule_id}</rule_id>", block)
    path.write_text(text[:start] + updated + text[finish:], encoding="utf-8")


def install(policy: Policy, xml: str, home: Path, verbose: bool) -> None:
    if os.geteuid() != 0:
        raise PermissionError("--install must run as root")
    rules_dir = home / "etc" / "rules"
    destination = rules_dir / "edge_phishing_pipeline_rules.xml"
    old_files = [rules_dir / name for name in MANAGED_FILES if name != destination.name]
    config_path = home / "etc" / "edge-phishing-classifier.json"
    policy_path = home / "etc" / "edge-phishing-rule-policy.json"
    ossec_path = home / "etc" / "ossec.conf"
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    backup = home / "backup" / f"edge-rule-policy-{stamp}"
    backup.mkdir(parents=True)
    managed = [destination, *old_files, config_path, policy_path, ossec_path]
    for path in managed:
        if path.exists():
            shutil.copy2(path, backup / path.name)

    samples = [
        (
            json.dumps({"schema_version": 1, "event_type": "browser_navigation", "event_id": "wizard-nav", "timestamp": "2026-07-11T00:00:00Z", "browser": "edge", "url": "https://example.test/", "url_host": "example.test", "source": "edge_extension"}),
            f"{policy.navigation_rule_id}:{policy.navigation_level}:json",
        ),
        (
            json.dumps({"integration": "edge-phishing-classifier", "classification": {"status": "malicious", "source": policy.reputation_provider, "url_host": "example.test", "threat_types": ["SOCIAL_ENGINEERING"]}}),
            f"{policy.phishtank_rule_id}:{policy.phishtank_level}:json",
        ),
        (
            json.dumps({"integration": "edge-phishing-classifier", "classification": {"status": "suspicious", "source": "ml", "url_host": "example.test", "score": 0.9, "model_kind": "legacy_svr", "calibrated": False}}),
            f"{policy.ml_rule_id}:{policy.ml_level}:json",
        ),
        (
            json.dumps({"integration": "edge-phishing-classifier", "classification": {"status": "review", "source": "ml", "url_host": "example.test", "score": 0.08, "review_threshold": 0.07, "threshold": 0.1}}),
            f"{policy.review_rule_id}:{policy.review_level}:json",
        ),
    ]
    try:
        try:
            wazuh_gid = grp.getgrnam("wazuh").gr_gid
        except KeyError as exc:
            raise OSError("Wazuh group 'wazuh' was not found") from exc
        destination.write_text(xml, encoding="utf-8")
        policy_path.write_text(json.dumps(policy.__dict__, indent=2) + "\n", encoding="utf-8")
        for path in (destination, policy_path):
            os.chown(path, 0, wazuh_gid)
            os.chmod(path, 0o640)
        for old in old_files:
            if old.exists():
                old.unlink()
        update_classifier_config(config_path, policy.navigation_rule_id)
        update_integration_rule_id(ossec_path, policy.navigation_rule_id)
        if not config_path.exists():
            print("WARNING: classifier configuration is not installed; run install-wazuh-server.sh.", file=sys.stderr)
        if not ossec_path.exists():
            print("WARNING: ossec.conf was not found; the classifier trigger was not updated.", file=sys.stderr)
        subprocess.run([str(home / "bin" / "wazuh-analysisd"), "-t"], check=True)
        subprocess.run(["systemctl", "restart", "wazuh-manager"], check=True)
        subprocess.run(["systemctl", "is-active", "--quiet", "wazuh-manager"], check=True)
        for sample, expected in samples:
            command = [
                str(home / "bin" / "wazuh-logtest"),
                "-v" if verbose else "-q", "-U", expected,
            ]
            subprocess.run(command, input=sample + "\n", text=True, check=True)
    except Exception:
        for path in managed:
            if path != ossec_path and path.exists():
                path.unlink()
            saved = backup / path.name
            if saved.exists():
                shutil.copy2(saved, path)
        subprocess.run(["systemctl", "restart", "wazuh-manager"], check=False)
        raise
    print(f"Installed rule policy at {destination}")
    print(f"Installed policy manifest at {policy_path}")
    print(f"Backup stored at {backup}")


def main() -> int:
    args = parser().parse_args()
    home = Path(args.wazuh_home)
    apply_installed_policy_defaults(args, home, sys.argv[1:])
    used, locations = scan_used_ids(home)
    allocated = allocate_ids(args, used, locations)
    if args.verbose:
        print(f"Scanned {len(used)} active rule IDs under {home}.", file=sys.stderr)
        print(f"Selected IDs: {json.dumps(allocated, sort_keys=True)}", file=sys.stderr)
    if args.wizard:
        run_wizard(args, allocated)
        allocated = allocate_ids(args, used, locations)
    policy = make_policy(args, allocated)
    xml = generate_xml(policy)
    if args.install:
        install(policy, xml, home, args.verbose)
    elif args.output:
        args.output.write_text(xml, encoding="utf-8")
        print(f"Generated {args.output}")
    else:
        print(xml, end="")
    print("Policy:", json.dumps(policy.__dict__, indent=2), file=sys.stderr)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
