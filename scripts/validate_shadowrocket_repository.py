#!/usr/bin/env python3
"""Validate stable Shadowrocket profile URLs, rule order, and rule-set syntax."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
RULE_DIR = ROOT / "client" / "shadowrocket"
if not RULE_DIR.is_dir():
    RULE_DIR = ROOT

PUBLIC_BASE = (
    "https://raw.githubusercontent.com/"
    "Jeliren/shadowrocket-russia-direct/main"
)
PROFILE_PATH = RULE_DIR / "profile.conf"
LIST_FILES = (
    "proxy-custom.list",
    "direct-custom.list",
    "adblock.list",
    "direct-curated.list",
)
EXPECTED_RULES = [
    f"RULE-SET,{PUBLIC_BASE}/proxy-custom.list,PROXY",
    f"RULE-SET,{PUBLIC_BASE}/direct-custom.list,DIRECT",
    f"RULE-SET,{PUBLIC_BASE}/adblock.list,REJECT",
    f"RULE-SET,{PUBLIC_BASE}/direct-curated.list,DIRECT",
    "FINAL,PROXY",
]
REQUIRED_MANUAL_RULES = {
    "DOMAIN-SUFFIX,bitrix24.ru",
    "DOMAIN-SUFFIX,rick-i-morty.net",
    "DOMAIN-SUFFIX,vkusnoitochka.ru",
    "DOMAIN-SUFFIX,trip.com",
    "DOMAIN-KEYWORD,yandex",
    "DOMAIN-SUFFIX,ya.ru",
    "DOMAIN-SUFFIX,yastatic.net",
}
RULE_PATTERN = re.compile(r"^(DOMAIN|DOMAIN-SUFFIX|DOMAIN-KEYWORD),[^,\s]+$")


def active_lines(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def validate_profile() -> None:
    profile = PROFILE_PATH.read_text(encoding="utf-8")
    expected_update = (
        f"update-url = {PUBLIC_BASE}/profile.conf interval=60 strict=true"
    )
    if expected_update not in profile:
        raise ValueError("stable profile update-url changed or disappeared")

    rule_section = profile.split("[Rule]", 1)
    if len(rule_section) != 2:
        raise ValueError("profile.conf has no [Rule] section")
    actual_rules = [
        line
        for line in active_lines(PROFILE_PATH)
        if line.startswith("RULE-SET,") or line.startswith("FINAL,")
    ]
    if actual_rules != EXPECTED_RULES:
        raise ValueError(
            "profile rule order changed:\n"
            f"expected={EXPECTED_RULES!r}\nactual={actual_rules!r}"
        )


def validate_rule_set(filename: str) -> set[str]:
    path = RULE_DIR / filename
    if not path.is_file():
        raise ValueError(f"missing public rule-set: {filename}")
    rules = active_lines(path)
    invalid = [rule for rule in rules if not RULE_PATTERN.fullmatch(rule)]
    if invalid:
        raise ValueError(f"invalid {filename} rule: {invalid[0]}")
    if len(rules) != len(set(rules)):
        raise ValueError(f"duplicate rules in {filename}")

    count_headers = [
        line
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.startswith("# Rules: ")
    ]
    if count_headers and count_headers != [f"# Rules: {len(rules)}"]:
        raise ValueError(
            f"stale rule count in {filename}: {count_headers!r}, actual={len(rules)}"
        )
    return set(rules)


def main() -> int:
    validate_profile()
    rule_sets = {filename: validate_rule_set(filename) for filename in LIST_FILES}

    missing = REQUIRED_MANUAL_RULES - rule_sets["direct-custom.list"]
    if missing:
        raise ValueError(f"required manual DIRECT rules are missing: {sorted(missing)}")

    sources = json.loads((RULE_DIR / "sources.json").read_text(encoding="utf-8"))
    if "manual_direct_rules" in sources:
        raise ValueError("manual rules must stay in direct-custom.list only")

    print("OK: stable URLs, profile order, and rule-set syntax are valid")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
