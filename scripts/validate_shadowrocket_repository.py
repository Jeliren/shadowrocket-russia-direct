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
CHINA_PROFILE_PATH = RULE_DIR / "china.conf"
LEGACY_PROFILE_PATH = RULE_DIR / "profile.conf interval=60 strict=true"
LIST_FILES = (
    "proxy-custom.list",
    "direct-custom.list",
    "adblock.list",
    "direct-curated.list",
)
# Referenced, not copied: the upstream repository has no licence.
ITDOG_OUTSIDE_SOURCE = (
    "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/"
    "Russia/outside-clashx.lst"
)
EXPECTED_RULES = [
    f"RULE-SET,{PUBLIC_BASE}/proxy-custom.list,PROXY",
    f"RULE-SET,{PUBLIC_BASE}/direct-custom.list,DIRECT",
    f"RULE-SET,{PUBLIC_BASE}/adblock.list,REJECT",
    f"RULE-SET,{PUBLIC_BASE}/direct-curated.list,DIRECT",
    f"RULE-SET,{ITDOG_OUTSIDE_SOURCE},DIRECT",
    "FINAL,PROXY",
]
CHINA_RULE_SOURCE = (
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/"
    "rule/Shadowrocket/ChinaMax/ChinaMax.list"
)
EXPECTED_CHINA_RULES = [
    f"RULE-SET,{CHINA_RULE_SOURCE},DIRECT",
    "GEOIP,CN,DIRECT",
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
    "DOMAIN-SUFFIX,aeroflot.ru",
    "DOMAIN-SUFFIX,s7.ru",
    "DOMAIN-SUFFIX,pobeda.aero",
    "DOMAIN-SUFFIX,domclick.ru",
    "DOMAIN-SUFFIX,lenta.ru",
}
REQUIRED_PROXY_RULES = {
    "DOMAIN-SUFFIX,telegram.org",
    "DOMAIN-SUFFIX,t.me",
    "DOMAIN-SUFFIX,telegram.me",
}
# Blocked or geo-restricted for Russian users: no DIRECT rule may match them
# or any of their subdomains.
FORBIDDEN_DIRECT_DOMAINS = (
    "telegram.org",
    "t.me",
    "telegram.me",
    "youtube.com",
    "googlevideo.com",
    "instagram.com",
    "facebook.com",
    "whatsapp.com",
    "whatsapp.net",
    "x.com",
    "twitter.com",
    "discord.com",
    "discordapp.com",
    "openai.com",
    "chatgpt.com",
    "anthropic.com",
    "claude.ai",
    "linkedin.com",
    "spotify.com",
    "netflix.com",
    "signal.org",
    "viber.com",
    "rutracker.org",
    "torproject.org",
)
# Core Russian services that must stay DIRECT after every daily rebuild.
REQUIRED_DIRECT_DOMAINS = (
    "gosuslugi.ru",
    "nalog.gov.ru",
    "mos.ru",
    "sberbank.ru",
    "tbank.ru",
    "vtb.ru",
    "alfabank.ru",
    "ozon.ru",
    "wildberries.ru",
    "avito.ru",
    "yandex.ru",
    "vk.com",
    "mail.ru",
    "rzd.ru",
    "pochta.ru",
    "2gis.ru",
    "kinopoisk.ru",
    "rutube.ru",
    "hh.ru",
    "cdek.ru",
)
MIN_RULES = {
    "direct-curated.list": 1_500,
    "adblock.list": 10_000,
}
KNOWN_IDN_TLDS = {
    "xn--p1ai",
    "xn--p1acf",
    "xn--80adxhks",
    "xn--d1acj3b",
    "xn--80asehdb",
    "xn--80aswg",
    "xn--c1avg",
    "xn--90ais",
    "xn--80ao21a",
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
    expected_update = f"update-url = {PUBLIC_BASE}/profile.conf"
    if expected_update not in profile:
        raise ValueError("stable profile update-url changed or disappeared")
    update_lines = [
        line.strip()
        for line in profile.splitlines()
        if line.strip().startswith("update-url =")
    ]
    if update_lines != [expected_update]:
        raise ValueError(f"invalid profile update-url: {update_lines!r}")
    if LEGACY_PROFILE_PATH.read_bytes() != PROFILE_PATH.read_bytes():
        raise ValueError("legacy malformed-URL bridge differs from profile.conf")

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


def validate_china_profile() -> None:
    profile = CHINA_PROFILE_PATH.read_text(encoding="utf-8")
    expected_update = f"update-url = {PUBLIC_BASE}/china.conf"
    update_lines = [
        line.strip()
        for line in profile.splitlines()
        if line.strip().startswith("update-url =")
    ]
    if update_lines != [expected_update]:
        raise ValueError(f"invalid China profile update-url: {update_lines!r}")

    if "[Rule]" not in profile:
        raise ValueError("china.conf has no [Rule] section")
    actual_rules = [
        line
        for line in active_lines(CHINA_PROFILE_PATH)
        if line.startswith("RULE-SET,") or line.startswith("GEOIP,") or line.startswith("FINAL,")
    ]
    if actual_rules != EXPECTED_CHINA_RULES:
        raise ValueError(
            "China profile rule order changed:\n"
            f"expected={EXPECTED_CHINA_RULES!r}\nactual={actual_rules!r}"
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


def rule_matches(rule: str, domain: str) -> bool:
    kind, value = rule.split(",", 1)
    if kind == "DOMAIN":
        return domain == value
    if kind == "DOMAIN-SUFFIX":
        return domain == value or domain.endswith(f".{value}")
    return value in domain


def validate_direct_policy(direct: set[str], proxy: set[str]) -> None:
    for rule in sorted(direct):
        kind, value = rule.split(",", 1)
        for domain in FORBIDDEN_DIRECT_DOMAINS:
            if rule_matches(rule, domain) or (
                kind != "DOMAIN-KEYWORD" and value.endswith(f".{domain}")
            ):
                raise ValueError(f"blocked service {domain} is DIRECT via {rule}")
        if kind != "DOMAIN-KEYWORD":
            tld = value.rsplit(".", 1)[-1]
            valid = (
                tld in KNOWN_IDN_TLDS
                if tld.startswith("xn--")
                else re.fullmatch(r"[a-z]{2,63}", tld)
            )
            if not valid:
                raise ValueError(f"invalid top-level domain in DIRECT rule: {rule}")

    for domain in REQUIRED_DIRECT_DOMAINS:
        if any(rule_matches(rule, domain) for rule in proxy):
            raise ValueError(f"required DIRECT service {domain} is forced to PROXY")
        if not any(rule_matches(rule, domain) for rule in direct):
            raise ValueError(f"required DIRECT service {domain} lost its rule")


def main() -> int:
    validate_profile()
    validate_china_profile()
    rule_sets = {filename: validate_rule_set(filename) for filename in LIST_FILES}

    missing = REQUIRED_MANUAL_RULES - rule_sets["direct-custom.list"]
    if missing:
        raise ValueError(f"required manual DIRECT rules are missing: {sorted(missing)}")
    missing = REQUIRED_PROXY_RULES - rule_sets["proxy-custom.list"]
    if missing:
        raise ValueError(f"required PROXY rules are missing: {sorted(missing)}")
    for filename, minimum in MIN_RULES.items():
        if len(rule_sets[filename]) < minimum:
            raise ValueError(
                f"{filename} has only {len(rule_sets[filename])} rules (< {minimum})"
            )
    validate_direct_policy(
        rule_sets["direct-custom.list"] | rule_sets["direct-curated.list"],
        rule_sets["proxy-custom.list"],
    )

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
