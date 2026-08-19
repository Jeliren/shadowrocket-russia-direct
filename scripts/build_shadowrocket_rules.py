#!/usr/bin/env python3
"""Build auditable Shadowrocket routing and ad-blocking rule-sets."""

from __future__ import annotations

import io
import json
import re
import subprocess
import sys
import tarfile
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parent.parent
LOCAL_RULE_DIR = ROOT / "client" / "shadowrocket"
RULE_DIR = LOCAL_RULE_DIR if LOCAL_RULE_DIR.is_dir() else ROOT
CONFIG_PATH = RULE_DIR / "sources.json"
OUTPUT_PATH = RULE_DIR / "direct-curated.list"
ADBLOCK_OUTPUT_PATH = RULE_DIR / "adblock.list"
V2FLY_ARCHIVE = (
    "https://codeload.github.com/v2fly/domain-list-community/"
    "tar.gz/refs/heads/master"
)


def download(url: str) -> bytes:
    result = subprocess.run(
        [
            "curl",
            "-fsSL",
            "--retry",
            "3",
            "--retry-all-errors",
            "--connect-timeout",
            "15",
            "--max-time",
            "90",
            url,
        ],
        check=True,
        capture_output=True,
    )
    return result.stdout


def clean_line(raw: str) -> str:
    return raw.split("#", 1)[0].strip()


def rule_from_domain_line(raw: str) -> str | None:
    value = clean_line(raw)
    if not value or value.startswith("include:"):
        return None

    # V2Fly attributes follow the domain and do not affect this DIRECT aggregate.
    value = value.split()[0]
    if value.startswith("full:"):
        return f"DOMAIN,{value[5:]}"
    if value.startswith("keyword:"):
        return f"DOMAIN-KEYWORD,{value[8:]}"
    if value.startswith("regexp:"):
        return None
    if value.startswith("domain:"):
        value = value[7:]
    return f"DOMAIN-SUFFIX,{value}"


def load_v2fly_files() -> dict[str, str]:
    archive = tarfile.open(fileobj=io.BytesIO(download(V2FLY_ARCHIVE)), mode="r:gz")
    files: dict[str, str] = {}
    marker = "/data/"
    for member in archive.getmembers():
        if not member.isfile() or marker not in member.name:
            continue
        name = member.name.split(marker, 1)[1]
        if "/" in name:
            continue
        extracted = archive.extractfile(member)
        if extracted is not None:
            files[name] = extracted.read().decode("utf-8")
    return files


def expand_category(name: str, files: dict[str, str], seen: set[str]) -> set[str]:
    if name in seen:
        return set()
    if name not in files:
        raise KeyError(f"V2Fly category not found: {name}")
    seen.add(name)

    rules: set[str] = set()
    for raw in files[name].splitlines():
        value = clean_line(raw)
        if value.startswith("include:"):
            include_name = value.split()[0][len("include:") :]
            rules.update(expand_category(include_name, files, seen))
            continue
        rule = rule_from_domain_line(raw)
        if rule:
            rules.add(rule)
    return rules


def parse_shadowrocket_list(content: str) -> set[str]:
    valid = re.compile(r"^(DOMAIN|DOMAIN-SUFFIX|DOMAIN-KEYWORD),[^,]+$")
    return {
        clean_line(line)
        for line in content.splitlines()
        if valid.match(clean_line(line))
    }


def parse_domain_list(content: str) -> set[str]:
    return {
        rule
        for line in content.splitlines()
        if (rule := rule_from_domain_line(line)) is not None
    }


class LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        if tag.lower() != "a":
            return
        for name, value in attrs:
            if name.lower() == "href" and value:
                self.links.append(value)


CBR_EXCLUDED_HOSTS = {
    "apps.apple.com",
    "appgallery.huawei.com",
    "dzen.ru",
    "linkedin.com",
    "max.ru",
    "ok.ru",
    "play.google.com",
    "rutube.ru",
    "t.me",
    "telegram.me",
    "twitter.com",
    "vk.com",
    "x.com",
    "youtu.be",
    "youtube.com",
    "zen.yandex.ru",
}


def is_domain(value: str) -> bool:
    if len(value) > 253 or "." not in value:
        return False
    label = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    return all(label.match(part) for part in value.split("."))


def normalize_hostname(url: str) -> str | None:
    try:
        parsed = urlsplit(unquote(url.strip()))
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return None
        hostname = parsed.hostname.lower().rstrip(".")
        if hostname.startswith("www."):
            hostname = hostname[4:]
        hostname = hostname.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return None
    return hostname if is_domain(hostname) else None


def parse_cbr_websites(content: str) -> set[str]:
    parser = LinkParser()
    parser.feed(content)
    domains: set[str] = set()
    for link in parser.links:
        hostname = normalize_hostname(link)
        if not hostname:
            continue
        if any(
            hostname == excluded or hostname.endswith(f".{excluded}")
            for excluded in CBR_EXCLUDED_HOSTS
        ):
            continue
        domains.add(f"DOMAIN-SUFFIX,{hostname}")
    return domains


def parse_oisd_small(content: str) -> set[str]:
    entry = re.compile(r"^\|\|([a-zA-Z0-9_.-]+)\^$")
    rules: set[str] = set()
    for raw in content.splitlines():
        match = entry.match(raw.strip())
        if not match:
            continue
        domain = match.group(1).lower().lstrip(".")
        if is_domain(domain):
            rules.add(f"DOMAIN-SUFFIX,{domain}")
    return rules


def write_rule_set(path: Path, header: list[str], rules: set[str]) -> None:
    ordered = sorted(rules, key=lambda item: (item.split(",", 1)[1], item))
    path.write_text(
        "\n".join(header + [f"# Rules: {len(ordered)}", ""] + ordered) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {len(ordered)} rules to {path}")


def main() -> int:
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    files = load_v2fly_files()
    rules: set[str] = set()
    seen: set[str] = set()

    for category in config["v2fly_categories"]:
        rules.update(expand_category(category, files, seen))
    for url in config["external_shadowrocket_lists"]:
        rules.update(parse_shadowrocket_list(download(url).decode("utf-8")))
    for url in config["external_domain_lists"]:
        rules.update(parse_domain_list(download(url).decode("utf-8")))
    # Keep explicit user routes in the curated projection as a compatibility
    # path for older profiles that refresh only direct-curated.list.
    rules.update(parse_shadowrocket_list("\n".join(config.get("manual_direct_rules", []))))
    cbr_rules = parse_cbr_websites(
        download(config["cbr_websites_url"]).decode("utf-8")
    )
    if len(cbr_rules) < 500:
        raise RuntimeError(
            f"Bank of Russia source produced only {len(cbr_rules)} rules"
        )
    rules.update(cbr_rules)

    write_rule_set(
        OUTPUT_PATH,
        [
            "# Generated by scripts/build_shadowrocket_rules.py; do not edit.",
            "# Sources and selected categories: sources.json",
        ],
        rules,
    )

    adblock_rules = parse_oisd_small(
        download(config["oisd_small_url"]).decode("utf-8")
    )
    if len(adblock_rules) < 10_000:
        raise RuntimeError(f"OISD Small produced only {len(adblock_rules)} rules")
    write_rule_set(
        ADBLOCK_OUTPUT_PATH,
        [
            "# Generated from OISD Small; do not edit.",
            "# Source: https://oisd.nl/",
            "# License: GNU General Public License v3.0",
            "# This transformed rule-set is distributed under GPL-3.0.",
        ],
        adblock_rules,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
