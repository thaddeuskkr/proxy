#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path


SHADOWROCKET_HEADER = "# Shadowrocket"
RULE_PLACEHOLDER = "{$$RULES$$}"
RULE_SOURCES = (
    ("direct.list", "DIRECT"),
    ("proxy.list", "PROXY"),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Render Shadowrocket config templates with generated rules."
    )
    parser.add_argument(
        "-c",
        "--config-dir",
        default=Path("config"),
        type=Path,
        help="Directory containing Shadowrocket config templates.",
    )
    parser.add_argument(
        "-r",
        "--rules-dir",
        default=Path("output"),
        type=Path,
        help="Directory containing generated direct.list and proxy.list files.",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default=Path("output"),
        type=Path,
        help="Directory where rendered Shadowrocket configs should be written.",
    )
    parser.add_argument(
        "-n",
        "--no-comments",
        action="store_false",
        dest="include_comments",
        help="Do not include comments from generated rule list files.",
    )
    return parser.parse_args()


def load_policy_rules(rules_dir: Path, *, include_comments: bool) -> list[str]:
    rules: list[str] = []
    rule_count = 0

    for filename, policy in RULE_SOURCES:
        path = rules_dir / filename
        if not path.is_file():
            raise ValueError(f"Required rule file does not exist: {path}")

        for raw_line in path.read_text(encoding="utf-8-sig").splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("#"):
                if include_comments:
                    rules.append(line)
                continue

            rules.append(f"{line},{policy}")
            rule_count += 1

    if rule_count == 0:
        raise ValueError(f"No rules found in {rules_dir}")

    return rules


def discover_shadowrocket_templates(config_dir: Path) -> list[Path]:
    if not config_dir.exists():
        raise ValueError(f"Config directory does not exist: {config_dir}")
    if not config_dir.is_dir():
        raise ValueError(f"Config path is not a directory: {config_dir}")

    return [
        path
        for path in sorted(config_dir.iterdir())
        if path.is_file() and is_shadowrocket_template(path)
    ]


def is_shadowrocket_template(path: Path) -> bool:
    with path.open("r", encoding="utf-8-sig", errors="replace") as file:
        return file.readline().startswith(SHADOWROCKET_HEADER)


def render_template(template_path: Path, rules: list[str]) -> str:
    template = template_path.read_text(encoding="utf-8-sig")
    if RULE_PLACEHOLDER not in template:
        raise ValueError(
            f"Shadowrocket template is missing {RULE_PLACEHOLDER}: {template_path}"
        )

    return template.replace(RULE_PLACEHOLDER, "\n".join(rules))


def generate_shadowrocket_configs(
    *,
    config_dir: Path,
    rules_dir: Path,
    output_dir: Path,
    include_comments: bool,
) -> list[Path]:
    rules = load_policy_rules(rules_dir, include_comments=include_comments)
    templates = discover_shadowrocket_templates(config_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    written: list[Path] = []
    for template_path in templates:
        output_path = output_dir / template_path.name
        output_path.write_text(render_template(template_path, rules), encoding="utf-8")
        written.append(output_path)

    return written


def main() -> int:
    try:
        args = parse_args()
        written = generate_shadowrocket_configs(
            config_dir=args.config_dir,
            rules_dir=args.rules_dir,
            output_dir=args.output_dir,
            include_comments=args.include_comments,
        )

        if not written:
            print(f"No Shadowrocket templates found in {args.config_dir}")
            return 0

        for output_path in written:
            print(f"Wrote {output_path}")
        return 0
    except Exception as error:
        print(f"error: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
