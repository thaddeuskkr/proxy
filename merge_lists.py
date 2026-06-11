#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Iterable, Literal


GITHUB_API_BASE = "https://api.github.com"
DEFAULT_USER_AGENT = "tkProxyConfig"
DOMAIN_LIST_SUFFIX = "_Domain"
DEFAULT_END_MARKER = "# {END}"
PIN_MARKER_RE = re.compile(r"\s+#\s*\{PIN-(START|END)\}\s*$", re.IGNORECASE)
FETCH_ATTEMPTS = 3
TRANSIENT_HTTP_CODES = {500, 502, 503, 504}
# Broad upstream lists are sorted after service-specific lists unless
# --preserve-order is used. This only affects output order.
LARGE_SOURCE_TOKENS = (
    "AdGuard",
    "Advertising",
    "ChinaIPs",
    "ChinaMax",
    "EasyPrivacy",
    "Global",
    "GlobalMedia",
    "Privacy",
)

BareDomainRule = Literal["domain", "suffix"]
DefaultPlacement = Literal["start", "end"]
PinPlacement = Literal["start", "end"]
Network = ipaddress.IPv4Network | ipaddress.IPv6Network


DOMAIN_RULE_TYPES = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN-WILDCARD",
}
IP_RULE_TYPES = {"IP-CIDR", "IP-CIDR6"}
OTHER_RULE_TYPES = {
    "FINAL",
    "GEOIP",
    "IP-ASN",
    "PROCESS-NAME",
    "PROCESS-PATH",
    "URL-REGEX",
    "USER-AGENT",
}
KNOWN_RULE_TYPES = DOMAIN_RULE_TYPES | IP_RULE_TYPES | OTHER_RULE_TYPES
COMMA_VALUE_RULE_TYPES = {"URL-REGEX"}
DOMAIN_SET_PREFIX_RULES = {
    "domain:": "DOMAIN",
    "full:": "DOMAIN",
    "suffix:": "DOMAIN-SUFFIX",
    "keyword:": "DOMAIN-KEYWORD",
    "regexp:": "URL-REGEX",
    "regex:": "URL-REGEX",
    "ip-cidr:": "IP-CIDR",
    "ip-cidr6:": "IP-CIDR6",
}
SIMPLE_HOST_REGEX_PREFIXES = (
    r"([^/]+\.)?",
    r"([A-Za-z0-9-]+\.)?",
    r"([^.\/]+\.)?",
)
SIMPLE_HOST_REGEX_REMAINDERS = {
    "$",
    "(/|$)",
    "($|/)",
    "(?:/|$)",
    "(?:[/:]|$)",
    "([/:]|$)",
    "[/:]",
    "[/:].*",
}
RULE_SORT_BUCKETS = {
    "DOMAIN": 0,
    "DOMAIN-SUFFIX": 1,
    "IP-CIDR": 2,
    "IP-CIDR6": 2,
    "IP-ASN": 3,
    "GEOIP": 3,
    "USER-AGENT": 4,
    "DOMAIN-WILDCARD": 5,
    "DOMAIN-KEYWORD": 6,
    "URL-REGEX": 8,
    "RAW": 9,
}
REMOVED_EXACT_DUPLICATE = "exact_duplicate"
REMOVED_DOMAIN_REDUNDANCY = "domain_redundancy"
REMOVED_COVERED_CIDR = "covered_cidr"


@dataclass(frozen=True)
class GitHubFile:
    owner: str
    repo: str
    path: str
    ref: str | None
    source_url: str
    pin: PinPlacement | None = None

    @property
    def api_url(self) -> str:
        owner = urllib.parse.quote(self.owner, safe="")
        repo = urllib.parse.quote(self.repo, safe="")
        path = "/".join(
            urllib.parse.quote(part, safe="") for part in self.path.split("/")
        )
        url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/contents/{path}"

        if self.ref:
            url = f"{url}?ref={urllib.parse.quote(self.ref, safe='')}"

        return url

    @property
    def is_domain_list(self) -> bool:
        return any(
            PurePosixPath(part).stem.endswith(DOMAIN_LIST_SUFFIX)
            for part in PurePosixPath(self.path).parts
        )

    @property
    def is_large_source(self) -> bool:
        lowered = self.path.lower()
        return any(token.lower() in lowered for token in LARGE_SOURCE_TOKENS)


@dataclass(frozen=True)
class LocalRuleFile:
    path: Path
    placement: DefaultPlacement = "start"
    text: str | None = None
    pin: PinPlacement | None = None

    @property
    def source_url(self) -> str:
        suffix = f":{self.placement}" if self.placement == "end" else ""
        return f"local:{self.path.as_posix()}{suffix}"

    @property
    def is_domain_list(self) -> bool:
        return self.path.stem.endswith(DOMAIN_LIST_SUFFIX)

    @property
    def is_large_source(self) -> bool:
        return False


RuleSource = GitHubFile | LocalRuleFile


@dataclass
class SourceStats:
    source_url: str
    source_path: str
    fetched_line_count: int = 0
    emitted_line_count: int = 0
    conversion_counts: Counter[str] = field(default_factory=Counter)
    warnings: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class SourceUrlSpec:
    url: str
    pin: PinPlacement | None = None


@dataclass(frozen=True)
class ParsedRuleLine:
    rule_type: str
    value: str
    options: tuple[str, ...]
    known: bool


@dataclass(frozen=True)
class CanonicalRuleLine:
    line: str
    rule_type: str
    value: str
    options: tuple[str, ...]
    known: bool
    network: Network | None = None

    @property
    def normalized_key(self) -> tuple[str, ...]:
        return (self.rule_type, self.value, *self.options)


@dataclass
class Rule:
    line: str
    rule_type: str
    value: str
    options: tuple[str, ...]
    source_index: int
    global_index: int
    is_large_source: bool
    is_default: bool
    pin: PinPlacement | None
    known: bool
    network: Network | None = None
    normalized_key: tuple[str, ...] = field(default_factory=tuple)

    @property
    def is_pinned(self) -> bool:
        return self.pin is not None


@dataclass
class OutputReport:
    output_path: str
    source_count: int
    fetched_line_count: int
    raw_emitted_line_count: int
    emitted_line_count: int
    removed_counts: Counter[str] = field(default_factory=Counter)
    conversion_counts: Counter[str] = field(default_factory=Counter)
    rule_type_counts_before: Counter[str] = field(default_factory=Counter)
    rule_type_counts_after: Counter[str] = field(default_factory=Counter)
    largest_sources: list[dict[str, int | str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Resolve every URL-list file in a source directory into a same-named "
            "merged output file."
        )
    )
    parser.add_argument(
        "-s",
        "--source-dir",
        default=Path("source"),
        type=Path,
        help="Directory containing input files with one GitHub file URL per line.",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default=Path("output"),
        type=Path,
        help="Directory where resolved files should be written.",
    )
    parser.add_argument(
        "-d",
        "--defaults-dir",
        default=Path("defaults"),
        type=Path,
        help="Directory containing local default rules prepended by matching filename.",
    )
    parser.add_argument(
        "-k",
        "--keep-comments",
        action="store_true",
        help="Keep comment lines from source files. By default, source comments are removed.",
    )
    parser.add_argument(
        "-D",
        "--no-dedupe",
        action="store_true",
        help="Keep duplicate rules instead of writing each unique rule once.",
    )
    parser.add_argument(
        "-H",
        "--include-header",
        action="store_true",
        help="Write a generated-file header at the top of each output.",
    )
    parser.add_argument(
        "-b",
        "--bare-domain-rule",
        choices=("suffix", "domain"),
        default="suffix",
        help=(
            "How to convert bare entries from *_Domain lists. The default "
            "uses DOMAIN-SUFFIX so exact domains and subdomains are covered."
        ),
    )
    parser.add_argument(
        "-O",
        "--no-optimize",
        action="store_true",
        help="Disable optimizer passes except *_Domain conversion.",
    )
    parser.add_argument(
        "-p",
        "--preserve-order",
        action="store_true",
        help="Do not reorder optimized rules into performance-oriented buckets.",
    )
    parser.add_argument(
        "-J",
        "--report-json",
        default=Path("output/report.json"),
        type=Path,
        help="Path for the machine-readable report.",
    )
    parser.add_argument(
        "-M",
        "--report-md",
        default=Path("output/report.md"),
        type=Path,
        help="Path for the Markdown report.",
    )
    parser.add_argument(
        "-R",
        "--no-report",
        action="store_true",
        help="Do not write report files.",
    )
    parser.add_argument(
        "-t",
        "--token",
        default=os.environ.get("GITHUB_TOKEN"),
        help="GitHub token. Defaults to the GITHUB_TOKEN environment variable.",
    )
    return parser.parse_args()


def discover_relative_files(source_dir: Path, defaults_dir: Path) -> list[Path]:
    relative_files: set[Path] = set()

    if source_dir.exists():
        if not source_dir.is_dir():
            raise ValueError(f"Source path is not a directory: {source_dir}")
        relative_files.update(list_relative_files(source_dir))
    else:
        raise ValueError(f"Source directory does not exist: {source_dir}")

    if defaults_dir.exists():
        if not defaults_dir.is_dir():
            raise ValueError(f"Defaults path is not a directory: {defaults_dir}")
        relative_files.update(list_relative_files(defaults_dir))

    if not relative_files:
        raise ValueError(f"No source or default files found in {source_dir} or {defaults_dir}")

    return sorted(relative_files)


def list_relative_files(directory: Path) -> list[Path]:
    return sorted(
        path.relative_to(directory)
        for path in directory.rglob("*")
        if path.is_file()
        and not any(
            part.startswith(".") for part in path.relative_to(directory).parts
        )
    )


def split_pin_marker(line: str) -> tuple[str, PinPlacement | None]:
    match = PIN_MARKER_RE.search(line)
    if not match:
        return line, None

    marker = match.group(1).upper()
    pin: PinPlacement = "start" if marker == "START" else "end"
    return line[: match.start()].rstrip(), pin


def load_source_urls(path: Path, *, allow_empty: bool = False) -> list[SourceUrlSpec]:
    urls: list[SourceUrlSpec] = []
    in_end_section = False

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()

        if not line:
            continue

        if line == DEFAULT_END_MARKER:
            in_end_section = True
            continue

        if line.startswith("#"):
            continue

        line, line_pin = split_pin_marker(line)
        pin: PinPlacement | None = "end" if in_end_section else line_pin

        if " #" in line:
            line = line.split(" #", 1)[0].strip()

        if not line:
            continue

        urls.append(SourceUrlSpec(line, pin))

    if not urls and not allow_empty:
        raise ValueError(f"No source URLs found in {path}")

    return urls


def load_default_rule_files(path: Path) -> tuple[list[LocalRuleFile], list[LocalRuleFile]]:
    start_text, end_text = split_default_text(path.read_text(encoding="utf-8"))
    start_files: list[LocalRuleFile] = []
    end_files: list[LocalRuleFile] = []

    if start_text.strip():
        start_files.append(LocalRuleFile(path=path, placement="start", text=start_text))

    if end_text and end_text.strip():
        end_files.append(
            LocalRuleFile(path=path, placement="end", text=end_text, pin="end")
        )

    return start_files, end_files


def split_default_text(text: str) -> tuple[str, str | None]:
    start_lines: list[str] = []
    end_lines: list[str] = []
    in_end_section = False

    for line in text.splitlines():
        if line.strip() == DEFAULT_END_MARKER:
            in_end_section = True
            continue

        if in_end_section:
            end_lines.append(line)
        else:
            start_lines.append(line)

    end_text = "\n".join(end_lines) if in_end_section else None
    return "\n".join(start_lines), end_text


def parse_github_file_url(
    url: str,
    pin: PinPlacement | None = None,
) -> GitHubFile:
    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc.lower()
    parts = [urllib.parse.unquote(part) for part in parsed.path.split("/") if part]

    if host == "github.com":
        return parse_github_blob_url(url, parts, pin)

    if host == "raw.githubusercontent.com":
        return parse_raw_github_url(url, parts, pin)

    if host == "api.github.com":
        return parse_github_api_url(url, parts, parsed.query, pin)

    raise ValueError(
        f"Unsupported GitHub URL host for {url!r}. Use github.com, "
        "raw.githubusercontent.com, or api.github.com file URLs."
    )


def parse_github_blob_url(
    url: str,
    parts: list[str],
    pin: PinPlacement | None,
) -> GitHubFile:
    if len(parts) < 5 or parts[2] != "blob":
        raise ValueError(
            f"Unsupported GitHub file URL {url!r}. Expected "
            "https://github.com/OWNER/REPO/blob/REF/PATH."
        )

    return GitHubFile(
        owner=parts[0],
        repo=parts[1],
        ref=parts[3],
        path="/".join(parts[4:]),
        source_url=url,
        pin=pin,
    )


def parse_raw_github_url(
    url: str,
    parts: list[str],
    pin: PinPlacement | None,
) -> GitHubFile:
    if len(parts) < 4:
        raise ValueError(
            f"Unsupported raw GitHub URL {url!r}. Expected "
            "https://raw.githubusercontent.com/OWNER/REPO/REF/PATH."
        )

    return GitHubFile(
        owner=parts[0],
        repo=parts[1],
        ref=parts[2],
        path="/".join(parts[3:]),
        source_url=url,
        pin=pin,
    )


def parse_github_api_url(
    url: str,
    parts: list[str],
    query: str,
    pin: PinPlacement | None,
) -> GitHubFile:
    if len(parts) < 5 or parts[0] != "repos" or parts[3] != "contents":
        raise ValueError(
            f"Unsupported GitHub API URL {url!r}. Expected "
            "https://api.github.com/repos/OWNER/REPO/contents/PATH."
        )

    query_params = urllib.parse.parse_qs(query)
    refs = query_params.get("ref", [])

    return GitHubFile(
        owner=parts[1],
        repo=parts[2],
        ref=refs[0] if refs else None,
        path="/".join(parts[4:]),
        source_url=url,
        pin=pin,
    )


def fetch_github_file(file: GitHubFile, token: str | None) -> str:
    headers = {
        "Accept": "application/vnd.github.raw+json",
        "User-Agent": os.environ.get("GITHUB_USER_AGENT", DEFAULT_USER_AGENT),
    }

    if token:
        headers["Authorization"] = f"Bearer {token}"

    api_version = os.environ.get("GITHUB_API_VERSION")
    if api_version:
        headers["X-GitHub-Api-Version"] = api_version

    last_error: Exception | None = None
    for attempt in range(1, FETCH_ATTEMPTS + 1):
        request = urllib.request.Request(file.api_url, headers=headers)

        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                content_type = response.headers.get("Content-Type", "")
                body = response.read()
                return decode_github_contents_response(body, content_type, file)
        except urllib.error.HTTPError as error:
            message = error.read().decode("utf-8", errors="replace")
            if error.code not in TRANSIENT_HTTP_CODES or attempt == FETCH_ATTEMPTS:
                raise RuntimeError(
                    f"GitHub API request failed for {file.source_url}: "
                    f"HTTP {error.code} {message}"
                ) from error
            last_error = error
        except urllib.error.URLError as error:
            if attempt == FETCH_ATTEMPTS:
                raise RuntimeError(
                    f"Could not reach GitHub API for {file.source_url}: {error.reason}"
                ) from error
            last_error = error

        print(
            f"Retrying {file.source_url} after transient fetch error "
            f"({attempt}/{FETCH_ATTEMPTS}): {last_error}",
            file=sys.stderr,
        )
        time.sleep(attempt)

    raise RuntimeError(f"Could not fetch {file.source_url}")


def fetch_source_text(source: RuleSource, token: str | None) -> str:
    if isinstance(source, LocalRuleFile):
        if source.text is not None:
            return source.text
        return source.path.read_text(encoding="utf-8")

    return fetch_github_file(source, token)


def source_path(source: RuleSource) -> str:
    if isinstance(source, LocalRuleFile):
        suffix = f":{source.placement}" if source.placement == "end" else ""
        return f"{source.path.as_posix()}{suffix}"

    return source.path


def decode_github_contents_response(
    body: bytes, content_type: str, file: GitHubFile
) -> str:
    text = body.decode("utf-8-sig", errors="replace")

    if "json" not in content_type.lower():
        return text

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return text

    if isinstance(data, dict) and data.get("type") not in (None, "file"):
        raise RuntimeError(f"GitHub API URL did not resolve to a file: {file.source_url}")

    if isinstance(data, dict) and data.get("encoding") == "base64":
        encoded = str(data.get("content", "")).replace("\n", "")
        return base64.b64decode(encoded).decode("utf-8-sig", errors="replace")

    if isinstance(data, dict) and "message" in data:
        raise RuntimeError(f"GitHub API error for {file.source_url}: {data['message']}")

    return text


def is_ip_or_cidr(value: str) -> Network | None:
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def ip_rule_type_for_network(network: Network) -> str:
    return "IP-CIDR6" if network.version == 6 else "IP-CIDR"


def is_hostname(value: str) -> bool:
    if not value or len(value) > 253:
        return False
    labels = value.rstrip(".").split(".")
    return all(
        label
        and len(label) <= 63
        and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
        for label in labels
    )


def convert_domain_set_line(
    line: str, bare_domain_rule: BareDomainRule
) -> tuple[str, str | None]:
    if "," in line:
        return line, None

    lowered = line.lower()

    for prefix, rule_type in DOMAIN_SET_PREFIX_RULES.items():
        if lowered.startswith(prefix):
            value = line[len(prefix):].strip()
            if not value:
                raise ValueError(f"Domain-set entry is missing a value: {line!r}")
            return f"{rule_type},{value}", f"domain_prefix_{prefix.rstrip(':')}"

    if line.startswith("||") and line.endswith("^") and len(line) > 3:
        return f"DOMAIN-SUFFIX,{line[2:-1]}", "domain_adblock_suffix"

    if line.startswith("+.") and len(line) > 2:
        return f"DOMAIN-SUFFIX,{line[2:]}", "domain_plus_dot_to_suffix"

    if line.startswith(".") and len(line) > 1:
        return f"DOMAIN-SUFFIX,{line[1:]}", "domain_leading_dot_to_suffix"

    network = is_ip_or_cidr(line)
    if network:
        rule_type = ip_rule_type_for_network(network)
        return f"{rule_type},{network},no-resolve", "domain_ip_to_cidr"

    if lowered.startswith("http://") or lowered.startswith("https://"):
        return f"URL-REGEX,{line}", "domain_url_to_regex"

    if (line.startswith("/") and line.endswith("/")) or lowered.startswith("^http"):
        return f"URL-REGEX,{line}", "domain_regex_passthrough"

    if "*" in line or "?" in line:
        return f"DOMAIN-WILDCARD,{line}", "domain_wildcard_passthrough"

    if bare_domain_rule == "domain":
        return f"DOMAIN,{line}", "domain_bare_to_domain"

    return f"DOMAIN-SUFFIX,{line}", "domain_bare_to_suffix"


def split_rule_line(line: str) -> ParsedRuleLine:
    rule_type_text, separator, remainder = line.partition(",")
    if not separator:
        return ParsedRuleLine("RAW", line, (), False)

    rule_type = rule_type_text.strip().upper()
    known = rule_type in KNOWN_RULE_TYPES

    if rule_type in COMMA_VALUE_RULE_TYPES:
        return ParsedRuleLine(rule_type, remainder.strip(), (), known)

    parts = tuple(part.strip() for part in remainder.split(","))
    value = parts[0]
    options = parts[1:]

    return ParsedRuleLine(rule_type, value, options, known)


def canonicalize_rule_line(line: str) -> CanonicalRuleLine:
    parsed = split_rule_line(line)
    if not parsed.known:
        return CanonicalRuleLine(line, "RAW", line, (), False)

    value = parsed.value
    normalized_options = tuple(option.lower() for option in parsed.options)
    network: Network | None = None

    if parsed.rule_type in DOMAIN_RULE_TYPES:
        value = value.lower().rstrip(".")
    elif parsed.rule_type in IP_RULE_TYPES:
        network = is_ip_or_cidr(value)
        if network:
            value = str(network)
        else:
            return CanonicalRuleLine(line, "RAW", line, (), False)

    canonical_line = ",".join((parsed.rule_type, value, *normalized_options))

    return CanonicalRuleLine(
        canonical_line,
        parsed.rule_type,
        value,
        normalized_options,
        True,
        network,
    )


def convert_balanced_domain_rule(line: str) -> tuple[str, str | None, str | None]:
    if line.startswith("#"):
        return line, None, None

    parsed = split_rule_line(line)
    if not parsed.known:
        return line, None, f"Unsupported rule preserved: {line}"

    lowered_value = parsed.value.lower().rstrip(".")

    if parsed.rule_type == "DOMAIN-WILDCARD" and not parsed.options:
        if lowered_value.startswith("*.") and is_hostname(lowered_value[2:]):
            return f"DOMAIN-SUFFIX,{lowered_value[2:]}", "wildcard_to_suffix", None

    if parsed.rule_type == "DOMAIN-KEYWORD" and not parsed.options:
        if lowered_value.startswith(".") and is_hostname(lowered_value[1:]):
            return f"DOMAIN-SUFFIX,{lowered_value[1:]}", "dot_keyword_to_suffix", None
        return line, None, f"Complex keyword preserved: {line}"

    if parsed.rule_type == "URL-REGEX" and not parsed.options:
        suffix = simple_host_regex_to_suffix(parsed.value)
        if suffix:
            return f"DOMAIN-SUFFIX,{suffix}", "simple_regex_to_suffix", None
        return line, None, f"Complex regex preserved: {line}"

    return line, None, None


def simple_host_regex_to_suffix(value: str) -> str | None:
    pattern = value.strip()
    if pattern.startswith("/") and pattern.endswith("/") and len(pattern) > 2:
        pattern = pattern[1:-1]
    pattern = pattern.replace(r"\/", "/")

    if not pattern.startswith("^https?://"):
        return None

    host_pattern = pattern[len("^https?://") :]
    for prefix in SIMPLE_HOST_REGEX_PREFIXES:
        if host_pattern.startswith(prefix):
            host_pattern = host_pattern[len(prefix) :]
            break
    else:
        return None

    domain_chars: list[str] = []
    index = 0
    while index < len(host_pattern):
        char = host_pattern[index]
        if char.isalnum() or char == "-":
            domain_chars.append(char.lower())
            index += 1
            continue
        if host_pattern[index : index + 2] == r"\.":
            domain_chars.append(".")
            index += 2
            continue
        break

    domain = "".join(domain_chars).rstrip(".")
    remainder = host_pattern[index:]

    if domain and is_hostname(domain) and remainder in SIMPLE_HOST_REGEX_REMAINDERS:
        return domain

    return None


def make_rule(
    line: str,
    *,
    file: RuleSource,
    source_index: int,
    global_index: int,
    pin: PinPlacement | None,
) -> Rule:
    canonical = canonicalize_rule_line(line)
    return Rule(
        line=canonical.line,
        rule_type=canonical.rule_type,
        value=canonical.value,
        options=canonical.options,
        source_index=source_index,
        global_index=global_index,
        is_large_source=file.is_large_source,
        is_default=isinstance(file, LocalRuleFile),
        pin=pin,
        known=canonical.known,
        network=canonical.network,
        normalized_key=canonical.normalized_key,
    )


def collect_rules(
    files: Iterable[RuleSource],
    *,
    token: str | None,
    keep_comments: bool,
    bare_domain_rule: BareDomainRule,
    optimize: bool,
) -> tuple[list[Rule], list[SourceStats]]:
    rules: list[Rule] = []
    source_stats: list[SourceStats] = []
    global_index = 0

    for source_index, file in enumerate(files):
        print(f"Fetching {file.source_url}", file=sys.stderr)
        text = fetch_source_text(file, token)
        stats = SourceStats(
            source_url=file.source_url,
            source_path=source_path(file),
        )

        for raw_line in text.splitlines():
            line = raw_line.strip()
            line_pin: PinPlacement | None = None

            if isinstance(file, LocalRuleFile):
                line, line_pin = split_pin_marker(line)

            if not line:
                continue

            if line.startswith("#") and not keep_comments:
                continue

            stats.fetched_line_count += 1
            pin = file.pin or line_pin

            if file.is_domain_list and not line.startswith("#"):
                line, conversion = convert_domain_set_line(line, bare_domain_rule)
                if conversion:
                    stats.conversion_counts[conversion] += 1

            if optimize and pin is None:
                line, conversion, warning = convert_balanced_domain_rule(line)
                if conversion:
                    stats.conversion_counts[conversion] += 1
                if warning:
                    stats.warnings.append(warning)

            rule = make_rule(
                line,
                file=file,
                source_index=source_index,
                global_index=global_index,
                pin=pin,
            )
            rules.append(rule)
            global_index += 1
            stats.emitted_line_count += 1

        source_stats.append(stats)
        print(f"Added {stats.emitted_line_count} lines from {source_path(file)}", file=sys.stderr)

    return rules, source_stats


def optimize_rules(
    rules: list[Rule],
    *,
    dedupe: bool,
    optimize: bool,
    preserve_order: bool,
) -> tuple[list[Rule], Counter[str]]:
    removed = Counter()

    if optimize and dedupe:
        rules, removed_count = remove_exact_duplicates(rules)
        removed[REMOVED_EXACT_DUPLICATE] += removed_count

    if optimize:
        rules, domain_removed = remove_domain_redundancy(rules)
        removed[REMOVED_DOMAIN_REDUNDANCY] += domain_removed

        rules, cidr_removed = remove_covered_cidrs(rules)
        removed[REMOVED_COVERED_CIDR] += cidr_removed

    rules = order_rules(
        rules,
        heuristic_sort=optimize and not preserve_order,
    )

    return rules, removed


def order_rules(rules: list[Rule], *, heuristic_sort: bool) -> list[Rule]:
    start_pinned = [rule for rule in rules if rule.pin == "start"]
    middle = [rule for rule in rules if rule.pin is None]
    end_pinned = [rule for rule in rules if rule.pin == "end"]

    if heuristic_sort:
        middle = sorted(middle, key=rule_sort_key)

    return [*start_pinned, *middle, *end_pinned]


def remove_exact_duplicates(rules: list[Rule]) -> tuple[list[Rule], int]:
    end_pinned_keys = {
        rule.normalized_key
        for rule in rules
        if rule.pin == "end"
    }
    seen: set[tuple[str, ...]] = set()
    kept: list[Rule] = []
    removed = 0

    for rule in rules:
        if (
            not rule.is_pinned
            and rule.normalized_key in end_pinned_keys
        ):
            removed += 1
            continue

        if rule.is_pinned:
            kept.append(rule)
            if rule.pin == "start":
                seen.add(rule.normalized_key)
            continue

        if rule.normalized_key in seen:
            removed += 1
            continue

        seen.add(rule.normalized_key)
        kept.append(rule)

    return kept, removed


def remove_domain_redundancy(rules: list[Rule]) -> tuple[list[Rule], int]:
    suffix_keys = {
        (rule.value, rule.options)
        for rule in rules
        if rule.rule_type == "DOMAIN-SUFFIX" and rule.known and not rule.is_pinned
    }
    kept: list[Rule] = []
    removed = 0

    for rule in rules:
        if rule.is_default or rule.is_pinned:
            kept.append(rule)
            continue

        if (
            rule.rule_type == "DOMAIN"
            and rule.known
            and (rule.value, rule.options) in suffix_keys
        ):
            removed += 1
            continue
        kept.append(rule)

    return kept, removed


def remove_covered_cidrs(rules: list[Rule]) -> tuple[list[Rule], int]:
    kept_by_group: dict[
        tuple[str, int, tuple[str, ...]],
        dict[int, set[Network]],
    ] = defaultdict(lambda: defaultdict(set))
    kept_indexes: set[int] = set()
    removed = 0

    indexed_networks: list[tuple[int, Rule, Network]] = []
    for index, rule in enumerate(rules):
        network = rule.network
        if rule.rule_type in IP_RULE_TYPES and network is not None:
            indexed_networks.append((index, rule, network))

    indexed_networks.sort(
        key=lambda item: (item[2].prefixlen, item[1].global_index)
    )

    for index, rule, network in indexed_networks:
        group = (rule.rule_type, network.version, rule.options)
        if rule.is_pinned:
            kept_indexes.add(index)
            continue

        if rule.is_default:
            kept_by_group[group][network.prefixlen].add(network)
            kept_indexes.add(index)
            continue

        if has_covering_supernet(network, kept_by_group[group]):
            removed += 1
            continue

        kept_by_group[group][network.prefixlen].add(network)
        kept_indexes.add(index)

    result: list[Rule] = []
    network_indexes = {index for index, _rule, _network in indexed_networks}
    for index, rule in enumerate(rules):
        if index in network_indexes and index not in kept_indexes:
            continue
        result.append(rule)

    return result, removed


def has_covering_supernet(
    network: Network,
    kept_by_prefix: dict[int, set[Network]],
) -> bool:
    for prefixlen, kept_networks in kept_by_prefix.items():
        if prefixlen >= network.prefixlen:
            continue
        if network.supernet(new_prefix=prefixlen) in kept_networks:
            return True
    return False


def rule_sort_key(rule: Rule) -> tuple[int, int, int, int, int]:
    if rule.is_default:
        return (-1, 0, 0, rule.source_index, rule.global_index)

    source_bucket = 1 if rule.is_large_source else 0
    rule_bucket = RULE_SORT_BUCKETS.get(rule.rule_type, 7)
    specificity = -specificity_score(rule)
    return (source_bucket, rule_bucket, specificity, rule.source_index, rule.global_index)


def specificity_score(rule: Rule) -> int:
    if rule.network is not None:
        return rule.network.prefixlen
    if rule.rule_type in DOMAIN_RULE_TYPES:
        return len(rule.value.split("."))
    return 0


def build_output(lines: list[str], source_urls: list[str], include_header: bool) -> str:
    output_lines: list[str] = []

    if include_header:
        output_lines.extend(
            [
                "# Generated by merge_lists.py",
                "# Sources:",
                *[f"# - {url}" for url in source_urls],
                "",
            ]
        )

    output_lines.extend(lines)
    return "\n".join(output_lines).rstrip() + "\n"


def build_rule_sources(source_file: Path, default_file: Path) -> list[RuleSource]:
    sources: list[RuleSource] = []
    end_default_sources: list[LocalRuleFile] = []

    if default_file.exists():
        start_defaults, end_default_sources = load_default_rule_files(default_file)
        sources.extend(start_defaults)

    if source_file.exists():
        urls = load_source_urls(
            source_file,
            allow_empty=bool(sources or end_default_sources),
        )
        sources.extend(parse_github_file_url(spec.url, spec.pin) for spec in urls)

    sources.extend(end_default_sources)
    return sources


def resolve_source_file(
    relative_file: Path,
    *,
    source_dir: Path,
    defaults_dir: Path,
    output_dir: Path,
    token: str | None,
    keep_comments: bool,
    dedupe: bool,
    include_header: bool,
    bare_domain_rule: BareDomainRule,
    optimize: bool,
    preserve_order: bool,
) -> tuple[Path, OutputReport]:
    source_file = source_dir / relative_file
    default_file = defaults_dir / relative_file
    print(f"Resolving {relative_file}", file=sys.stderr)

    files = build_rule_sources(source_file, default_file)
    if not files:
        raise ValueError(f"No default rules or source URLs found for {relative_file}")

    raw_rules, source_stats = collect_rules(
        files,
        token=token,
        keep_comments=keep_comments,
        bare_domain_rule=bare_domain_rule,
        optimize=optimize,
    )
    optimized_rules, removed_counts = optimize_rules(
        raw_rules,
        dedupe=dedupe,
        optimize=optimize,
        preserve_order=preserve_order,
    )

    output_path = output_dir / relative_file
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        build_output(
            [rule.line for rule in optimized_rules],
            [file.source_url for file in files],
            include_header,
        ),
        encoding="utf-8",
    )

    report = build_report(
        output_path=output_path,
        source_stats=source_stats,
        raw_rules=raw_rules,
        optimized_rules=optimized_rules,
        removed_counts=removed_counts,
    )
    return output_path, report


def build_report(
    *,
    output_path: Path,
    source_stats: list[SourceStats],
    raw_rules: list[Rule],
    optimized_rules: list[Rule],
    removed_counts: Counter[str],
) -> OutputReport:
    conversion_counts = Counter()
    warnings: list[str] = []
    for stats in source_stats:
        conversion_counts.update(stats.conversion_counts)
        warnings.extend(stats.warnings[:10])

    largest_sources = [
        {
            "source_url": stats.source_url,
            "source_path": stats.source_path,
            "emitted_line_count": stats.emitted_line_count,
        }
        for stats in sorted(
            source_stats,
            key=lambda item: item.emitted_line_count,
            reverse=True,
        )[:10]
    ]

    return OutputReport(
        output_path=str(output_path),
        source_count=len(source_stats),
        fetched_line_count=sum(stats.fetched_line_count for stats in source_stats),
        raw_emitted_line_count=len(raw_rules),
        emitted_line_count=len(optimized_rules),
        removed_counts=removed_counts,
        conversion_counts=conversion_counts,
        rule_type_counts_before=Counter(rule.rule_type for rule in raw_rules),
        rule_type_counts_after=Counter(rule.rule_type for rule in optimized_rules),
        largest_sources=largest_sources,
        warnings=warnings[:50],
    )


def write_reports(
    reports: list[OutputReport],
    *,
    json_path: Path,
    markdown_path: Path,
) -> None:
    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(
        json.dumps(report_to_json(reports), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(report_to_markdown(reports), encoding="utf-8")


def report_to_json(reports: list[OutputReport]) -> dict[str, object]:
    return {
        "files": [
            {
                "output_path": report.output_path,
                "source_count": report.source_count,
                "fetched_line_count": report.fetched_line_count,
                "raw_emitted_line_count": report.raw_emitted_line_count,
                "emitted_line_count": report.emitted_line_count,
                "removed_counts": dict(sorted(report.removed_counts.items())),
                "conversion_counts": dict(sorted(report.conversion_counts.items())),
                "rule_type_counts_before": dict(
                    sorted(report.rule_type_counts_before.items())
                ),
                "rule_type_counts_after": dict(
                    sorted(report.rule_type_counts_after.items())
                ),
                "largest_sources": report.largest_sources,
                "warnings": report.warnings,
            }
            for report in reports
        ]
    }


def report_to_markdown(reports: list[OutputReport]) -> str:
    lines = ["# Proxy Rule Report", ""]

    for report in reports:
        lines.extend(
            [
                f"## {report.output_path}",
                "",
                f"- Sources: {report.source_count}",
                f"- Fetched active lines: {report.fetched_line_count}",
                f"- Raw emitted lines: {report.raw_emitted_line_count}",
                f"- Final emitted lines: {report.emitted_line_count}",
                (
                    "- Removed exact duplicates: "
                    f"{report.removed_counts.get(REMOVED_EXACT_DUPLICATE, 0)}"
                ),
                f"- Removed covered CIDRs: {report.removed_counts.get(REMOVED_COVERED_CIDR, 0)}",
                (
                    "- Removed domain redundancies: "
                    f"{report.removed_counts.get(REMOVED_DOMAIN_REDUNDANCY, 0)}"
                ),
                "",
                "### Rule Types After",
                "",
            ]
        )
        for rule_type, count in sorted(report.rule_type_counts_after.items()):
            lines.append(f"- {rule_type}: {count}")

        if report.conversion_counts:
            lines.extend(["", "### Conversions", ""])
            for conversion, count in sorted(report.conversion_counts.items()):
                lines.append(f"- {conversion}: {count}")

        if report.largest_sources:
            lines.extend(["", "### Largest Sources", ""])
            for source in report.largest_sources[:5]:
                lines.append(
                    f"- {source['emitted_line_count']}: {source['source_path']}"
                )

        if report.warnings:
            lines.extend(["", "### Warning Examples", ""])
            for warning in report.warnings[:10]:
                lines.append(f"- {warning}")

        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    try:
        args = parse_args()
        relative_files = discover_relative_files(args.source_dir, args.defaults_dir)
        reports: list[OutputReport] = []

        for relative_file in relative_files:
            output_path, report = resolve_source_file(
                relative_file,
                source_dir=args.source_dir,
                defaults_dir=args.defaults_dir,
                output_dir=args.output_dir,
                token=args.token,
                keep_comments=args.keep_comments,
                dedupe=not args.no_dedupe,
                include_header=args.include_header,
                bare_domain_rule=args.bare_domain_rule,
                optimize=not args.no_optimize,
                preserve_order=args.preserve_order,
            )
            reports.append(report)
            print(
                f"Wrote {report.emitted_line_count} optimized lines from "
                f"{report.source_count} sources to {output_path}",
                file=sys.stderr,
            )

        if not args.no_report:
            write_reports(
                reports,
                json_path=args.report_json,
                markdown_path=args.report_md,
            )

        return 0
    except Exception as error:
        print(f"error: {error}", file=sys.stderr)
        if "GitHub API" in str(error) or "rate limit" in str(error).lower():
            print(
                "hint: set GITHUB_TOKEN for authenticated GitHub API requests.",
                file=sys.stderr,
            )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
