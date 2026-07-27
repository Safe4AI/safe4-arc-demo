from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MD_FILES = sorted(ROOT.rglob("*.md"))
LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
FORBIDDEN_RE = [
    re.compile(r"(?i)\bc:\\"),
    re.compile(r"(?i)/c:/"),
    re.compile(r"(?i)file://"),
]


def iter_relative_links(text: str) -> list[str]:
    links: list[str] = []
    for _label, target in LINK_RE.findall(text):
        target = target.strip()
        if not target or target.startswith("#"):
            continue
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", target):
            continue
        if target.startswith("mailto:"):
            continue
        links.append(target)
    return links


def resolve_target(md_file: Path, target: str) -> Path:
    normalized = target.split("#", 1)[0]
    return (md_file.parent / normalized).resolve()


def main() -> int:
    issues: list[str] = []
    fixed_links = 0

    for md_file in MD_FILES:
        text = md_file.read_text(encoding="utf-8")
        rel_path = md_file.relative_to(ROOT)

        for pattern in FORBIDDEN_RE:
            if pattern.search(text):
                issues.append(f"{rel_path}: forbidden path/link pattern matched `{pattern.pattern}`")

        for target in iter_relative_links(text):
            resolved = resolve_target(md_file, target)
            if not resolved.exists():
                issues.append(f"{rel_path}: broken relative link `{target}`")

    print("Documentation check summary")
    print(f"- markdown files scanned: {len(MD_FILES)}")
    print(f"- fixed links: {fixed_links}")
    print(f"- issues found: {len(issues)}")

    if issues:
        print("\nIssues:")
        for issue in issues:
            print(f"- {issue}")
        return 1

    print("\nNo issues found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
