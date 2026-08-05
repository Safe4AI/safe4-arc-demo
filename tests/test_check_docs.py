from __future__ import annotations

from pathlib import Path

from scripts.check_docs import markdown_files


def test_markdown_discovery_ignores_generated_and_environment_trees(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "kept.md").write_text("# Kept\n", encoding="utf-8")
    for ignored in (".tmp", ".git", ".python313", ".venv", "node_modules", "__pycache__"):
        directory = tmp_path / ignored
        directory.mkdir()
        (directory / "ignored.md").write_text("# Ignore\n", encoding="utf-8")

    assert [path.relative_to(tmp_path).as_posix() for path in markdown_files(tmp_path)] == [
        "docs/kept.md"
    ]
