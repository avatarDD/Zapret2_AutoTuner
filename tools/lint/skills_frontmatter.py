"""Checks that every .claude/skills/*/SKILL.md starts with YAML frontmatter that parses and has name and description.

An unquoted ": " inside description breaks the YAML and the skill stops loading, so CI runs this.
"""
import pathlib
import sys

import yaml

root = pathlib.Path(__file__).resolve().parents[2]
bad = 0
for path in sorted(root.glob(".claude/skills/*/SKILL.md")):
    text = path.read_text(encoding="utf-8")
    parts = text.split("---\n", 2)
    try:
        if not text.startswith("---\n") or len(parts) < 3:
            raise ValueError("no frontmatter")
        meta = yaml.safe_load(parts[1])
        if not isinstance(meta, dict) or not meta.get("name") or not meta.get("description"):
            raise ValueError("name and description are required")
        if meta["name"] != path.parent.name:
            raise ValueError(f"name {meta['name']!r} differs from the folder")
    except Exception as e:
        print(f"{path.relative_to(root)}: {e}")
        bad += 1
    else:
        print(f"ok {path.relative_to(root)}")
sys.exit(1 if bad else 0)
