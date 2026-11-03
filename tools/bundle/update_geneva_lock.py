#!/usr/bin/env python3
"""Point geneva.lock.json at a geneva_c release (by default the latest one) of the official repository.

    python3 tools/bundle/update_geneva_lock.py [--tag v1.1.1] [--print-tag] [--check]

Steps:
  1. find the release: --tag, or the latest published (not draft, not pre-release) release of the lock's repo;
  2. download every archive the lock ships (one per RID) and the release's SHA256SUMS from that release;
  3. require each archive's SHA-256 to be listed in SHA256SUMS, and the WinDivert files inside the Windows archive
     to be byte for byte the WinDivert release already pinned in the lock (file_sha256, WinDivert's own release);
  4. rewrite tag, version and the per-RID asset names and SHA-256 pins; everything else in the lock stays.
The protocol version is checked later by bundle_geneva.py, which runs "geneva version --json" on its native runner.
--check only reports whether the lock is at the latest release (exit code 1 when it is not) and changes nothing.
Only the Python standard library is used.
"""
import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bundle import Archive, fail, http_get, log, sha256  # noqa: E402

LOCK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "geneva.lock.json")
API = "application/vnd.github+json"


def release(repo, tag):
    url = f"https://api.github.com/repos/{repo}/releases/" + (f"tags/{tag}" if tag else "latest")
    try:
        rel = json.loads(http_get(url, API))
    except Exception as e:  # noqa: BLE001
        fail(f"release {tag or 'latest'} of {repo}: {e}")
    if rel.get("draft") or (rel.get("prerelease") and not tag):
        fail(f"release {rel.get('tag_name')} of {repo} is a draft or a pre-release")
    return rel


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", help="release tag of geneva_c (default: the latest release)")
    ap.add_argument("--check", action="store_true", help="only report whether the lock is at that release")
    ap.add_argument("--print-tag", action="store_true", help="print the resulting tag on stdout")
    args = ap.parse_args()

    lock = json.load(open(LOCK, encoding="utf-8"))
    repo = lock["repo"]
    rel = release(repo, args.tag)
    tag = rel["tag_name"]
    m = re.fullmatch(r"v(\d+\.\d+\.\d+)", tag)
    if not m:
        fail(f"{repo} release tag {tag!r} is not vX.Y.Z")
    version = m.group(1)

    if args.check:
        same = tag == lock["tag"]
        log(f"lock {lock['tag']}, {repo} release {tag}: " + ("up to date" if same else "the lock is behind"))
        if args.print_tag:
            print(tag)
        sys.exit(0 if same else 1)

    if tag == lock["tag"]:
        log(f"the lock is already at {repo} {tag}")
        if args.print_tag:
            print(tag)
        return

    base = f"https://github.com/{repo}/releases/download/{tag}/"
    assets = {a["name"] for a in rel.get("assets", [])}
    if lock["sums_asset"] not in assets:
        fail(f"{repo} {tag} has no {lock['sums_asset']}")
    sums = {}
    for line in http_get(base + lock["sums_asset"]).decode("utf-8", "replace").splitlines():
        parts = line.split()
        if len(parts) >= 2:
            sums[parts[-1].lstrip("*").split("/")[-1]] = parts[0].lower()

    for rid, spec in lock["rids"].items():
        name = spec["asset"].replace(f"geneva-{lock['version']}-", f"geneva-{version}-", 1)
        if name not in assets:
            fail(f"{rid}: {repo} {tag} has no asset {name}")
        log(f"{rid}: downloading {name}")
        data = http_get(base + name)
        digest = sha256(data)
        if sums.get(name) != digest:
            fail(f"{name}: sha256 {digest} is not the one in the release's {lock['sums_asset']} ({sums.get(name)})")
        arc = Archive(data, name)
        pins = spec.get("file_sha256", {})
        for f in spec["files"]:
            blob = arc.get(f)
            if blob is None:
                fail(f"{f} not in {name}")
            if f in pins and sha256(blob) != pins[f]:
                fail(f"{f} in {name} differs from its official release ({pins['_source']}); pin the new one by hand")
        spec["asset"] = name
        spec["sha256"] = digest

    old = lock["tag"]
    lock["tag"] = tag
    lock["version"] = version
    with open(LOCK, "w", encoding="utf-8") as f:
        # short lists of names stay on one line, as in the hand-written lock
        text = json.dumps(lock, indent=2)
        text = re.sub(r"\[\s*((?:\"[^\"]*\",\s*)*\"[^\"]*\")\s*\]", lambda m: "[" + re.sub(r",\s+", ", ", m.group(1)) + "]", text)
        f.write(text + "\n")
    log(f"geneva.lock.json: {old} -> {tag}")
    if args.print_tag:
        print(tag)


if __name__ == "__main__":
    main()
