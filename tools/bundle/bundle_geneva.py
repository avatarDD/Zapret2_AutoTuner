#!/usr/bin/env python3
"""Fetch the pinned geneva_c release and lay out the geneva bundle for one runtime identifier.

    python3 tools/bundle/bundle_geneva.py --rid linux-x64 [--out runtimes/linux-x64/geneva] [--archive file.tar.gz]

Steps (skill geneva, "Бандл"):
  1. download the release asset named in geneva.lock.json for the RID from the official geneva_c release
     (https://github.com/<repo>/releases/download/<tag>/<asset>), or use --archive;
  2. verify SHA-256 against the pin in the lock and against the release's SHA256SUMS, and the WinDivert files
     against WinDivert's own official release (file_sha256 in the lock);
  3. copy the binary (on Windows with WinDivert.dll and WinDivert64.sys, which geneva_c's release takes from the
     official WinDivert release) into the output directory;
  4. run "geneva version --json" when the binary is for this machine and check the protocol version;
  5. write bundle.json with per-file SHA-256 for the runtime integrity check (the Agent verifies it before a start).
Only the Python standard library is used.
"""
import argparse
import json
import os
import platform
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bundle import ROOT, Archive, fail, http_get, log, sha256  # noqa: E402

LOCK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "geneva.lock.json")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rid", required=True)
    ap.add_argument("--out")
    ap.add_argument("--archive", help="use a local release archive instead of downloading")
    ap.add_argument("--strict", action="store_true", help="also require the release's SHA256SUMS to list the asset")
    args = ap.parse_args()

    lock = json.load(open(LOCK, encoding="utf-8"))
    spec = lock["rids"].get(args.rid) or fail(f"unknown rid {args.rid}; known: {', '.join(lock['rids'])}")
    out = os.path.abspath(args.out or os.path.join(ROOT, "runtimes", args.rid, "geneva"))
    name = spec["asset"]
    base = f"https://github.com/{lock['repo']}/releases/download/{lock['tag']}/"

    if args.archive:
        data = open(args.archive, "rb").read()
    else:
        log(f"downloading {name} from {lock['repo']} {lock['tag']}")
        data = http_get(base + name)
        listed = None
        try:
            for line in http_get(base + lock["sums_asset"]).decode("utf-8", "replace").splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[-1].lstrip("*").split("/")[-1] == name:
                    listed = parts[0].lower()
        except Exception as e:  # noqa: BLE001
            if args.strict:
                fail(f"{lock['sums_asset']} of the release: {e}")
        if listed and listed != sha256(data):
            fail(f"{name}: sha256 does not match the release's {lock['sums_asset']} ({listed})")
        if not listed and args.strict:
            fail(f"{name}: the release's {lock['sums_asset']} has no line for it")
        log(f"{name}: {lock['sums_asset']} of the release " + ("matches" if listed else "has no line for it"))

    actual = sha256(data)
    if actual != spec["sha256"]:
        fail(f"{name}: sha256 {actual} does not match the pinned {spec['sha256']}")
    log(f"{name}: sha256 matches the pin")

    arc = Archive(data, name)
    if os.path.isdir(out):
        shutil.rmtree(out)
    os.makedirs(out)
    files = {}

    def put(rel, blob, executable=False):
        dst = os.path.join(out, rel)
        with open(dst, "wb") as f:
            f.write(blob)
        if executable:
            os.chmod(dst, 0o755)
        files[rel] = sha256(blob)

    pins = spec.get("file_sha256", {})
    for f in spec["files"]:
        blob = arc.get(f)
        if blob is None:
            fail(f"{f} not in {name}; directories with it: {arc.dirs_containing(f)}")
        # files geneva_c takes from another author (WinDivert) must be byte for byte that author's release
        if f in pins and sha256(blob) != pins[f]:
            fail(f"{f} in {name} differs from its official release ({pins['_source']})")
        put(f, blob, executable=not f.endswith((".dll", ".sys")))
    for f in spec.get("optional", []):
        blob = arc.get(f)
        if blob is not None:
            put(f, blob)

    binary = os.path.join(out, spec["files"][0])
    native = {("Linux", "x86_64"): "linux-x64", ("Linux", "aarch64"): "linux-arm64",
              ("Windows", "AMD64"): "win-x64"}.get((platform.system(), platform.machine()))
    if native == args.rid:
        v = json.loads(subprocess.run([binary, "version", "--json"], capture_output=True, check=True, text=True).stdout)
        if v.get("proto") != lock["proto"]:
            fail(f"geneva speaks proto {v.get('proto')}, the lock expects {lock['proto']}")
        log(f"geneva {v.get('version')} proto {v.get('proto')} features {','.join(v.get('features', []))}")

    manifest = {
        "tag": lock["tag"],
        "version": lock["version"],
        "rid": args.rid,
        "lua_compat": 0,
        "source_sha256": actual,
        "files": dict(sorted(files.items())),
    }
    with open(os.path.join(out, "bundle.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")
    log(f"geneva bundle for {args.rid} is ready in {out} ({len(files)} files)")


if __name__ == "__main__":
    main()
